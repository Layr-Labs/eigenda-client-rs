use std::collections::HashMap;

use ethereum_types::H160;
use rust_eigenda_v2_common::{EigenDACert, Payload, PayloadForm};

use crate::{
    cert_verifier::{self, CertVerifier},
    core::{eigenda_cert::build_cert_from_reply, BlobKey},
    disperser_client::{DisperserClient, DisperserClientConfig},
    errors::{ConversionError, EigenClientError, PayloadDisperserError},
    generated::disperser::v2::{BlobStatus, BlobStatusReply},
    rust_eigenda_signers::{signers::private_key::Signer as PrivateKeySigner, Sign},
    utils::SecretUrl,
};

#[derive(Clone, Debug)]
pub struct PayloadDisperserConfig {
    pub polynomial_form: PayloadForm,
    pub blob_version: u16,
    pub cert_verifier_address: H160,
    pub eth_rpc_url: SecretUrl,
    pub disperser_rpc: String,
    pub use_secure_grpc_flag: bool,
}

#[derive(Debug, Clone)]
/// Provides the ability to disperse payloads to EigenDA via a Disperser GRPC service.
pub struct PayloadDisperser<S = PrivateKeySigner> {
    config: PayloadDisperserConfig,
    disperser_client: DisperserClient<S>,
    cert_verifier: CertVerifier<S>,
    required_quorums: Vec<u8>,
}

impl<S> PayloadDisperser<S> {
    const BLOB_SIZE_LIMIT: usize = 1024 * 1024 * 16; // 16 MB
    /// Creates a [`PayloadDisperser`] from the specified configuration.
    pub async fn new(
        payload_config: PayloadDisperserConfig,
        signer: S,
    ) -> Result<Self, PayloadDisperserError>
    where
        S: Sign + Clone,
    {
        let disperser_config = DisperserClientConfig {
            disperser_rpc: payload_config.disperser_rpc.clone(),
            signer: signer.clone(),
            use_secure_grpc_flag: payload_config.use_secure_grpc_flag,
        };
        let disperser_client = DisperserClient::new(disperser_config).await?;
        let cert_verifier = CertVerifier::new(
            payload_config.cert_verifier_address,
            payload_config.eth_rpc_url.clone(),
            signer,
        )?;
        let required_quorums = cert_verifier.quorum_numbers_required().await?;
        Ok(PayloadDisperser {
            disperser_client,
            config: payload_config.clone(),
            cert_verifier,
            required_quorums,
        })
    }

    /// Executes the dispersal of a payload, returning the associated blob key
    pub async fn send_payload(&self, payload: Payload) -> Result<BlobKey, PayloadDisperserError>
    where
        S: Sign,
    {
        let blob = payload
            .to_blob(self.config.polynomial_form)
            .map_err(ConversionError::EigenDACommon)?;

        let (blob_status, blob_key) = self
            .disperser_client
            .disperse_blob(
                &blob.serialize(),
                self.config.blob_version,
                &self.required_quorums,
            )
            .await?;

        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => {
                return Err(PayloadDisperserError::BlobStatus);
            }
            BlobStatus::Complete
            | BlobStatus::Encoded
            | BlobStatus::GatheringSignatures
            | BlobStatus::Queued => {}
        }
        Ok(blob_key)
    }

    /// Retrieves the inclusion data for a given blob key
    /// If the requested blob is still not complete, returns None
    pub async fn get_cert(
        &self,
        blob_key: &BlobKey,
    ) -> Result<Option<EigenDACert>, EigenClientError>
    where
        S: Sign,
    {
        let status = self
            .disperser_client
            .blob_status(blob_key)
            .await
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Disperser(e)))?;

        let blob_status = BlobStatus::try_from(status.status)
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Decode(e)))?;
        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => Err(PayloadDisperserError::BlobStatus)?,
            BlobStatus::Encoded | BlobStatus::Queued => Ok(None),
            BlobStatus::GatheringSignatures | BlobStatus::Complete => {
                self.check_thresholds(blob_key, &status)
                    .await?;
                let eigenda_cert = self.build_eigenda_cert(&status).await?;
                self.cert_verifier
                    .verify_cert_v2(&eigenda_cert)
                    .await
                    .map_err(|e| {
                        EigenClientError::PayloadDisperser(PayloadDisperserError::CertVerifier(e))
                    })?;
                Ok(Some(eigenda_cert))
            }
        }
    }

    /// Verifies if all quorums meet the confirmation threshold
    async fn check_thresholds(
        &self,
        blob_key: &BlobKey,
        status: &BlobStatusReply,
    ) -> Result<(), PayloadDisperserError> { // todo error handling
        let blob_quorum_numbers = status.clone().blob_inclusion_info.unwrap().blob_certificate.unwrap().blob_header.unwrap().quorum_numbers;
        if blob_quorum_numbers.is_empty() {
            return Err(PayloadDisperserError::NoQuorumNumbers);
        }
        let attestation = status.signed_batch.unwrap().attestation.unwrap();
        let batch_quorum_numbers = attestation.quorum_numbers;
        let batch_signed_percentages = attestation.quorum_signed_percentages;

        if batch_quorum_numbers.len() != batch_signed_percentages.len() {
            return Err(PayloadDisperserError::QuorumNumbersMismatch);
        }

        // map from quorum ID to the percentage stake signed from that quorum
        let signed_percentages_map = HashMap::new();
        for (quorum_id, signed_percentage) in batch_quorum_numbers.iter().zip(batch_signed_percentages.iter()) {
            signed_percentages_map.insert(quorum_id, *signed_percentage);
        }

        let batch_header = status.signed_batch.unwrap().header;
        if batch_header.is_none() {
            return Err(PayloadDisperserError::BatchHeaderNotPresent);
        }

        let confirmation_threshold = self.cert_verifier.get_confirmation_threshold().await?;

        for quorum in blob_quorum_numbers {
            let signed_percentage = signed_percentages_map
                .get(&quorum)
                .ok_or(PayloadDisperserError::SignedPercentageNotFound(quorum))?;
            if *signed_percentage < confirmation_threshold {
                return Err(PayloadDisperserError::ConfirmationThresholdNotMet(
                    quorum,
                    *signed_percentage,
                    confirmation_threshold,
                ));
            }
        }

        Ok(())
    }

    /// Creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub async fn build_eigenda_cert(
        &self,
        status: &BlobStatusReply,
    ) -> Result<EigenDACert, EigenClientError>
    where
        S: Sign,
    {
        let signed_batch = match status.clone().signed_batch {
            Some(batch) => batch,
            None => {
                return Err(EigenClientError::PayloadDisperser(
                    PayloadDisperserError::Conversion(ConversionError::SignedBatch(
                        "Not Present".to_string(),
                    )),
                ))
            }
        };
        let non_signer_stakes_and_signature = self
            .cert_verifier
            .get_non_signer_stakes_and_signature(signed_batch)
            .await
            .map_err(|e| {
                EigenClientError::PayloadDisperser(PayloadDisperserError::CertVerifier(e))
            })?;

        let cert = build_cert_from_reply(status, non_signer_stakes_and_signature)?;

        Ok(cert)
    }

    /// Returns the max size of a blob that can be dispersed.
    pub fn blob_size_limit() -> Option<usize> {
        Some(Self::BLOB_SIZE_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use rust_eigenda_v2_common::{Payload, PayloadForm};

    use crate::{
        payload_disperser::{PayloadDisperser, PayloadDisperserConfig},
        tests::{
            get_test_holesky_rpc_url, get_test_private_key_signer, CERT_VERIFIER_ADDRESS,
            HOLESKY_DISPERSER_RPC_URL,
        },
    };

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_disperse_payload() {
        let timeout = tokio::time::Duration::from_secs(180);

        let payload_config = PayloadDisperserConfig {
            polynomial_form: PayloadForm::Coeff,
            blob_version: 0,
            cert_verifier_address: CERT_VERIFIER_ADDRESS,
            eth_rpc_url: get_test_holesky_rpc_url(),
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            use_secure_grpc_flag: false,
        };

        let payload_disperser =
            PayloadDisperser::new(payload_config, get_test_private_key_signer())
                .await
                .unwrap();

        let payload = Payload::new(vec![1, 2, 3, 4, 5]);
        let blob_key = payload_disperser.send_payload(payload).await.unwrap();

        let mut finished = false;
        let start_time = tokio::time::Instant::now();
        while !finished {
            let cert = payload_disperser.get_cert(&blob_key).await.unwrap();
            match cert {
                Some(cert) => {
                    println!("Inclusion data: {:?}", cert);
                    finished = true;
                }
                None => {
                    let elapsed = start_time.elapsed();
                    assert!(elapsed < timeout, "Timeout waiting for inclusion data");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}
