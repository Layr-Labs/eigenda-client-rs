use ethereum_types::H160;

use crate::{
    cert_verifier::CertVerifier,
    core::{eigenda_cert::EigenDACert, BlobKey, Payload, PayloadForm},
    disperser_client::{DisperserClient, DisperserClientConfig},
    errors::{ConversionError, EigenClientError, PayloadDisperserError},
    generated::disperser::v2::{BlobStatus, BlobStatusReply},
    utils::{PrivateKey, SecretUrl},
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
/// PayloadDisperser provides the ability to disperse payloads to EigenDA via a Disperser grpc service.
pub struct PayloadDisperser {
    config: PayloadDisperserConfig,
    disperser_client: DisperserClient,
    cert_verifier: CertVerifier,
    required_quorums: Vec<u8>,
}

impl PayloadDisperser {
    /// Creates a PayloadDisperser from the specified configs.
    pub async fn new(
        payload_config: PayloadDisperserConfig,
        private_key: PrivateKey,
    ) -> Result<Self, PayloadDisperserError> {
        let disperser_config = DisperserClientConfig {
            disperser_rpc: payload_config.disperser_rpc.clone(),
            private_key: private_key.clone(),
            use_secure_grpc_flag: payload_config.use_secure_grpc_flag,
        };
        let disperser_client = DisperserClient::new(disperser_config).await?;
        let cert_verifier = CertVerifier::new(
            payload_config.cert_verifier_address,
            payload_config.eth_rpc_url.clone(),
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
    pub async fn send_payload(&self, payload: Payload) -> Result<BlobKey, PayloadDisperserError> {
        let blob = payload.to_blob(self.config.polynomial_form)?;

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
    pub async fn get_inclusion_data(
        &self,
        blob_key: &BlobKey,
    ) -> Result<Option<EigenDACert>, EigenClientError> {
        let status = self
            .disperser_client
            .blob_status(blob_key)
            .await
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Disperser(e)))?;

        let blob_status = BlobStatus::try_from(status.status)
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Decode(e)))?;
        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => Err(PayloadDisperserError::BlobStatus)?,
            BlobStatus::Encoded | BlobStatus::GatheringSignatures | BlobStatus::Queued => Ok(None),
            BlobStatus::Complete => {
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

    /// Creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub async fn build_eigenda_cert(
        &self,
        status: &BlobStatusReply,
    ) -> Result<EigenDACert, EigenClientError> {
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

        let cert = EigenDACert::new(status, non_signer_stakes_and_signature)?;

        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        core::{Payload, PayloadForm},
        payload_disperser::{PayloadDisperser, PayloadDisperserConfig},
        tests::{
            get_test_holesky_rpc_url, get_test_private_key, CERT_VERIFIER_ADDRESS,
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

        let mut payload_disperser = PayloadDisperser::new(payload_config, get_test_private_key())
            .await
            .unwrap();

        let payload = Payload::new(vec![1, 2, 3, 4, 5]);
        let blob_key = payload_disperser.send_payload(payload).await.unwrap();

        let mut finished = false;
        let start_time = tokio::time::Instant::now();
        while !finished {
            let inclusion_data = payload_disperser
                .get_inclusion_data(&blob_key)
                .await
                .unwrap();
            match inclusion_data {
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
