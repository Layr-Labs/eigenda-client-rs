use std::{collections::HashMap, str::FromStr};

use alloy::{
    primitives::{Address, FixedBytes},
    signers::local::PrivateKeySigner,
};
use ark_bn254::G1Affine;
use ark_ff::{BigInteger, PrimeField};
use eigensdk::{
    client_avsregistry::reader::{AvsRegistryChainReader, AvsRegistryReader},
    logging::{get_logger, init_logger, log_level::LogLevel},
};
use ethereum_types::H160;
use rust_eigenda_v2_common::{EigenDACert, NonSignerStakesAndSignature, Payload, PayloadForm};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    cert_verifier::CertVerifier,
    core::{
        eigenda_cert::{build_cert_from_reply, SignedBatch},
        BlobKey,
    },
    disperser_client::{DisperserClient, DisperserClientConfig},
    errors::{ConversionError, EigenClientError, PayloadDisperserError},
    generated::disperser::v2::{BlobStatus, BlobStatusReply, SignedBatch as SignedBatchProto},
    utils::SecretUrl,
};

#[derive(Clone, Debug)]
pub struct PayloadDisperserConfig {
    pub polynomial_form: PayloadForm,
    pub blob_version: u16,
    pub cert_verifier_address: String,
    pub eth_rpc_url: SecretUrl,
    pub disperser_rpc: String,
    pub use_secure_grpc_flag: bool,
    pub registry_coordinator_addr: String,
    pub operator_state_retriever_addr: String,
}

#[derive(Debug, Clone)]
/// Provides the ability to disperse payloads to EigenDA via a Disperser GRPC service.
pub struct PayloadDisperser {
    config: PayloadDisperserConfig,
    disperser_client: DisperserClient,
    cert_verifier: CertVerifier,
    required_quorums: Vec<u8>,
}

impl PayloadDisperser {
    const BLOB_SIZE_LIMIT: usize = 1024 * 1024 * 16; // 16 MB
    /// Creates a [`PayloadDisperser`] from the specified configuration.
    pub async fn new(
        payload_config: PayloadDisperserConfig,
        signer: PrivateKeySigner,
    ) -> Result<Self, PayloadDisperserError> {
        init_logger(LogLevel::Info);
        let disperser_config = DisperserClientConfig {
            disperser_rpc: payload_config.disperser_rpc.clone(),
            signer: signer.clone(),
            use_secure_grpc_flag: payload_config.use_secure_grpc_flag,
        };
        let disperser_client = DisperserClient::new(disperser_config).await?;
        let cert_verifier = CertVerifier::new(
            H160::from_str(&payload_config.cert_verifier_address).map_err(|_| {
                ConversionError::Address(payload_config.cert_verifier_address.clone())
            })?,
            payload_config.eth_rpc_url.clone(),
            alloy::signers::local::PrivateKeySigner::random(), // TODO: REPLACE
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
    /// The Cert returned is checked to be correct, and an error is returned if it is not valid.
    pub async fn get_cert(
        &self,
        blob_key: &BlobKey,
    ) -> Result<Option<EigenDACert>, EigenClientError> {
        let status = self
            .disperser_client
            .blob_status(blob_key)
            .await
            .map_err(|e| {
                EigenClientError::PayloadDisperser(Box::new(PayloadDisperserError::Disperser(e)))
            })?;

        let blob_status = BlobStatus::try_from(status.status).map_err(|e| {
            EigenClientError::PayloadDisperser(Box::new(PayloadDisperserError::Decode(e)))
        })?;
        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => Err(PayloadDisperserError::BlobStatus)?,
            BlobStatus::Encoded | BlobStatus::Queued => Ok(None),
            BlobStatus::GatheringSignatures => {
                let thresholds_met = self.check_thresholds(&status).await;
                if thresholds_met.is_err() {
                    // Since we are gathering signatures, it is ok for thresholds not to be met yet.
                    return Ok(None);
                }
                let eigenda_cert = self.build_eigenda_cert(&status).await?;
                self.cert_verifier
                    .check_da_cert(&eigenda_cert)
                    .await
                    .map_err(|e| {
                        EigenClientError::PayloadDisperser(Box::new(
                            PayloadDisperserError::CertVerifier(e),
                        ))
                    })?;
                Ok(Some(eigenda_cert))
            }
            BlobStatus::Complete => {
                self.check_thresholds(&status).await?;
                let eigenda_cert = self.build_eigenda_cert(&status).await?;
                self.cert_verifier
                    .check_da_cert(&eigenda_cert)
                    .await
                    .map_err(|e| {
                        EigenClientError::PayloadDisperser(Box::new(
                            PayloadDisperserError::CertVerifier(e),
                        ))
                    })?;
                Ok(Some(eigenda_cert))
            }
        }
    }

    /// Verifies if all quorums meet the confirmation threshold
    async fn check_thresholds(
        &self,
        status: &BlobStatusReply,
    ) -> Result<(), PayloadDisperserError> {
        let blob_quorum_numbers = status
            .clone()
            .blob_inclusion_info
            .ok_or(ConversionError::BlobInclusion(
                "BlobInclusionInfo not present".to_string(),
            ))?
            .blob_certificate
            .ok_or(ConversionError::BlobCertificate(
                "BlobCertificate not present".to_string(),
            ))?
            .blob_header
            .ok_or(ConversionError::BlobHeader(
                "BlobHeader not present".to_string(),
            ))?
            .quorum_numbers;

        let attestation = status
            .signed_batch
            .clone()
            .ok_or(ConversionError::SignedBatch(
                "SignedBatch not present".to_string(),
            ))?
            .attestation
            .ok_or(ConversionError::Attestation(
                "Attestation not present".to_string(),
            ))?;
        let batch_quorum_numbers = attestation.quorum_numbers;
        let batch_signed_percentages = attestation.quorum_signed_percentages;

        let batch_header = status
            .clone()
            .signed_batch
            .ok_or(ConversionError::SignedBatch(
                "SignedBatch not present".to_string(),
            ))?
            .header;
        if batch_header.is_none() {
            return Err(PayloadDisperserError::BatchHeaderNotPresent);
        }

        self.check_thresholds_pure(
            batch_quorum_numbers,
            batch_signed_percentages,
            blob_quorum_numbers,
        )
        .await?;

        Ok(())
    }

    async fn check_thresholds_pure(
        &self,
        batch_quorum_numbers: Vec<u32>,
        batch_signed_percentages: Vec<u8>,
        blob_quorum_numbers: Vec<u32>,
    ) -> Result<(), PayloadDisperserError> {
        if blob_quorum_numbers.is_empty() {
            return Err(PayloadDisperserError::NoQuorumNumbers);
        }

        if batch_quorum_numbers.len() != batch_signed_percentages.len() {
            return Err(PayloadDisperserError::QuorumNumbersMismatch);
        }

        // map from quorum ID to the percentage stake signed from that quorum
        let mut signed_percentages_per_quorum = HashMap::new();
        for (quorum_id, signed_percentage) in batch_quorum_numbers
            .iter()
            .zip(batch_signed_percentages.iter())
        {
            signed_percentages_per_quorum.insert(quorum_id, *signed_percentage);
        }

        let confirmation_threshold = self.cert_verifier.get_confirmation_threshold().await?;

        for quorum in blob_quorum_numbers {
            let signed_percentage = signed_percentages_per_quorum
                .get(&quorum)
                .ok_or(PayloadDisperserError::SignedPercentageNotFound(quorum))?;
            if *signed_percentage < confirmation_threshold {
                return Err(PayloadDisperserError::ConfirmationThresholdNotMet {
                    quorum_number: quorum,
                    signed_percentage: *signed_percentage,
                    threshold: confirmation_threshold,
                });
            }
        }

        Ok(())
    }

    /// Creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub async fn build_eigenda_cert(
        &self,
        status: &BlobStatusReply,
    ) -> Result<EigenDACert, EigenClientError> {
        let signed_batch = match status.clone().signed_batch {
            Some(batch) => batch,
            None => {
                return Err(EigenClientError::PayloadDisperser(Box::new(
                    PayloadDisperserError::Conversion(ConversionError::SignedBatch(
                        "Not Present".to_string(),
                    )),
                )))
            }
        };
        let non_signer_stakes_and_signature = self
            .get_non_signer_stakes_and_signature(signed_batch)
            .await?;

        let cert = build_cert_from_reply(status, non_signer_stakes_and_signature)?;

        Ok(cert)
    }

    async fn get_non_signer_stakes_and_signature(
        &self,
        signed_batch_proto: SignedBatchProto,
    ) -> Result<NonSignerStakesAndSignature, EigenClientError> {
        let signed_batch: SignedBatch = signed_batch_proto.try_into()?;

        let non_signers_pubkeys: Vec<G1Affine> =
            signed_batch.attestation.non_signer_pubkeys.clone();

        let mut non_signer_operator_ids: Vec<FixedBytes<32>> = vec![];

        for pubkey in non_signers_pubkeys {
            let x = pubkey.x.into_bigint().to_bytes_be();
            let y = pubkey.y.into_bigint().to_bytes_be();
            let mut hasher = Keccak::v256();
            hasher.update(&[x, y].concat());
            let mut g1_hash = [0u8; 32];
            hasher.finalize(&mut g1_hash);
            let operator_id = FixedBytes::<32>::from_slice(&g1_hash);
            non_signer_operator_ids.push(operator_id);
        }

        let quorum_numbers = signed_batch
            .attestation
            .quorum_numbers
            .iter()
            .map(|x| *x as u8)
            .collect::<Vec<u8>>();

        let reference_block_number = signed_batch.header.reference_block_number;

        let avs_registry_chain_reader = AvsRegistryChainReader::new(
            get_logger(),
            Address::from_str(&self.config.registry_coordinator_addr).map_err(|_| {
                ConversionError::Address(self.config.registry_coordinator_addr.clone())
            })?,
            Address::from_str(&self.config.operator_state_retriever_addr).map_err(|_| {
                ConversionError::Address(self.config.operator_state_retriever_addr.clone())
            })?,
            self.config.eth_rpc_url.clone().try_into()?,
        )
        .await
        .map_err(|_| PayloadDisperserError::EigenSDKNotInitialized)?;

        let check_sig_indices = avs_registry_chain_reader
            .get_check_signatures_indices(
                reference_block_number,
                quorum_numbers,
                non_signer_operator_ids,
            )
            .await
            .map_err(|_| PayloadDisperserError::GetCheckSignaturesIndices)?;

        Ok(NonSignerStakesAndSignature {
            non_signer_quorum_bitmap_indices: check_sig_indices.nonSignerQuorumBitmapIndices,
            non_signer_pubkeys: signed_batch.attestation.non_signer_pubkeys,
            quorum_apks: signed_batch.attestation.quorum_apks,
            apk_g2: signed_batch.attestation.apk_g2,
            sigma: signed_batch.attestation.sigma,
            quorum_apk_indices: check_sig_indices.quorumApkIndices,
            total_stake_indices: check_sig_indices.totalStakeIndices,
            non_signer_stake_indices: check_sig_indices.nonSignerStakeIndices,
        })
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
            HOLESKY_DISPERSER_RPC_URL, OPERATOR_STATE_RETRIEVER_ADDRESS,
            REGISTRY_COORDINATOR_ADDRESS,
        },
    };

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_disperse_payload() {
        let timeout = tokio::time::Duration::from_secs(180);

        let payload_config = PayloadDisperserConfig {
            polynomial_form: PayloadForm::Coeff,
            blob_version: 0,
            cert_verifier_address: CERT_VERIFIER_ADDRESS.to_string(),
            eth_rpc_url: get_test_holesky_rpc_url(),
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            use_secure_grpc_flag: false,
            registry_coordinator_addr: REGISTRY_COORDINATOR_ADDRESS.to_string(),
            operator_state_retriever_addr: OPERATOR_STATE_RETRIEVER_ADDRESS.to_string(),
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
