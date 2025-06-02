use ark_bn254::G1Affine;
use rust_eigenda_v2_common::{Blob, BlobHeader, EigenDACert, Payload, PayloadForm};
use tokio::time::timeout;

use crate::{commitment_utils::generate_and_compare_blob_commitment, errors::ValidatorPayloadRetrieverError, validator_client::ValidatorClient};

/// Contains all configuration values needed by a ValidatorPayloadRetriever
pub struct ValidatorPayloadRetrieverConfig {
    retrieval_timeout: tokio::time::Duration,
    payload_polynomial_form: PayloadForm,
    blob_version: u16,
}

/// Provides the ability to get payloads from the EigenDA validator nodes directly
pub struct ValidatorPayloadRetriver {
    config: ValidatorPayloadRetrieverConfig,
    retrieval_client: ValidatorClient,
    g1_srs: Vec<G1Affine>,
}

impl ValidatorPayloadRetriver {

    // Iteratively attempts to retrieve a given blob from the quorums listed in the EigenDACert.
    //
    // If the blob is successfully retrieved, then the blob is verified against the EigenDACert. If the verification succeeds,
    // the blob is decoded to yield the payload (the original user data, with no padding or any modification), and the
    // payload is returned.
    pub async fn get_payload(&self, eigenda_cert: &EigenDACert) -> Result<Payload, ValidatorPayloadRetrieverError> {

        let blob_header = &eigenda_cert.blob_inclusion_info.blob_certificate.blob_header;

        for _ in blob_header.quorum_numbers.clone() {

            let payload = self.get_payload_from_quorum(blob_header, eigenda_cert.batch_header.reference_block_number).await;

            if let Ok(payload) = payload {
                return Ok(payload);
            } else {
                continue; //If retrieval fails, try the next quorum
            }
        }

        Err(ValidatorPayloadRetrieverError::BlobRetrieval(
            blob_header.quorum_numbers.clone()
        ))
    }

    async fn get_payload_from_quorum(
        &self,
        blob_header: &BlobHeader,
        reference_block_number: u32,
    ) -> Result<Payload, ValidatorPayloadRetrieverError> {
        let blob: Blob = self.retrieve_blob_with_timeout(blob_header,reference_block_number).await?;

        let valid = generate_and_compare_blob_commitment(self.g1_srs.clone(), blob.serialize(), blob_header.commitment.commitment)?;

        if !valid {
           return Err(ValidatorPayloadRetrieverError::BlobVerification);
        }

        let payload = blob.to_payload(self.config.payload_polynomial_form)?;

        Ok(payload)
    }

    async fn retrieve_blob_with_timeout(
        &self,
        blob_header: &BlobHeader,
        reference_block_number: u32,
    ) -> Result<Blob, ValidatorPayloadRetrieverError> {
        let blob_bytes = timeout(self.config.retrieval_timeout, self.retrieval_client.get_blob(blob_header, reference_block_number)).await.map_err(|_| ValidatorPayloadRetrieverError::Timeout)??;

        let blob = Blob::deserialize_blob(blob_bytes, blob_header.commitment.length as usize)?;

        Ok(blob)
    }
}
