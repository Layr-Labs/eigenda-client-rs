use std::time::Duration;

use rand::seq::SliceRandom;
use rust_eigenda_v2_common::{Blob, EigenDACert, Payload};
use rust_kzg_bn254_prover::srs::SRS;
use tokio::time::timeout;

use crate::{
    commitment_utils::generate_and_compare_blob_commitment,
    core::BlobKey,
    errors::{BlobError, ConversionError, RelayPayloadRetrieverError},
    relay_client::{RelayClient, RelayKey},
};

/// Computes the blob_key of the blob that belongs to the EigenDACert
fn compute_blob_key(eigenda_cert: &EigenDACert) -> Result<BlobKey, ConversionError> {
    let blob_header = eigenda_cert
        .blob_inclusion_info
        .blob_certificate
        .blob_header
        .clone();

    BlobKey::compute_blob_key(&blob_header)
}

#[derive(Clone)]
pub struct SRSConfig {
    pub source_path: String,
    pub order: u32,
    pub points_to_load: u32,
}

#[derive(Clone)]
pub struct RelayPayloadRetrieverConfig {
    pub retrieval_timeout_secs: Duration,
}

/// Provides the ability to get payloads from the relay subsystem.
pub struct RelayPayloadRetriever {
    srs: SRS,
    config: RelayPayloadRetrieverConfig,
    relay_client: RelayClient,
}

impl RelayPayloadRetriever {
    /// Assembles a RelayPayloadRetriever from specified configs and a
    /// relay client that have already been constructed.
    pub fn new(
        config: RelayPayloadRetrieverConfig,
        srs_config: SRSConfig,
        relay_client: RelayClient,
    ) -> Result<Self, RelayPayloadRetrieverError> {
        let srs = SRS::new(
            &srs_config.source_path,
            srs_config.order,
            srs_config.points_to_load,
        )?;

        Ok(RelayPayloadRetriever {
            srs,
            config,
            relay_client,
        })
    }

    // Iteratively attempts to fetch a given blob with key blobKey from relays that have it, as claimed by the
    // blob certificate. The relays are attempted in random order.
    //
    // If the blob is successfully retrieved, then the blob is verified against the certificate. If the verification
    // succeeds, the blob is decoded to yield the payload (the original user data, with no padding or any modification),
    // and the payload is returned.
    //
    // This method does NOT verify the [`EigenDACert`] on chain: it is assumed that the input [`EigenDACert`] has already been
    // verified prior to calling this method.
    pub async fn get_payload(
        &mut self,
        eigenda_cert: EigenDACert,
    ) -> Result<Payload, RelayPayloadRetrieverError> {
        let blob_key = compute_blob_key(&eigenda_cert)?;

        let relay_keys = eigenda_cert.blob_inclusion_info.blob_certificate.relay_keys;
        if relay_keys.is_empty() {
            return Err(RelayPayloadRetrieverError::InvalidCertificate(
                "relay key count is zero".to_string(),
            ));
        }

        let blob_commitments = eigenda_cert
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .commitment
            .clone();

        // create a randomized array of indices, so that it isn't always the first relay in the list which gets hit
        let mut indices: Vec<usize> = (0..relay_keys.len()).collect();
        indices.shuffle(&mut rand::thread_rng()); // TODO: use other rng

        // TODO (litt3): consider creating a utility which deprioritizes relays that fail to respond (or respond maliciously),
        //  and prioritizes relays with lower latencies.

        // iterate over relays in random order, until we are able to get the blob from someone
        for idx in indices {
            let relay_key = relay_keys[idx];

            let blob_length_symbols = eigenda_cert
                .blob_inclusion_info
                .blob_certificate
                .blob_header
                .commitment
                .length;

            // if get_blob returned and error, try calling a different relay
            let blob = match self
                .retrieve_blob_with_timeout(relay_key, &blob_key, blob_length_symbols)
                .await
            {
                Ok(blob) => blob,
                Err(err) => {
                    println!("Error retrieving blob from relay {}: {}", relay_key, err);
                    continue;
                }
            };

            let g1_srs = self.srs.g1.clone();
            let valid = generate_and_compare_blob_commitment(
                g1_srs,
                blob.serialize(),
                blob_commitments.commitment,
            )
            .unwrap_or(false);
            if !valid {
                println!("Retrieved blob from relay {} is not valid", relay_key);
                continue;
            }

            let payload = match blob.to_payload() {
                Ok(payload) => payload,
                Err(err) => {
                    println!(
                        "Error converting blob retrieved from relay {} to payload: {}",
                        relay_key, err
                    );
                    continue;
                }
            };

            return Ok(payload);
        }

        // If we reach this point, we've tried all relays and failed to retrieve the blob
        Err(RelayPayloadRetrieverError::UnableToRetrievePayload)
    }

    /// Attempts to retrieve a [`Blob`] from a given [`RelayKey`].
    ///
    /// Times out based on config's `retrieval_timeout_secs`.
    ///
    /// Returns [`RelayPayloadRetrieverError::RetrievalTimeout`] if the timeout is exceeded.
    async fn retrieve_blob_with_timeout(
        &mut self,
        relay_key: RelayKey,
        blob_key: &BlobKey,
        blob_length_symbols: u32,
    ) -> Result<Blob, RelayPayloadRetrieverError> {
        let blob_bytes = timeout(
            self.config.retrieval_timeout_secs,
            self.relay_client.get_blob(relay_key, blob_key),
        )
        .await
        .map_err(|_| RelayPayloadRetrieverError::RetrievalTimeout)??;

        let blob = Blob::deserialize_blob(blob_bytes, blob_length_symbols as usize)
            .map_err(BlobError::CommonBlob)?;
        Ok(blob)
    }
}
