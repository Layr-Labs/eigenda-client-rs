use rand::seq::SliceRandom;
use rust_kzg_bn254_prover::srs::SRS;

use crate::{
    commitment_utils::generate_and_compare_blob_commitment,
    core::{
        eigenda_cert::{BlobKey, EigenDACert},
        Blob, Payload, PayloadForm,
    },
    relay_client::{RelayClient, RelayKey},
};

pub struct RelayPayloadRetrieverConfig {
    pub(crate) srs: SRS,
    pub(crate) payload_form: PayloadForm,
}

// RelayPayloadRetriever provides the ability to get payloads from the relay subsystem.
pub struct RelayPayloadRetriever {
    config: RelayPayloadRetrieverConfig,
    relay_client: RelayClient,
}

impl RelayPayloadRetriever {
    pub fn new(config: RelayPayloadRetrieverConfig, relay_client: RelayClient) -> Self {
        RelayPayloadRetriever {
            config,
            relay_client,
        }
    }

    // get_payload iteratively attempts to fetch a given blob with key blobKey from relays that have it, as claimed by the
    // blob certificate. The relays are attempted in random order.
    //
    // If the blob is successfully retrieved, then the blob is verified against the certificate. If the verification
    // succeeds, the blob is decoded to yield the payload (the original user data, with no padding or any modification),
    // and the payload is returned.
    //
    // This method does NOT verify the eigenDACert on chain: it is assumed that the input eigenDACert has already been
    // verified prior to calling this method.
    pub async fn get_payload(&mut self, eigenda_cert: EigenDACert) -> Result<Payload, String> {
        let blob_key = eigenda_cert.compute_blob_key().unwrap();

        let relay_keys = eigenda_cert.blob_inclusion_info.blob_certificate.relay_keys;
        if relay_keys.is_empty() {
            return Err("relay key count is zero".to_string());
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
                .retrieve_blob_with_timeout(relay_key, blob_key, blob_length_symbols)
                .await
            {
                Ok(blob) => blob,
                Err(_err) => {
                    // TODO: add logging here?
                    continue;
                }
            };

            // TODO (litt3): eventually, we should make generate_and_compare_blob_commitment accept a blob, instead of the
            //  serialization of a blob. Commitment generation operates on field elements, which is how a blob is stored
            //  under the hood, so it's actually duplicating work to serialize the blob here. I'm declining to make this
            //  change now, to limit the size of the refactor PR.
            let g1_srs = self.config.srs.g1.clone();
            let valid = generate_and_compare_blob_commitment(
                g1_srs,
                blob.serialize(),
                blob_commitments.commitment,
            )
            .unwrap_or(false);
            if !valid {
                // TODO: add logging here?
                continue;
            }

            // TODO: PayloadForm is derived from config
            let payload = match blob.to_payload(self.config.payload_form) {
                Ok(payload) => payload,
                Err(_err) => {
                    // TODO: add logging here?
                    continue;
                }
            };

            return Ok(payload);
        }

        // If we reach this point, we've tried all relays and failed to retrieve the blob
        Err(format!(
            "Unable to retrieve blob {}, from any relay. relay count: {}",
            hex::encode(blob_key),
            relay_keys.len()
        ))
    }

    async fn retrieve_blob_with_timeout(
        &mut self,
        relay_key: RelayKey,
        blob_key: BlobKey,
        blob_length_symbols: u32,
    ) -> Result<Blob, String> {
        // TODO: add timeout logic here
        let blob_bytes = self
            .relay_client
            .get_blob(relay_key, blob_key)
            .await
            .unwrap();
        let blob = Blob::deserialize_blob(blob_bytes, blob_length_symbols as usize).unwrap();
        Ok(blob)
    }
}
