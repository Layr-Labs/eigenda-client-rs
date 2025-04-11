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
                Err(err) => {
                    println!("Error retrieving blob from relay {}: {}", relay_key, err);
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
                println!("Retrieved blob from relay {} is not valid", relay_key);
                continue;
            }

            // TODO: PayloadForm is derived from config
            let payload = match blob.to_payload(self.config.payload_form) {
                Ok(payload) => payload,
                Err(err) => {
                    println!("Error converting blob retrieved from relay {} to payload: {}", relay_key, err);
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

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use tokio::sync::Mutex;
    use url::Url;

    use crate::{
        commitment_utils::{g1_commitment_from_bytes, g2_commitment_from_bytes}, core::eigenda_cert::{BatchHeaderV2, BlobCertificate, BlobCommitment, BlobHeader, BlobInclusionInfo, NonSignerStakesAndSignature}, eth_client::EthClient, utils::{relay_client_test_config, SecretUrl}
    };

    use super::*;

    fn get_relay_payload_retriever_test_config() -> RelayPayloadRetrieverConfig {
        RelayPayloadRetrieverConfig {
            srs: SRS::new("../../resources/g1.point", 42, 42).unwrap(),
            payload_form: PayloadForm::Coeff,
        }
    }

    async fn get_test_relay_client() -> RelayClient {
        let eth_client = EthClient::new(SecretUrl::new(
            Url::from_str("https://ethereum-holesky-rpc.publicnode.com").unwrap(),
        ));
        let eth_client = Arc::new(Mutex::new(eth_client));

        RelayClient::new(relay_client_test_config(), eth_client)
            .await
            .unwrap()
    }

    fn get_test_eigenda_cert() -> EigenDACert {
        let commitment_bytes = hex::decode("a7c4441c06c2f25772a92652359a6d8d833b366ddd8a5ebfc8607f071e0338d6").unwrap();
        let length_commitment_bytes = hex::decode("82f60548e251ba29e02a85a926dc4fc4cf1c807527e1ae11173d3b135ffed97224c75fef03818181e69954bb43daa9430abbf580ef6e0334b2b2bebb16de6f20").unwrap();
        let length_proof_bytes = hex::decode("89a044a6d501258caaea977182083fff31bdccfffc158d59137a04e3aa9adf4817f0a83a449c22d153a054a14e2313d6fe17c5434373f7ed3267d1ba36452275").unwrap();
        let non_signer_pubkey_bytes = hex::decode("ca23a80806ce5f1632efc1dd69e1a12b0a4ba777bc3212d2655861bfe6397eb1").unwrap();
        let quorum_apk_bytes = vec![
            hex::decode("8d35c7750d50e54b2a6c4979ea9b3862bf22a5c091a763f58dc7e8fcfca84e34").unwrap(),
            hex::decode("e0c0894de2da03d515c9e5ac6d4a388f853504cc5fdadd0609eb2944b88cabc7").unwrap(),
        ];
        let apk_g2_bytes = hex::decode("a48ceba943b11ffaedd7f58c6592757b020ea837db69122d4b85a88918a55efa089513e71f7542d52faf50c0628a0ce8b44dccd62c96d864a7a0ad276ae45af7").unwrap();
        let sigma_bytes = hex::decode("d8bcbb37fb19641347b7165298d481368adde8b332e565bb0768f564bdbbae06").unwrap();

        EigenDACert {
            blob_inclusion_info: BlobInclusionInfo {
                blob_certificate: BlobCertificate {
                    blob_header: BlobHeader {
                        version: 0,
                        quorum_numbers: vec![0, 1],
                        commitment: BlobCommitment {
                            commitment: g1_commitment_from_bytes(&commitment_bytes).unwrap(),
                            length_commitment: g2_commitment_from_bytes(&length_commitment_bytes).unwrap(),
                            length_proof: g2_commitment_from_bytes(&length_proof_bytes).unwrap(),
                            length: 2
                        },
                        payment_header_hash: [102, 175, 75, 184, 81, 157, 192, 11, 93, 183, 87, 10, 158, 29, 104, 70, 95, 43, 104, 185, 104, 165, 207, 55, 198, 240, 19, 121, 76, 219, 129, 14],
                    },
                    signature: vec![62, 105, 120, 213, 12, 10, 218, 180, 240, 79, 217, 199, 106, 76, 157, 173, 211, 125, 124, 183, 199, 177, 71, 4, 137, 227, 124, 47, 187, 129, 98, 87, 118, 217, 79, 36, 35, 210, 153, 113, 65, 55, 210, 79, 66, 76, 226, 51, 170, 241, 55, 151, 135, 207, 59, 24, 82, 6, 138, 67, 218, 116, 1, 145, 1],
                    relay_keys: vec![1, 2],
                },
                blob_index: 1,
                inclusion_proof: vec![51, 15, 42, 184, 129, 38, 60, 111, 23, 19, 10, 111, 230, 76, 225, 223, 157, 2, 171, 210, 202, 239, 156, 74, 39, 61, 109, 189, 240, 3, 56, 129]
            },
            batch_header: BatchHeaderV2 {
                batch_root: [223, 236, 131, 30, 9, 156, 39, 50, 11, 177, 46, 125, 175, 191, 146, 132, 129, 197, 61, 50, 201, 42, 133, 40, 10, 194, 162, 76, 145, 106, 57, 120],
                reference_block_number: 3656235,
            },
            non_signer_stakes_and_signature: NonSignerStakesAndSignature {
                non_signer_quorum_bitmap_indices: vec![11],
                non_signer_pubkeys: vec![
                    g1_commitment_from_bytes(&non_signer_pubkey_bytes).unwrap()
                ],
                quorum_apks: vec![
                    g1_commitment_from_bytes(&quorum_apk_bytes[0]).unwrap(),
                    g1_commitment_from_bytes(&quorum_apk_bytes[1]).unwrap()
                ],
                apk_g2: g2_commitment_from_bytes(&apk_g2_bytes).unwrap(),
                sigma: g1_commitment_from_bytes(&sigma_bytes).unwrap(),
                quorum_apk_indices: vec![1744, 2175],
                total_stake_indices: vec![2305, 2440],
                non_signer_stake_indices: vec![vec![12], vec![5]]
            },
            signed_quorum_numbers: vec![0,1],
        }
    }

    #[tokio::test]
    async fn get_payload_from_relay() {
        let config = get_relay_payload_retriever_test_config();
        let relay_client = get_test_relay_client().await;
        let mut client = RelayPayloadRetriever::new(config, relay_client);

        let eigenda_cert = get_test_eigenda_cert();
        let res = client.get_payload(eigenda_cert).await;
        assert!(res.is_ok())
    }
}
