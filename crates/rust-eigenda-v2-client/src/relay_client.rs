use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::G1Affine;
use ark_serialize::CanonicalSerialize;
use eigensdk::crypto_bls::BlsKeyPair;
use ethabi::Address;
use tiny_keccak::{Hasher, Keccak};
use tonic::transport::Channel;

use crate::{
    core::BlobKey,
    errors::RelayClientError,
    generated::relay::{
        chunk_request,
        relay_client::{self, RelayClient as RpcRelayClient},
        ChunkRequest as ChunkRequestProto, ChunkRequestByIndex as ChunkRequestByIndexProto,
        GetBlobRequest, GetChunksRequest as GetChunksRequestProto,
    },
    relay_registry::RelayRegistry,
    utils::SecretUrl,
};

const RELAY_GET_CHUNKS_REQUEST_DOMAIN: &str = "relay.GetChunksRequest";
const CHUNK_REQUEST_BY_RANGE: u8 = 0x72; // 'r'

// TODO: Move to commitment_utils? Not the same as g1_to_bytes??
fn g1_point_raw_bytes(g1_point: &G1Affine) -> Vec<u8> {
    // TODO: Add infitiny flag and check?

    let mut bytes = vec![];

    let mut y_bytes = Vec::new();
    g1_point.y.serialize_uncompressed(&mut y_bytes).unwrap();
    bytes.extend_from_slice(&y_bytes);

    let mut x_bytes = Vec::new();
    g1_point.x.serialize_uncompressed(&mut x_bytes).unwrap();
    bytes.extend_from_slice(&x_bytes);
    bytes.reverse();
    bytes
}

/// All integers are encoded as unsigned 4 byte big endian values.
///
/// Perform a keccak256 hash on the following data in the following order:
/// 1. the length of the operator ID in bytes
/// 2. the operator id
/// 3. the number of chunk requests
/// 4. for each chunk request:
///     a. if the chunk request is a request by index:
///        i.   a one byte ASCII representation of the character "i" (aka Ox69)
///        ii.  the length blob key in bytes
///        iii. the blob key
///        iv.  the start index
///        v.   the end index
///     b. if the chunk request is a request by range:
///        i.   a one byte ASCII representation of the character "r" (aka Ox72)
///        ii.  the length of the blob key in bytes
///        iii. the blob key
///        iv.  each requested chunk index, in order
/// 5. the timestamp (seconds since the Unix epoch encoded as a 4 byte big endian value)
fn hash_get_chunks_request(request: &GetChunksRequestProto) -> Result<[u8; 32], RelayClientError> {
    // TODO: implementation follows the one in go client
    // https://github.com/Layr-Labs/eigenda/blob/02c0788d875e2e0ef07c8596d6bea9e883bb0cea/api/hashing/relay_hashing.go#L18
    // The steps 5 is missing apparently

    let mut hasher = Keccak::v256();

    hasher.update(RELAY_GET_CHUNKS_REQUEST_DOMAIN.as_bytes());
    hasher.update(&(request.operator_id.len() as u32).to_be_bytes());
    hasher.update(&request.operator_id);

    hasher.update(&(request.chunk_requests.len() as u32).to_be_bytes());
    for request in &request.chunk_requests {
        match &request.request {
            Some(chunk_request::Request::ByIndex(_)) => {
                unimplemented!()
            }
            Some(chunk_request::Request::ByRange(req)) => {
                hasher.update(&[CHUNK_REQUEST_BY_RANGE]);
                hasher.update(&(req.blob_key.len() as u32).to_be_bytes());
                hasher.update(&req.blob_key);
                hasher.update(&req.start_index.to_be_bytes());
                hasher.update(&req.end_index.to_be_bytes());
            }
            None => {}
        }
    }

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Ok(output)
}

pub type RelayKey = u32;

pub struct ChunkRequestByIndex {
    blob_key: BlobKey,
    indices: Vec<u32>,
}

pub struct RelayClientConfig {
    pub(crate) max_grpc_message_size: usize,
    pub(crate) relay_clients_keys: Vec<u32>,
    pub(crate) relay_registry_address: Address,
    pub(crate) eth_rpc_url: SecretUrl,
    pub(crate) operator_id: String,
    pub(crate) bls_private_key: String,
}

// RelayClient is a client for the entire relay subsystem.
//
// It is a wrapper around a collection of grpc relay clients, which are used to interact with individual relays.
pub struct RelayClient {
    rpc_clients: HashMap<RelayKey, RpcRelayClient<tonic::transport::Channel>>,
    config: RelayClientConfig,
    message_signer: BlsKeyPair,
}

impl RelayClient {
    pub async fn new(config: RelayClientConfig) -> Result<Self, RelayClientError> {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let relay_registry_address = hex::encode(config.relay_registry_address);
        let relay_registry =
            RelayRegistry::new(relay_registry_address, config.eth_rpc_url.clone())?;

        let mut rpc_clients = HashMap::new();
        for relay_key in config.relay_clients_keys.iter() {
            let url = relay_registry.get_url_from_relay_key(*relay_key).await?;
            let endpoint =
                Channel::from_shared(url.clone()).map_err(|_| RelayClientError::InvalidURI(url))?;
            let channel = endpoint.connect().await?;
            let rpc_client = relay_client::RelayClient::new(channel);
            rpc_clients.insert(*relay_key, rpc_client);
        }

        let message_signer = BlsKeyPair::new(config.bls_private_key.clone()).unwrap();

        Ok(Self {
            rpc_clients,
            config,
            message_signer,
        })
    }

    // get_blob retrieves a blob from a relay.
    pub async fn get_blob(
        &mut self,
        relay_key: RelayKey,
        blob_key: &BlobKey,
    ) -> Result<Vec<u8>, RelayClientError> {
        let relay_client = self
            .rpc_clients
            .get_mut(&relay_key)
            .ok_or(RelayClientError::InvalidRelayKey(relay_key))?;
        let res = relay_client
            .get_blob(GetBlobRequest {
                blob_key: blob_key.to_bytes().to_vec(),
            })
            .await?
            .into_inner();

        Ok(res.blob)
    }

    // sign_get_chunks_request signs the GetChunksRequest with the operator's private key
    // and sets the signature in the request.
    fn sign_get_chunks_request(
        &self,
        request: &mut GetChunksRequestProto,
    ) -> Result<(), RelayClientError> {
        if self.config.operator_id.is_empty() {
            panic!("no operator ID provided in config, cannot sign get chunks request");
        }

        let hash = hash_get_chunks_request(request)?;
        let signature = self.message_signer.sign_message(&hash);
        let sig = g1_point_raw_bytes(&signature.g1_point().g1());
        request.operator_signature = sig;
        Ok(())
    }

    // get_chunks_by_index retrieves blob chunks from a relay by index
    // The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
    // Each bundle is a sequence of frames in raw form.
    pub async fn get_chunks_by_index(
        &mut self,
        relay_key: RelayKey,
        requests: Vec<ChunkRequestByIndex>,
    ) -> Result<Vec<Vec<u8>>, RelayClientError> {
        if requests.is_empty() {
            return Err(RelayClientError::EmptyRequest);
        }

        let mut request = {
            let chunk_requests = requests
                .into_iter()
                .map(|request| ChunkRequestProto {
                    request: Some(chunk_request::Request::ByIndex(ChunkRequestByIndexProto {
                        blob_key: request.blob_key.to_bytes().to_vec(),
                        chunk_indices: request.indices,
                    })),
                })
                .collect();

            GetChunksRequestProto {
                chunk_requests,
                operator_id: self.config.operator_id.clone().into_bytes(), // TODO: hex::decode?
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32,
                operator_signature: vec![], // Left blank, modified in self.sign_get_chunks_request (TODO: can it be done in a better way?)
            }
        };

        self.sign_get_chunks_request(&mut request)?;

        let relay_client = self
            .rpc_clients
            .get_mut(&relay_key)
            .ok_or(RelayClientError::InvalidRelayKey(relay_key))?;

        let res = relay_client.get_chunks(request).await.unwrap().into_inner();
        Ok(res.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generated::relay::ChunkRequestByRange,
        relay_client::RelayClient,
        tests::{
            get_test_holesky_rpc_url, BLS_PRIVATE_KEY, HOLESKY_RELAY_REGISTRY_ADDRESS, OPERATOR_ID,
        },
    };

    fn get_test_relay_client_config() -> RelayClientConfig {
        RelayClientConfig {
            max_grpc_message_size: 9999999,
            relay_clients_keys: vec![0, 1, 2],
            relay_registry_address: HOLESKY_RELAY_REGISTRY_ADDRESS,
            eth_rpc_url: get_test_holesky_rpc_url(),
            operator_id: OPERATOR_ID.to_string(),
            bls_private_key: BLS_PRIVATE_KEY.to_string(),
        }
    }

    #[test]
    fn test_hash_get_chunks_request_with_empty_requests() {
        let test_request_empty = GetChunksRequestProto {
            chunk_requests: vec![],
            operator_id: vec![
                201, 153, 167, 111, 188, 113, 30, 37, 78, 145, 171, 80, 212, 48, 177, 104, 38, 158,
                24, 188, 84, 209, 230, 114, 65, 204, 174, 131, 246, 33, 70, 151,
            ],
            timestamp: 0,
            operator_signature: vec![],
        };

        let expected_hash = [
            14, 92, 29, 247, 32, 112, 78, 13, 164, 68, 233, 213, 195, 182, 122, 237, 135, 147, 27,
            128, 208, 10, 143, 39, 228, 7, 108, 125, 141, 127, 246, 73,
        ];
        let actual_hash = hash_get_chunks_request(&test_request_empty).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    #[test]
    fn test_hash_get_chunks_request_by_range() {
        let test_request_by_range = GetChunksRequestProto {
            chunk_requests: vec![
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByRange(ChunkRequestByRange {
                        blob_key: vec![
                            35, 129, 131, 197, 7, 71, 144, 68, 167, 251, 175, 50, 13, 238, 41, 48,
                            94, 186, 194, 190, 67, 245, 157, 163, 227, 228, 145, 133, 109, 122, 2,
                            31,
                        ],
                        start_index: 838755209,
                        end_index: 4151325033,
                    })),
                },
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByRange(ChunkRequestByRange {
                        blob_key: vec![
                            195, 98, 231, 115, 67, 155, 36, 173, 82, 50, 16, 70, 88, 209, 122, 141,
                            141, 147, 7, 125, 69, 10, 22, 22, 17, 148, 183, 78, 128, 123, 194, 221,
                        ],
                        start_index: 3772926323,
                        end_index: 59516524,
                    })),
                },
            ],
            operator_id: vec![
                196, 105, 75, 125, 70, 118, 16, 71, 56, 44, 189, 228, 119, 170, 195, 156, 193, 62,
                43, 89, 179, 237, 208, 95, 3, 14, 180, 118, 202, 54, 161, 136,
            ],
            timestamp: 0,
            operator_signature: vec![],
        };

        let expected_hash = [
            19, 177, 33, 150, 96, 20, 237, 133, 11, 48, 227, 61, 83, 188, 113, 81, 176, 201, 99,
            196, 245, 170, 214, 141, 52, 106, 224, 20, 16, 238, 59, 180,
        ];
        let actual_hash = hash_get_chunks_request(&test_request_by_range).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    // TODO: REMOVE BASE64 CRATE EVENTUALLY

    #[tokio::test]
    async fn test_retrieve_single_blob() {
        let mut client = RelayClient::new(get_test_relay_client_config())
            .await
            .unwrap();

        let blob_key =
            BlobKey::from_hex("625eaa1a5695b260e0caab1c4d4ec97a5211455e8eee0e4fe9464fe8300cf1c4")
                .unwrap();
        let relay_key = 2;
        let result = client.get_blob(relay_key, &blob_key).await;
        assert!(result.is_ok());

        let expected_blob_data = vec![1, 2, 3, 4, 5];
        let actual_blob_data = result.unwrap();
        assert_eq!(expected_blob_data, actual_blob_data);
    }

    #[tokio::test]
    async fn test_sign_get_chunks_request() {
        let mut config = get_test_relay_client_config();

        // We set a specific bls private key, otherwise the signature will be different
        config.bls_private_key =
            "18523706440931002834984598044673773734215117097254740594844099528915818025925"
                .to_string();

        let client = RelayClient::new(config).await.unwrap();

        let mut test_request = GetChunksRequestProto {
            chunk_requests: vec![ChunkRequestProto {
                request: Some(chunk_request::Request::ByRange(ChunkRequestByRange {
                    blob_key: vec![
                        194, 149, 65, 194, 139, 215, 34, 33, 168, 131, 147, 111, 125, 155, 86, 135,
                        109, 54, 26, 50, 183, 155, 154, 4, 16, 126, 219, 97, 138, 29, 148, 187,
                    ],
                    start_index: 1618487414,
                    end_index: 1440410313,
                })),
            }],
            operator_id: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            timestamp: 0,
            operator_signature: vec![],
        };
        client.sign_get_chunks_request(&mut test_request).unwrap();

        let expected_signature = vec![
            13, 201, 103, 55, 115, 63, 62, 42, 102, 207, 208, 109, 29, 11, 190, 182, 118, 54, 85,
            0, 141, 181, 144, 60, 122, 195, 237, 100, 198, 24, 201, 213, 13, 30, 102, 125, 61, 58,
            108, 20, 170, 21, 58, 170, 101, 24, 128, 76, 226, 51, 63, 132, 196, 239, 227, 187, 82,
            74, 202, 235, 158, 10, 245, 189,
        ];
        let actual_signature = test_request.operator_signature;
        assert_eq!(expected_signature, actual_signature)
    }
}
