use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::G1Affine;
use ark_serialize::CanonicalSerialize;
use eigensdk::crypto_bls::BlsKeyPair;
use ethabi::Address;
use ethers::signers::Signer;
use tiny_keccak::{Hasher, Keccak};
use tonic::transport::Channel;

use crate::{
    core::BlobKey,
    errors::{ConversionError, RelayClientError},
    generated::relay::{
        chunk_request,
        relay_client::{self, RelayClient as RpcRelayClient},
        ChunkRequest as ChunkRequestProto, ChunkRequestByIndex as ChunkRequestByIndexProto,
        ChunkRequestByRange as ChunkRequestByRangeProto, GetBlobRequest,
        GetChunksRequest as GetChunksRequestProto,
    },
    relay_registry::RelayRegistry,
    utils::SecretUrl,
};
use rust_eigenda_signers::signers::ethers::Signer as EthersSigner;

const RELAY_GET_CHUNKS_REQUEST_DOMAIN: &str = "relay.GetChunksRequest";
const CHUNK_REQUEST_BY_RANGE: u8 = 0x72; // 'r'
const CHUNK_REQUEST_BY_INDEX: u8 = 0x69; // 'i'

fn g1_point_raw_bytes(g1_point: &G1Affine) -> Result<Vec<u8>, ConversionError> {
    let mut bytes = vec![];

    let mut y_bytes = Vec::new();
    g1_point
        .y
        .serialize_uncompressed(&mut y_bytes)
        .map_err(|e| ConversionError::G1Point(e.to_string()))?;
    bytes.extend_from_slice(&y_bytes);

    let mut x_bytes = Vec::new();
    g1_point
        .x
        .serialize_uncompressed(&mut x_bytes)
        .map_err(|e| ConversionError::G1Point(e.to_string()))?;
    bytes.extend_from_slice(&x_bytes);

    bytes.reverse();
    Ok(bytes)
}

fn hash_get_chunks_request(request: &GetChunksRequestProto) -> Result<[u8; 32], RelayClientError> {
    let mut hasher = Keccak::v256();

    hasher.update(RELAY_GET_CHUNKS_REQUEST_DOMAIN.as_bytes());
    hasher.update(&(request.operator_id.len() as u32).to_be_bytes());
    hasher.update(&request.operator_id);

    hasher.update(&(request.chunk_requests.len() as u32).to_be_bytes());
    for request in &request.chunk_requests {
        match &request.request {
            Some(chunk_request::Request::ByIndex(req)) => {
                hasher.update(&[CHUNK_REQUEST_BY_INDEX]);
                hasher.update(&(req.blob_key.len() as u32).to_be_bytes());
                hasher.update(&req.blob_key);
                hasher.update(&(req.chunk_indices.len() as u32).to_be_bytes());
                for index in &req.chunk_indices {
                    hasher.update(&index.to_be_bytes());
                }
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

pub struct ChunkRequestByRange {
    blob_key: BlobKey,
    start_index: u32,
    end_index: u32,
}

pub struct RelayClientConfig {
    pub(crate) max_grpc_message_size: usize,
    pub(crate) relay_clients_keys: Vec<u32>,
    pub(crate) relay_registry_address: Address,
    pub(crate) eth_rpc_url: SecretUrl,
    // Operator ID is encoded as a hex string.
    pub(crate) operator_id: String,
    pub(crate) bls_private_key: String,
}

/// [`RelayClient`] is a client for the entire relay subsystem.
///
/// It is a wrapper around a collection of GRPC clients, which are used to interact with individual relays.
/// This struct is a low level implementation and should not be used directly,
/// use a high level abstraction to interact with it ([`RelayPayloadRetriever`]).
pub struct RelayClient {
    rpc_clients: HashMap<RelayKey, RpcRelayClient<tonic::transport::Channel>>,
    config: RelayClientConfig,
    message_signer: BlsKeyPair,
}

impl RelayClient {
    pub async fn new<S>(config: RelayClientConfig, signer: S) -> Result<Self, RelayClientError>
    where
        EthersSigner<S>: Signer,
    {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let relay_registry = RelayRegistry::new(
            config.relay_registry_address,
            config.eth_rpc_url.clone(),
            signer,
        )?;

        let mut rpc_clients = HashMap::new();
        for relay_key in config.relay_clients_keys.iter() {
            let url = relay_registry.get_url_from_relay_key(*relay_key).await?;
            let endpoint =
                Channel::from_shared(url.clone()).map_err(|_| RelayClientError::InvalidURI(url))?;
            let channel = endpoint.connect().await?;
            let rpc_client = relay_client::RelayClient::new(channel);
            rpc_clients.insert(*relay_key, rpc_client);
        }

        let bls_private_key = config.bls_private_key.clone();
        let message_signer = BlsKeyPair::new(bls_private_key.clone())
            .map_err(|_| RelayClientError::InvalidBLSPrivateKey(bls_private_key))?;

        Ok(Self {
            rpc_clients,
            config,
            message_signer,
        })
    }

    /// Retrieves a blob from a relay.
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
        let sig = g1_point_raw_bytes(&signature.g1_point().g1())?;
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

            let operator_id = hex::decode(self.config.operator_id.clone()).map_err(|_| {
                RelayClientError::InvalidOperatorID(self.config.operator_id.clone())
            })?;
            GetChunksRequestProto {
                chunk_requests,
                operator_id,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32,
                operator_signature: vec![], // Left blank, modified in self.sign_get_chunks_request (TODO: can it be done in a better way?)
            }
        };

        self.sign_get_chunks_request(&mut request)?;

        let relay_client = self
            .rpc_clients
            .get_mut(&relay_key)
            .ok_or(RelayClientError::InvalidRelayKey(relay_key))?;

        let res = relay_client.get_chunks(request).await?.into_inner();
        Ok(res.data)
    }

    // get_chunks_by_range retrieves blob chunks from a relay by chunk index range
    // The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
    // Each bundle is a sequence of frames in raw form (i.e., serialized core.Bundle bytearray).
    pub async fn get_chunks_by_range(
        &mut self,
        relay_key: RelayKey,
        requests: Vec<ChunkRequestByRange>,
    ) -> Result<Vec<Vec<u8>>, RelayClientError> {
        if requests.is_empty() {
            return Err(RelayClientError::EmptyRequest);
        }

        let mut request = {
            let chunk_requests = requests
                .into_iter()
                .map(|request| ChunkRequestProto {
                    request: Some(chunk_request::Request::ByRange(ChunkRequestByRangeProto {
                        blob_key: request.blob_key.to_bytes().to_vec(),
                        start_index: request.start_index,
                        end_index: request.end_index,
                    })),
                })
                .collect();

            let operator_id = hex::decode(self.config.operator_id.clone()).map_err(|_| {
                RelayClientError::InvalidOperatorID(self.config.operator_id.clone())
            })?;
            GetChunksRequestProto {
                chunk_requests,
                operator_id,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32,
                operator_signature: vec![], // Left blank, modified in self.sign_get_chunks_request (TODO: can it be done in a better way?)
            }
        };

        self.sign_get_chunks_request(&mut request)?;

        let relay_client = self
            .rpc_clients
            .get_mut(&relay_key)
            .ok_or(RelayClientError::InvalidRelayKey(relay_key))?;

        let res = relay_client.get_chunks(request).await?.into_inner();
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
            get_test_holesky_rpc_url, get_test_private_key_signer, BLS_PRIVATE_KEY,
            HOLESKY_RELAY_REGISTRY_ADDRESS, OPERATOR_ID,
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

    #[test]
    fn test_hash_get_chunks_request_by_index() {
        let test_request_by_range = GetChunksRequestProto {
            chunk_requests: vec![
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByIndex(ChunkRequestByIndexProto {
                        blob_key: vec![
                            74, 175, 235, 241, 191, 90, 144, 126, 204, 146, 115, 115, 30, 65, 151,
                            17, 0, 217, 86, 9, 4, 186, 209, 245, 4, 252, 35, 194, 227, 252, 35, 79,
                        ],
                        chunk_indices: vec![
                            758166708, 755702841, 3071977814, 4000427110, 3579555988,
                        ],
                    })),
                },
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByIndex(ChunkRequestByIndexProto {
                        blob_key: vec![
                            244, 43, 219, 203, 238, 107, 244, 134, 165, 177, 209, 83, 35, 192, 192,
                            89, 53, 89, 119, 106, 202, 96, 59, 229, 175, 208, 45, 184, 41, 83, 140,
                            72,
                        ],
                        chunk_indices: vec![2264458652, 3625422776],
                    })),
                },
            ],
            operator_id: vec![
                89, 110, 60, 62, 69, 59, 210, 3, 162, 158, 169, 35, 95, 157, 24, 91, 160, 201, 26,
                193, 195, 93, 250, 23, 46, 76, 193, 70, 84, 28, 134, 167,
            ],
            timestamp: 0,
            operator_signature: vec![],
        };

        let expected_hash = [
            115, 233, 164, 222, 90, 174, 202, 253, 137, 225, 212, 55, 110, 142, 252, 179, 91, 51,
            150, 97, 178, 115, 170, 2, 102, 21, 178, 4, 86, 216, 197, 39,
        ];
        let actual_hash = hash_get_chunks_request(&test_request_by_range).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_sign_get_chunks_request() {
        let mut config = get_test_relay_client_config();

        // We set a specific bls private key, otherwise the signature will be different
        config.bls_private_key =
            "18959225578362426315950880151265128588967843516032712394056671181174645903587"
                .to_string();

        let client = RelayClient::new(config, get_test_private_key_signer())
            .await
            .unwrap();

        let mut test_request = GetChunksRequestProto {
            chunk_requests: vec![
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByIndex(ChunkRequestByIndexProto {
                        blob_key: vec![
                            170, 196, 143, 51, 173, 161, 147, 250, 108, 61, 45, 68, 86, 179, 148,
                            157, 75, 222, 161, 73, 4, 174, 51, 208, 191, 146, 219, 241, 236, 68,
                            178, 80,
                        ],
                        chunk_indices: vec![
                            203844548, 1456580166, 152621468, 67180442, 786495950, 3407409718,
                            3460281575, 2153531929, 2944574584, 3432716980,
                        ],
                    })),
                },
                ChunkRequestProto {
                    request: Some(chunk_request::Request::ByRange(ChunkRequestByRange {
                        blob_key: vec![
                            235, 208, 225, 148, 235, 203, 86, 167, 207, 184, 43, 95, 3, 210, 169,
                            105, 136, 70, 163, 114, 183, 245, 17, 193, 37, 101, 89, 59, 107, 190,
                            4, 229,
                        ],
                        start_index: 1739543624,
                        end_index: 3569400570,
                    })),
                },
            ],
            operator_id: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            timestamp: 0,
            operator_signature: vec![],
        };
        client.sign_get_chunks_request(&mut test_request).unwrap();

        let expected_signature = vec![
            36, 200, 137, 60, 194, 52, 175, 141, 50, 95, 123, 124, 91, 92, 117, 98, 66, 208, 211,
            159, 81, 14, 26, 245, 71, 231, 91, 94, 188, 69, 48, 92, 12, 95, 67, 180, 233, 245, 97,
            72, 40, 43, 100, 11, 249, 41, 33, 163, 93, 69, 168, 88, 215, 235, 221, 25, 124, 200,
            71, 64, 22, 8, 207, 228,
        ];
        let actual_signature = test_request.operator_signature;
        assert_eq!(expected_signature, actual_signature)
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_retrieve_single_blob() {
        let mut client = RelayClient::new(
            get_test_relay_client_config(),
            get_test_private_key_signer(),
        )
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
}
