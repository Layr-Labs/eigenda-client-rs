use tonic::transport::Channel;

use crate::{
    core::eigenda_cert::BlobKey,
    errors::RelayClientError,
    generated::relay::{
        chunk_request,
        relay_client::{self, RelayClient as RpcRelayClient},
        ChunkRequest, ChunkRequestByIndex as RpcChunkRequestByIndex,
        ChunkRequestByRange as RpcChunkRequestByRange, GetBlobRequest, GetChunksRequest,
    },
    utils::get_timestamp,
};

pub type RelayKey = u32;

pub struct ChunkRequestByRange {
    pub(crate) blob_key: BlobKey,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

pub struct ChunkRequestByIndex {
    pub(crate) blob_key: BlobKey,
    pub(crate) indices: Vec<u32>,
}

pub struct RelayClientConfig {
    pub(crate) max_grpc_message_size: usize,
    pub(crate) operator_id: u32,
    pub(crate) operator_signature: Vec<u8>,
    pub(crate) relay_clients_rpcs: Vec<String>,
}

// RelayClient is a client for the entire relay subsystem.
//
// It is a wrapper around a collection of grpc relay clients, which are used to interact with individual relays.
pub struct RelayClient {
    config: RelayClientConfig,
    rpc_clients: Vec<RpcRelayClient<tonic::transport::Channel>>,
}

impl RelayClient {
    pub async fn new(config: RelayClientConfig) -> Result<Self, RelayClientError> {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let mut rpc_clients = Vec::new();
        for relay_client_rpc in config.relay_clients_rpcs.iter() {
            let endpoint = Channel::from_shared(relay_client_rpc.clone())
                .map_err(|_| RelayClientError::InvalidURI(relay_client_rpc.clone()))?;
            let channel = endpoint.connect().await?;
            let rpc_client = relay_client::RelayClient::new(channel);
            rpc_clients.push(rpc_client);
        }

        Ok(Self {
            config,
            rpc_clients,
        })
    }

    // get_blob retrieves a blob from a relay.
    pub async fn get_blob(
        &mut self,
        relay_key: RelayKey,
        blob_key: BlobKey,
    ) -> Result<Vec<u8>, RelayClientError> {
        if relay_key as usize >= self.rpc_clients.len() {
            return Err(RelayClientError::InvalidRelayKey(relay_key));
        }

        let res = self.rpc_clients[relay_key as usize]
            .get_blob(GetBlobRequest {
                blob_key: blob_key.to_vec(),
            })
            .await?
            .into_inner();

        Ok(res.blob)
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

        let mut grpc_requests = Vec::new();
        for request in requests {
            grpc_requests.push(ChunkRequest {
                request: Some(chunk_request::Request::ByRange(RpcChunkRequestByRange {
                    blob_key: request.blob_key.to_vec(),
                    start_index: request.start,
                    end_index: request.end,
                })),
            })
        }

        let request = GetChunksRequest {
            chunk_requests: grpc_requests,
            operator_id: self.config.operator_id.to_be_bytes().to_vec(),
            timestamp: get_timestamp()
                .map_err(|_| RelayClientError::FailedToFetchCurrentTimestamp)?
                as u32,
            operator_signature: self.config.operator_signature.clone(),
        };

        let res = self.rpc_clients[relay_key as usize]
            .get_chunks(request)
            .await?
            .into_inner();

        Ok(res.data)
    }

    // get_chunks_by_index retrieves blob chunks from a relay by index
    // The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
    // Each bundle is a sequence of frames in raw form (i.e., serialized core.Bundle bytearray).
    pub async fn get_chunks_by_index(
        &mut self,
        relay_key: RelayKey,
        requests: Vec<ChunkRequestByIndex>,
    ) -> Result<Vec<Vec<u8>>, RelayClientError> {
        if requests.is_empty() {
            return Err(RelayClientError::EmptyRequest);
        }

        let mut grpc_requests = Vec::new();
        for request in requests {
            grpc_requests.push(ChunkRequest {
                request: Some(chunk_request::Request::ByIndex(RpcChunkRequestByIndex {
                    blob_key: request.blob_key.to_vec(),
                    chunk_indices: request.indices,
                })),
            });
        }

        let request = GetChunksRequest {
            chunk_requests: grpc_requests,
            operator_id: self.config.operator_id.to_be_bytes().to_vec(),
            timestamp: get_timestamp()
                .map_err(|_| RelayClientError::FailedToFetchCurrentTimestamp)?
                as u32,
            operator_signature: self.config.operator_signature.clone(),
        };

        let res = self.rpc_clients[relay_key as usize]
            .get_chunks(request)
            .await?
            .into_inner();

        Ok(res.data)
    }
}
