use crate::{
    core::eigenda_cert::BlobKey,
    generated::relay::{
        chunk_request, relay_client::RelayClient as RpcRelayClient, ChunkRequest,
        ChunkRequestByIndex as RpcChunkRequestByIndex,
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
}

// RelayClient is a client for the entire relay subsystem.
//
// It is a wrapper around a collection of grpc relay clients, which are used to interact with individual relays.
pub struct RelayClient {
    config: RelayClientConfig,
    rpc_clients: Vec<RpcRelayClient<tonic::transport::Channel>>,
}

impl RelayClient {
    pub fn new(
        config: RelayClientConfig,
        rpc_clients: Vec<RpcRelayClient<tonic::transport::Channel>>,
    ) -> Self {
        if config.max_grpc_message_size == 0 {
            panic!("max grpc message size must be greater than 0");
        }

        Self {
            config,
            rpc_clients,
        }
    }

    // get_blob retrieves a blob from a relay.
    pub async fn get_blob(
        &mut self,
        relay_key: RelayKey,
        blob_key: BlobKey,
    ) -> Result<Vec<u8>, String> {
        if relay_key as usize >= self.rpc_clients.len() {
            return Err("Invalid relay key".to_string());
        }

        let res = self.rpc_clients[relay_key as usize]
            .get_blob(GetBlobRequest {
                blob_key: blob_key.to_vec(),
            })
            .await
            .unwrap()
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
    ) -> Result<Vec<Vec<u8>>, String> {
        if requests.is_empty() {
            return Err("Invalid request".to_string());
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
            timestamp: get_timestamp().unwrap() as u32,
            operator_signature: self.config.operator_signature.clone(),
        };

        let res = self.rpc_clients[relay_key as usize]
            .get_chunks(request)
            .await
            .unwrap()
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
    ) -> Result<Vec<Vec<u8>>, String> {
        if requests.is_empty() {
            return Err("Invalid request".to_string());
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
            timestamp: get_timestamp().unwrap() as u32,
            operator_signature: self.config.operator_signature.clone(),
        };

        let res = self.rpc_clients[relay_key as usize]
            .get_chunks(request)
            .await
            .unwrap()
            .into_inner();

        Ok(res.data)
    }
}
