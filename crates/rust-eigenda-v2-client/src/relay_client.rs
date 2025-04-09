use crate::{
    core::eigenda_cert::BlobKey,
    generated::{
        relay::{relay_client::RelayClient as RpcRelayClient, GetBlobRequest},
        validator::retrieval_client::RetrievalClient,
    },
};

pub type RelayKey = u32;
pub struct ChunkRequestByRange;

pub struct RelayClientConfig {
    pub max_grpc_message_size: usize,
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
        &self,
        relay_key: RelayKey,
        requests: Vec<ChunkRequestByRange>,
    ) -> Result<Vec<Vec<u8>>, String> {
        unimplemented!()
    }

    // get_chunks_by_index retrieves blob chunks from a relay by index
    // The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
    // Each bundle is a sequence of frames in raw form (i.e., serialized core.Bundle bytearray).
    pub async fn get_chunks_by_index(&self, relay_key: RelayKey) -> Result<Vec<Vec<u8>>, String> {
        unimplemented!()
    }
}
