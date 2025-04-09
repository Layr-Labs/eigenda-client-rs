use crate::core::eigenda_cert::BlobKey;


pub struct RelayKey;
pub struct ChunkRequestByRange;

pub struct RelayClientConfig {
    pub max_grpc_message_size: usize,
}

// RelayClient is a client for the entire relay subsystem.
//
// It is a wrapper around a collection of grpc relay clients, which are used to interact with individual relays.
pub struct RelayClient {
    config: RelayClientConfig,
}

impl RelayClient {
    pub fn new(config: RelayClientConfig) -> Self {
        Self { config }
    }

    // get_blob retrieves a blob from a relay.
    pub async fn get_blob(&self, relay_key: RelayKey, blob_key: BlobKey) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    // get_chunks_by_range retrieves blob chunks from a relay by chunk index range
	// The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
	// Each bundle is a sequence of frames in raw form (i.e., serialized core.Bundle bytearray).
    pub async fn get_chunks_by_range(&self, relay_key: RelayKey, requests: Vec<ChunkRequestByRange>) -> Result<Vec<Vec<u8>>, String> {
        unimplemented!()
    }

   	// get_chunks_by_index retrieves blob chunks from a relay by index
	// The returned slice has the same length and ordering as the input slice, and the i-th element is the bundle for the i-th request.
	// Each bundle is a sequence of frames in raw form (i.e., serialized core.Bundle bytearray).
    pub async fn get_chunks_by_index(&self, relay_key: RelayKey) -> Result<Vec<Vec<u8>>, String> {
        unimplemented!()
    }

}
