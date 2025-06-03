use rust_eigenda_v2_common::BlobHeader;

use crate::{
    core::BlobKey, errors::ValidatorClientError, validator_client::ValidatorClientConfig,
    validator_types::EncodingParams,
};

pub(crate) struct RetrievalWorker {}

impl RetrievalWorker {
    pub(crate) fn new(
        config: ValidatorClientConfig,
        assigments: Vec<Vec<u8>>,
        minimum_chunk_count: u64,
        encoding_params: EncodingParams,
        blob_header: &BlobHeader,
        blob_key: BlobKey,
    ) -> Self {
        unimplemented!()
    }

    pub(crate) fn retrieve_blob_from_validators(&self) -> Result<Vec<u8>, ValidatorClientError> {
        unimplemented!()
    }
}
