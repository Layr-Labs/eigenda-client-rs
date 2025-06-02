use std::collections::HashMap;

use rust_eigenda_v2_common::BlobHeader;

use crate::{core::BlobKey, errors::ValidatorClientError, eth_client::EthClient, validator_chain_state_provider::RetrievalChainStateProvider, validator_verifier::ValidatorVerifier};

/// Contains the configuration for the validator retrieval client.

pub(crate) struct ValidatorClientConfig {
    download_pessimism: f64,
    verification_pessimism: f64,
    pessimistic_timeout: tokio::time::Duration,
    download_timeout: tokio::time::Duration,
    control_loop_period: tokio::time::Duration,
    detailed_logging: bool,
    connection_pool_size: usize,
    compute_pool_size: usize,
}

/// ValidatorClient is an object that can retrieve blobs from the validator nodes.
/// To retrieve a blob from the relay, use RelayClient instead.
pub(crate) struct ValidatorClient {
    reader: Reader,
    chain_state: EthClient, // todo add trait
    verifier: EthClient,
    config: ValidatorClientConfig,
}

impl ValidatorClient {
    /// Downloads chunks of a blob from operator network and reconstructs the blob.
    pub async fn get_blob(&self, blob_header: &BlobHeader, reference_block_number: u32) -> Result<Vec<u8>, ValidatorClientError> {
        self.verifier.verify_commit_equivalence_batch(vec![blob_header.commitment]).await?;

        let operator_state = self.chain_state.get_operator_state_with_socket(reference_block_number as u64, blob_header.quorum_numbers.clone()).await?;

        let blob_versions = self.reader.get_all_versioned_blob_params().await?;

        let blob_params = blob_versions[blob_header.version as usize];

        let encoding_params = get_encoding_params(blob_header.commitment.length,blob_params);

        let blob_key = BlobKey::compute_blob_key(blob_header);

        let assigments = get_assigment_for_blob(operator_state, blob_params, blob_header.quorum_numbers);

        let minimum_chunk_count = encoding_params.num_chunks / blob_params.coding_rate;

        let sockets = self.get_flattened_operator_sockets(operator_state.operators);

        let worker = RetrievalWorker::new(
            self.config,
            assigments,
            minimum_chunk_count,
            encoding_params,
            blob_header,
            blob_key,
        );

        let blob = worker.retrieve_blob_from_validators();
        Ok(blob)
    }

    async fn get_flattened_operator_sockets(&self, operators: HashMap<QuorumID,HashMap<OperatorID,OperatorInfo>>) -> HashMap<OperatorID, OperatorSocker> {
        let mut operator_sockets = HashMap::new();
        for (_, quorum_operator) in operators {
            for (operator_id, operator) in quorum_operator {
                if !operator_sockets.contains_key(operator_id) {
                    operator_sockets[operator_id] = operator.socket;
                }
            }
        }
        
    }
}


