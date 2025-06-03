use std::collections::HashMap;

use ethabi::{ParamType, Token};
use ethereum_types::U256;

use crate::{
    errors::{AbiEncodeError, EthClientError, ValidatorClientError},
    eth_client::EthClient,
    utils::{u16_from_token, u32_from_token},
    validator_types::BlobVersionParameters,
};

/// Trait that defines the methods for the eth_client used by the retrieval client
#[async_trait::async_trait]
pub trait ValidatorReader: Sync + Send + std::fmt::Debug {
    async fn get_all_versioned_blob_params(
        &self,
    ) -> Result<HashMap<u16, BlobVersionParameters>, ValidatorClientError>;
}

#[async_trait::async_trait]
impl ValidatorReader for EthClient {
    async fn get_all_versioned_blob_params(
        &self,
    ) -> Result<HashMap<u16, BlobVersionParameters>, ValidatorClientError> {
        // Solidity: function nextBlobVersion() view returns(uint16)
        let func_selector = ethabi::short_signature("nextBlobVersion", &[]);
        let data = func_selector.to_vec();
        let response_bytes = self
            .call(
                self.threshold_registry_addr,
                bytes::Bytes::copy_from_slice(&data),
                None,
            )
            .await?;
        let output_type = [ParamType::Uint(16)];

        let tokens =
            ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;

        // Safe unwrap because decode guarantees type correctness and non-empty output
        let next_blob_version_token = tokens.iter().next().unwrap();
        let next_blob_version = u16_from_token(next_blob_version_token)?;

        let mut blob_params = HashMap::new();
        for blob_version in 0..next_blob_version {
            // Solidity: function getBlobParams(uint16 version) view returns((uint32,uint32,uint8))
            let func_selector = ethabi::short_signature("getBlobParams", &[]);
            let mut data = func_selector.to_vec();
            let mut blob_version_token = Token::Uint(U256::from(blob_version))
                .into_bytes()
                .ok_or(AbiEncodeError::EncodeTokenAsBytes)?;
            data.append(&mut blob_version_token);

            let response_bytes = self
                .call(
                    self.threshold_registry_addr,
                    bytes::Bytes::copy_from_slice(&data),
                    None,
                )
                .await?;
            let output_type = [ParamType::Uint(32), ParamType::Uint(32), ParamType::Uint(8)];
            let tokens =
                ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;
            let mut tokens_iter = tokens.iter();

            // Safe unwrap because decode guarantees type correctness and non-empty output
            let coding_rate_token = tokens_iter.next().unwrap();
            let max_num_operators_token = tokens_iter.next().unwrap();
            let num_chunks_token = tokens_iter.next().unwrap();
            blob_params.insert(
                blob_version.into(),
                BlobVersionParameters {
                    coding_rate: u32_from_token(coding_rate_token)?,
                    max_num_operators: u32_from_token(max_num_operators_token)?,
                    num_chunks: u32_from_token(num_chunks_token)?,
                },
            );
        }

        Ok(blob_params)
    }
}
