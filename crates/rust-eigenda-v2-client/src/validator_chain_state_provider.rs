use std::collections::HashMap;

use ethabi::{ParamType, Token};
use ethereum_types::U256;

use crate::{errors::{AbiEncodeError, EthClientError, ValidatorClientError}, eth_client::EthClient, utils::{string_from_token, u256_from_token}, validator_types::{OperatorInfo, OperatorState}};

/// Trait that defines the methods for the chain_state used by the retrieval client
#[async_trait::async_trait]
pub trait RetrievalChainStateProvider: Sync + Send + std::fmt::Debug {
    async fn get_operator_state_with_socket(
        &self,
        block_number: u64,
        quorums: Vec<u8>,
    ) -> Result<OperatorState, ValidatorClientError>;
}


#[async_trait::async_trait]
impl RetrievalChainStateProvider for EthClient {
    async fn get_operator_state_with_socket(
        &self,
        block_number: u64,
        quorums: Vec<u8>,
    ) -> Result<OperatorState, ValidatorClientError> {
        // Solidity: function getOperatorStateWithSocket(address registryCoordinator, bytes quorumNumbers, uint32 blockNumber) view returns((address,bytes32,uint96)[][] operators, string[][] sockets)
        let func_selector = ethabi::short_signature("getOperatorStateWithSocket", &[]);
        let mut data = func_selector.to_vec();

        let mut registry_coordinator_bytes = Token::Address(self.threshold_registry_addr)
            .into_bytes()
            .ok_or(AbiEncodeError::EncodeTokenAsBytes)?;
        data.append(&mut registry_coordinator_bytes);

        let mut quorum_numbers_bytes = Token::Bytes(quorums)
            .into_bytes()
            .ok_or(AbiEncodeError::EncodeTokenAsBytes)?;
        data.append(&mut quorum_numbers_bytes);

        let mut block_number_bytes = Token::Uint(U256::from(block_number))
            .into_bytes()
            .ok_or(AbiEncodeError::EncodeTokenAsBytes)?;
        data.append(&mut block_number_bytes);

        let response_bytes = self
            .call(
                self.contract_operator_state_retriever_addr,
                bytes::Bytes::copy_from_slice(&data),
                None,
            )
            .await?;
        let output_type = [
            // operators
            ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::Tuple(
                vec![
                    ParamType::Address,
                    ParamType::FixedBytes(32),
                    ParamType::Uint(96),
                ],
            ))))),
            // sockets
            ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::String)))),
        ];
        let tokens =
            ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;
        let mut tokens_iter = tokens.iter();

        // Safe unwrap because decode guarantees type correctness and non-empty output
        // from: https://github.com/Layr-Labs/eigenda/blob/57a7b3b20907dfe0f46dc534a0d2673203e69267/core/eth/reader.go#L494-L498
        // Operators is a [][]*opstateretriever.OperatorStake with the same length and order as quorumBytes, and then indexed by operator index
        let mut operators = HashMap::new();
        let operators_token = tokens_iter.next().unwrap().clone().into_array().unwrap();
        for (quorum_id, inner_token) in operators_token.iter().enumerate() {
            let mut quorum_operators = HashMap::new();
            for (operator_idx, operator_stake_tokens) in
                inner_token.clone().into_array().unwrap().iter().enumerate()
            {
                let operator_stake_tokens = operator_stake_tokens.clone().into_tuple().unwrap();
                let mut operator_stake_tokens_iter = operator_stake_tokens.iter();
                let _address_token = operator_stake_tokens_iter.next().unwrap(); // Unused?
                let _operator_id_bytes_token = operator_stake_tokens_iter.next().unwrap(); // Unused? We already have the id with the enumeration
                let stake_token = operator_stake_tokens_iter.next().unwrap();
                let stake = u256_from_token(stake_token)?;

                let operator_info = OperatorInfo {
                    stake,
                    index: operator_idx,
                    _socket: String::default(), // TODO: Irrelevant, remove?
                };
                quorum_operators.insert(operator_idx, operator_info);
            }
            operators.insert(quorum_id as u8, quorum_operators);
        }

        // Safe unwrap because decode guarantees type correctness and non-empty output
        // Sockets is a [][]string with the same length and order as quorumBytes, and then indexed by operator index
        let sockets_token = tokens_iter.next().unwrap().clone().into_array().unwrap();
        let mut totals = HashMap::new();
        for (quorum_id, inner_token) in sockets_token.iter().enumerate() {
            for (operator_idx, socket_token) in
                inner_token.clone().into_array().unwrap().iter().enumerate()
            {
                let mut total_stake = U256::zero();
                let quorum_operators = operators.get(&(quorum_id as u8)).unwrap();
                for (_, operator) in quorum_operators {
                    total_stake += operator.stake;
                }
                let socket = string_from_token(socket_token)?;
                totals.insert(
                    quorum_id as u8,
                    OperatorInfo {
                        stake: total_stake,
                        index: operator_idx,
                        _socket: socket,
                    },
                );
            }
        }

        Ok(OperatorState {
            operators,
            totals,
            _block_number: block_number as usize,
        })
    }
}
