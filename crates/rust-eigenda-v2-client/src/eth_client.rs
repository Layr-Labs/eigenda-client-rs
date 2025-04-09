//! This client is inspired in ethrex EthClient https://github.com/lambdaclass/ethrex/blob/1d3ae1edf2dd40702c69bb09d8def3a0c0047ff8/crates/l2/sdk/src/eth_client/mod.rs
//! We use this low level client in order to avoid adding unnecessary dependencies that would make the compile time longer
use bytes::Bytes;
use ethereum_types::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{errors::EthClientError, utils::SecretUrl};

/// Request ID for the RPC
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RpcRequestId {
    Number(u64),
    String(String),
}

/// Response for a successful RPC request
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcSuccessResponse {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) result: Value,
}

/// Metadata for an RPC error
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcErrorMetadata {
    pub(crate) code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<String>,
    pub(crate) message: String,
}

/// Response for an RPC error
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorResponse {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) error: RpcErrorMetadata,
}

impl std::fmt::Display for RpcErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcErrorResponse: {:?}", self)
    }
}

/// Response for an RPC request
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum RpcResponse {
    Success(RpcSuccessResponse),
    Error(RpcErrorResponse),
}

/// Request for the RPC
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcRequest {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) method: String,
    pub(crate) params: Option<Vec<Value>>,
}

/// Client for interacting with an Ethereum node
#[derive(Debug, Clone)]
pub(crate) struct EthClient {
    client: reqwest::Client,
    pub(crate) url: SecretUrl,
    pub(crate) cert_verifier_addr: Address,
    pub(crate) threshold_registry_addr: Address,
}

impl EthClient {
    /// Creates a new EthClient
    pub(crate) fn new(
        url: SecretUrl,
        cert_verifier_addr: Address,
        threshold_registry_addr: Address,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            cert_verifier_addr,
            threshold_registry_addr,
        }
    }

    /// Sends a request to the Ethereum node
    async fn send_request(&self, request: RpcRequest) -> Result<RpcResponse, EthClientError> {
        let url: Url = self.url.clone().into();
        self.client
            .post(url)
            .header("content-type", "application/json")
            .body(serde_json::ser::to_string(&request).map_err(EthClientError::SerdeJSON)?)
            .send()
            .await?
            .json::<RpcResponse>()
            .await
            .map_err(EthClientError::from)
    }

    /// Gets the latest block number
    pub(crate) async fn get_block_number(&self) -> Result<U256, EthClientError> {
        let request = RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: "eth_blockNumber".to_string(),
            params: None,
        };

        match self.send_request(request).await {
            Ok(RpcResponse::Success(result)) => {
                serde_json::from_value(result.result).map_err(EthClientError::SerdeJSON)
            }
            Ok(RpcResponse::Error(error_response)) => Err(EthClientError::Rpc(error_response)),
            Err(error) => Err(error),
        }
    }

    /// Calls a contract
    pub(crate) async fn call(
        &self,
        to: Address,
        calldata: Bytes,
        block: Option<u64>,
    ) -> Result<Vec<u8>, EthClientError> {
        let request = RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: "eth_call".to_string(),
            params: Some(vec![
                json!({
                    "to": format!("{:#x}",to),
                    "input": format!("0x{:#x}", calldata),
                    "value": format!("{:#x}", 0),
                    "from": format!("{:#x}", Address::zero()),
                }),
                json!(match block {
                    Some(block) => format!("{:#x}", block),
                    None => "latest".to_string(),
                }),
            ]),
        };

        let res: String = match self.send_request(request).await {
            Ok(RpcResponse::Success(result)) => {
                serde_json::from_value(result.result).map_err(EthClientError::SerdeJSON)
            }
            Ok(RpcResponse::Error(error_response)) => Err(EthClientError::Rpc(error_response)),
            Err(error) => Err(error),
        }?;

        let res = res.trim_start_matches("0x");
        hex::decode(res).map_err(EthClientError::HexEncoding)
    }
}
