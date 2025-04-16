use std::{collections::HashMap, sync::Arc};

use ethabi::{Address, ParamType, Token};
use ethereum_types::U256;
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::{
    core::BlobKey,
    errors::{EthClientError, RelayClientError},
    eth_client::EthClient,
    generated::relay::{
        relay_client::{self, RelayClient as RpcRelayClient},
        GetBlobRequest,
    },
};

pub type RelayKey = u32;

pub struct RelayClientConfig {
    pub(crate) max_grpc_message_size: usize,
    pub(crate) relay_clients_keys: Vec<u32>,
    pub(crate) relay_registry_address: Address,
}

async fn get_url_from_relay_key(
    eth_client: Arc<Mutex<EthClient>>,
    relay_registry_address: Address,
    relay_key: RelayKey,
) -> Result<String, EthClientError> {
    // Solidity: function relayKeyToUrl() view returns(string)
    let func_selector = ethabi::short_signature("relayKeyToUrl", &[ParamType::Uint(32)]);
    let mut data = func_selector.to_vec();

    let relay_key_data = ethabi::encode(&[Token::Uint(U256::from(relay_key))]);
    data.extend_from_slice(&relay_key_data);

    let response_bytes = eth_client
        .lock()
        .await
        .call(
            relay_registry_address,
            bytes::Bytes::copy_from_slice(&data),
            None,
        )
        .await?;

    let output_type = [ParamType::String];

    let tokens = ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;

    // Safe unwrap because decode guarantees type correctness and non-empty output
    let url_token = tokens.first().unwrap();
    let url = format!("https://{}", url_token.clone().into_string().unwrap()); // TODO: forcing https schema on local stack will fail

    Ok(url)
}

// RelayClient is a client for the entire relay subsystem.
//
// It is a wrapper around a collection of grpc relay clients, which are used to interact with individual relays.
pub struct RelayClient {
    rpc_clients: HashMap<RelayKey, RpcRelayClient<tonic::transport::Channel>>,
}

impl RelayClient {
    pub async fn new(
        config: RelayClientConfig,
        eth_client: Arc<Mutex<EthClient>>,
    ) -> Result<Self, RelayClientError> {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let mut rpc_clients = HashMap::new();
        for relay_key in config.relay_clients_keys.iter() {
            let url = get_url_from_relay_key(
                eth_client.clone(),
                config.relay_registry_address,
                *relay_key,
            )
            .await?;
            let endpoint =
                Channel::from_shared(url.clone()).map_err(|_| RelayClientError::InvalidURI(url))?;
            let channel = endpoint.connect().await?;
            let rpc_client = relay_client::RelayClient::new(channel);
            rpc_clients.insert(*relay_key, rpc_client);
        }

        Ok(Self { rpc_clients })
    }

    // get_blob retrieves a blob from a relay.
    pub async fn get_blob(
        &mut self,
        relay_key: RelayKey,
        blob_key: BlobKey,
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
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{eth_client::EthClient, relay_client::RelayClient, utils::SecretUrl};
    use ethereum_types::H160;
    use url::Url;

    fn test_config() -> RelayClientConfig {
        RelayClientConfig {
            max_grpc_message_size: 9999999,
            relay_clients_keys: vec![1, 2],
            relay_registry_address: H160::from_str("0xaC8C6C7Ee7572975454E2f0b5c720f9E74989254")
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn test_retrieve_single_blob() {
        let eth_client = EthClient::new(SecretUrl::new(
            Url::from_str("https://ethereum-holesky-rpc.publicnode.com").unwrap(),
        ));
        let eth_client = Arc::new(Mutex::new(eth_client));

        let mut client = RelayClient::new(test_config(), eth_client).await.unwrap();

        let blob_key =
            BlobKey::from_hex("625eaa1a5695b260e0caab1c4d4ec97a5211455e8eee0e4fe9464fe8300cf1c4")
                .unwrap();
        let relay_key = 2;
        let result = client.get_blob(relay_key, blob_key).await;
        assert!(result.is_ok());

        let expected_blob_data = vec![1, 2, 3, 4, 5];
        let actual_blob_data = result.unwrap();
        assert_eq!(expected_blob_data, actual_blob_data);
    }
}
