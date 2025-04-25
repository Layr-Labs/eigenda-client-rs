use std::collections::HashMap;

use ethabi::Address;
use tonic::transport::Channel;

use crate::{
    core::BlobKey,
    errors::RelayClientError,
    generated::relay::{
        relay_client::{self, RelayClient as RpcRelayClient},
        GetBlobRequest,
    },
    relay_registry::RelayRegistry,
    utils::{PrivateKey, SecretUrl},
};

pub type RelayKey = u32;

pub struct RelayClientConfig {
    pub max_grpc_message_size: usize,
    pub relay_clients_keys: Vec<u32>,
    pub relay_registry_address: Address,
    pub eth_rpc_url: SecretUrl,
}

/// [`RelayClient`] is a client for the entire relay subsystem.
///
/// It is a wrapper around a collection of GRPC clients, which are used to interact with individual relays.
/// This struct is a low level implementation and should not be used directly,
/// use a high level abstraction to interact with it ([`RelayPayloadRetriever`]).
pub struct RelayClient {
    rpc_clients: HashMap<RelayKey, RpcRelayClient<tonic::transport::Channel>>,
}

impl RelayClient {
    pub async fn new(
        config: RelayClientConfig,
        private_key: PrivateKey,
    ) -> Result<Self, RelayClientError> {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let relay_registry = RelayRegistry::new(
            config.relay_registry_address,
            config.eth_rpc_url.clone(),
            private_key,
        )?;

        let mut rpc_clients = HashMap::new();
        for relay_key in config.relay_clients_keys.iter() {
            let url = relay_registry.get_url_from_relay_key(*relay_key).await?;
            let endpoint =
                Channel::from_shared(url.clone()).map_err(|_| RelayClientError::InvalidURI(url))?;
            let channel = endpoint.connect().await?;
            let rpc_client = relay_client::RelayClient::new(channel);
            rpc_clients.insert(*relay_key, rpc_client);
        }

        Ok(Self { rpc_clients })
    }

    /// Retrieves a blob from a relay.
    pub async fn get_blob(
        &mut self,
        relay_key: RelayKey,
        blob_key: &BlobKey,
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
    use super::*;
    use crate::{
        relay_client::RelayClient,
        tests::{get_test_holesky_rpc_url, get_test_private_key, HOLESKY_RELAY_REGISTRY_ADDRESS},
    };

    fn get_test_relay_client_config() -> RelayClientConfig {
        RelayClientConfig {
            max_grpc_message_size: 9999999,
            relay_clients_keys: vec![0, 1, 2],
            relay_registry_address: HOLESKY_RELAY_REGISTRY_ADDRESS,
            eth_rpc_url: get_test_holesky_rpc_url(),
        }
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_retrieve_single_blob() {
        let mut client = RelayClient::new(get_test_relay_client_config(), get_test_private_key())
            .await
            .unwrap();

        let blob_key =
            BlobKey::from_hex("625eaa1a5695b260e0caab1c4d4ec97a5211455e8eee0e4fe9464fe8300cf1c4")
                .unwrap();
        let relay_key = 2;
        let result = client.get_blob(relay_key, &blob_key).await;
        assert!(result.is_ok());

        let expected_blob_data = vec![1, 2, 3, 4, 5];
        let actual_blob_data = result.unwrap();
        assert_eq!(expected_blob_data, actual_blob_data);
    }
}
