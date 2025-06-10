use std::collections::HashMap;

use alloy::primitives::Address;
use tonic::transport::Channel;

use crate::{
    core::BlobKey,
    errors::RelayClientError,
    generated::relay::{
        relay_client::{self, RelayClient as RpcRelayClient},
        GetBlobRequest,
    },
    relay_registry::RelayRegistry,
    utils::SecretUrl,
};

pub type RelayKey = u32;

#[derive(Clone)]
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
    pub async fn new(config: RelayClientConfig) -> Result<Self, RelayClientError> {
        if config.max_grpc_message_size == 0 {
            return Err(RelayClientError::InvalidMaxGrpcMessageSize);
        }

        let relay_registry =
            RelayRegistry::new(config.relay_registry_address, config.eth_rpc_url.clone())?;

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
