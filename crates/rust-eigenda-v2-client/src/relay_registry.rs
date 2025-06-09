use url::Url;

use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, RootProvider},
    transports::http::Http,
};

use crate::{
    errors::{ConversionError, RelayClientError},
    generated::contract_bindings::IRelayRegistry::IRelayRegistryInstance,
    relay_client::RelayKey,
    utils::SecretUrl,
};

/// Provides methods for interacting with the EigenDA RelayRegistry contract.
pub struct RelayRegistry {
    relay_registry_contract:
        IRelayRegistryInstance<Http<reqwest::Client>, RootProvider<Http<reqwest::Client>>>,
}

impl RelayRegistry {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(address: Address, rpc_url: SecretUrl) -> Result<Self, ConversionError> {
        // Construct the ProviderBuilder
        let rpc_url: Url = rpc_url.into();
        let provider = ProviderBuilder::new().on_http(rpc_url);
        let contract = IRelayRegistryInstance::new(address, provider);
        Ok(RelayRegistry {
            relay_registry_contract: contract,
        })
    }

    /// Calls the relayKeyToUrl view function on the EigenDARelayRegistry
    /// contract, and returns the resulting url as a String.
    pub async fn get_url_from_relay_key(
        &self,
        relay_key: RelayKey,
    ) -> Result<String, RelayClientError> {
        let url = format!(
            "https://{}",
            self.relay_registry_contract
                .relayKeyToUrl(relay_key)
                .call()
                .await
                .map_err(|_| RelayClientError::RelayKeyToUrl(relay_key))?
                ._0
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
