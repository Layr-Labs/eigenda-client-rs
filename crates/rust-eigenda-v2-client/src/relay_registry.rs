use url::Url;

use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, RootProvider},
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
        IRelayRegistryInstance<RootProvider<alloy::network::Ethereum>, alloy::network::Ethereum>,
}

impl RelayRegistry {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(address: Address, rpc_url: SecretUrl) -> Result<Self, ConversionError> {
        // Construct the ProviderBuilder
        let rpc_url: Url = rpc_url.into();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_http(rpc_url);
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
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
