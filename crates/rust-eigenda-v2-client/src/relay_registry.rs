use std::str::FromStr;
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
        let rpc_url: String = rpc_url.try_into()?;
        let rpc_url = Url::from_str(&rpc_url).unwrap();

        // Construct the ProviderBuilder
        let provider = ProviderBuilder::new().on_http(rpc_url.clone());
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
                .unwrap()
                ._0 // .map_err(|_| RelayClientError::RelayKeyToUrl(relay_key))?
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
