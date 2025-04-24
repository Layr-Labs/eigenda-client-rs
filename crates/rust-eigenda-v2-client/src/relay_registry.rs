use ethers::prelude::*;
use secrecy::ExposeSecret;
use std::sync::Arc;

use crate::{
    contracts_bindings::IRelayRegistry::{self},
    errors::{ConversionError, RelayClientError},
    relay_client::RelayKey,
    utils::{PrivateKey, SecretUrl},
};

/// RelayRegistry is a struct that provides methods for interacting with the EigenDA RelayRegistry contract.
pub struct RelayRegistry {
    relay_registry_contract: IRelayRegistry<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl RelayRegistry {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(
        address: H160,
        rpc_url: SecretUrl,
        private_key: PrivateKey,
    ) -> Result<Self, ConversionError> {
        let url: String = rpc_url.try_into()?;

        let provider = Provider::<Http>::try_from(url).unwrap();
        let wallet: LocalWallet = private_key.0.expose_secret().parse().unwrap();
        let client = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(client);
        let relay_registry_contract = IRelayRegistry::new(address, client);
        Ok(RelayRegistry {
            relay_registry_contract,
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
                .relay_key_to_url(relay_key)
                .call()
                .await
                .unwrap()
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
