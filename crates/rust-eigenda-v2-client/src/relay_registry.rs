use std::str::FromStr;

use alloy::{network::Ethereum, providers::RootProvider};

use crate::{
    contracts_bindings::IRelayRegistry::{self},
    errors::RelayClientError,
    relay_client::RelayKey,
};

pub type RelayRegistryContract = IRelayRegistry::IRelayRegistryInstance<RootProvider<Ethereum>>;

/// RelayRegistry is a struct that provides methods for interacting with the EigenDA RelayRegistry contract.
pub struct RelayRegistry {
    relay_registry_contract: RelayRegistryContract,
}

impl RelayRegistry {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(address: String, rpc_url: String) -> Self {
        let url = alloy::transports::http::reqwest::Url::from_str(&rpc_url).unwrap();
        let provider: RootProvider<Ethereum> = RootProvider::new_http(url);

        println!("Address: {:?}", address);
        let relay_registry_address = alloy::primitives::Address::from_str(&address).unwrap();
        let relay_registry_contract: IRelayRegistry::IRelayRegistryInstance<RootProvider> =
            IRelayRegistry::new(relay_registry_address, provider);
        RelayRegistry {
            relay_registry_contract,
        }
    }

    /// Calls the getNonSignerStakesAndSignature view function on the EigenDACertVerifier
    /// contract, and returns the resulting NonSignerStakesAndSignature object.
    pub async fn get_url_from_relay_key(
        &self,
        relay_key: RelayKey,
    ) -> Result<String, RelayClientError> {
        let url = format!(
            "https://{}",
            self.relay_registry_contract
                .relayKeyToUrl(relay_key)
                .call()
                .await?
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
