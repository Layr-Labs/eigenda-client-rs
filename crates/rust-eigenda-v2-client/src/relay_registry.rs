use std::str::FromStr;
use url::Url;

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::Address,
    providers::{
        fillers::{FillProvider, JoinFill, WalletFiller},
        Identity, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
    transports::http::Http,
};

use crate::{
    contracts_bindings::IRelayRegistry::IRelayRegistryInstance,
    errors::{ConversionError, RelayClientError},
    relay_client::RelayKey,
    utils::SecretUrl,
};

/// Provides methods for interacting with the EigenDA RelayRegistry contract.
pub struct RelayRegistry {
    relay_registry_contract: IRelayRegistryInstance<
        Http<reqwest::Client>,
        FillProvider<
            JoinFill<Identity, WalletFiller<EthereumWallet>>,
            RootProvider<Http<reqwest::Client>>,
            Http<reqwest::Client>,
            Ethereum,
        >,
    >,
}

impl RelayRegistry {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(
        address: Address,
        rpc_url: SecretUrl,
        signer: PrivateKeySigner,
    ) -> Result<Self, ConversionError> {
        let rpc_url: String = rpc_url.try_into()?;
        let rpc_url = Url::from_str(&rpc_url).unwrap();

        // Construct the ProviderBuilder
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_http(rpc_url.clone());
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
