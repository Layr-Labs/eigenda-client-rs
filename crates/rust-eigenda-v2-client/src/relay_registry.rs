use ethers::prelude::*;
use rust_eigenda_signers::signers::ethers::Signer as EthersSigner;
use std::sync::Arc;

use crate::{
    errors::{ConversionError, RelayClientError},
    generated::i_relay_registry::IRelayRegistry,
    relay_client::RelayKey,
    utils::SecretUrl,
};

/// Provides methods for interacting with the EigenDA RelayRegistry contract.
pub struct RelayRegistry<S> {
    relay_registry_contract:
        IRelayRegistry<SignerMiddleware<Provider<Http>, EthersSigner<S>>>,
}

impl<S> RelayRegistry<S> {
    /// Creates a new instance of RelayRegistry receiving the address of the contract and the ETH RPC url.
    pub fn new(
        address: H160,
        rpc_url: SecretUrl,
        signer: S,
    ) -> Result<Self, ConversionError>
    where
        EthersSigner<S>: Signer,
    {
        let url: String = rpc_url.try_into()?;

        let provider =
            Provider::<Http>::try_from(url).map_err(ConversionError::UrlParse)?;
        // ethers wallet hard code the chain id to 1
        let signer = EthersSigner::new(signer, 1);
        let client = SignerMiddleware::new(provider, signer);
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
    ) -> Result<String, RelayClientError>
    where
        EthersSigner<S>: Signer,
    {
        let url = format!(
            "https://{}",
            self.relay_registry_contract
                .relay_key_to_url(relay_key)
                .call()
                .await
                .map_err(|_| RelayClientError::RelayKeyToUrl(relay_key))?
        ); // TODO: forcing https schema on local stack will fail
        Ok(url)
    }
}
