use ethereum_types::H160;
use secrecy::{ExposeSecret, Secret};
use url::Url;

use crate::errors::ConfigError;

#[derive(Debug, Clone)]
/// A URL stored securely using the `Secret` type from the secrecy crate
pub struct SecretUrl {
    // We keep the URL as a String because Secret<T> enforces T: DefaultIsZeroes
    // which is not the case for the type Url
    inner: Secret<String>,
}

impl SecretUrl {
    /// Create a new `SecretUrl` from a `Url`
    pub fn new(url: Url) -> Self {
        Self {
            inner: Secret::new(url.to_string()),
        }
    }
}

impl From<SecretUrl> for Url {
    fn from(secret_url: SecretUrl) -> Self {
        Url::parse(secret_url.inner.expose_secret()).unwrap() // Safe to unwrap, as the `new` fn ensures the URL is valid
    }
}

impl PartialEq for SecretUrl {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret().eq(other.inner.expose_secret())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SrsPointsSource {
    /// Path to the SRS points file, it should have both g1 and power of g2 points
    Path(String),
    /// Urls to g1 and power of g2 points
    Url((String, String)),
}

/// Configuration for the EigenDA remote disperser client.
#[derive(Clone, Debug, PartialEq)]
pub struct EigenConfig {
    /// URL of the Disperser RPC server
    pub disperser_rpc: String,
    /// URL of the Ethereum RPC server
    pub eth_rpc_url: SecretUrl,
    /// Block height needed to reach in order to consider the blob finalized
    /// a value less or equal to 0 means that the disperser will not wait for finalization
    pub settlement_layer_confirmation_depth: u32,
    /// Address of the service manager contract
    pub eigenda_svc_manager_address: H160,
    /// Wait for the blob to be finalized before returning the response
    pub wait_for_finalization: bool,
    /// Authenticated dispersal
    pub authenticated: bool,
    /// Points source
    pub srs_points_source: SrsPointsSource,
    /// Custom quorum numbers
    pub custom_quorum_numbers: Vec<u8>,
}

impl EigenConfig {
    /// Create a new EigenConfig
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        disperser_rpc: String,
        eth_rpc_url: SecretUrl,
        settlement_layer_confirmation_depth: u32,
        eigenda_svc_manager_address: H160,
        wait_for_finalization: bool,
        authenticated: bool,
        srs_points_source: SrsPointsSource,
        custom_quorum_numbers: Vec<u8>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            disperser_rpc,
            eth_rpc_url,
            settlement_layer_confirmation_depth,
            eigenda_svc_manager_address,
            wait_for_finalization,
            authenticated,
            srs_points_source,
            custom_quorum_numbers,
        })
    }
}
