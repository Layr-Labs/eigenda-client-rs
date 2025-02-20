use ethereum_types::H160;
use secrecy::{ExposeSecret, Secret};
use std::str::FromStr;
use url::Url;

use crate::errors::{ConfigError, EigenClientError};

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
    pub eth_rpc_url: Option<SecretUrl>,
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
}

/// Contains the private key
#[derive(Clone, Debug, PartialEq)]
pub struct EigenSecrets {
    pub private_key: PrivateKey,
}

/// Secretly enclosed Private Key
#[derive(Debug, Clone)]
pub struct PrivateKey(pub Secret<String>);

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret().eq(other.0.expose_secret())
    }
}

impl FromStr for PrivateKey {
    type Err = EigenClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PrivateKey(s.parse().map_err(|_| ConfigError::PrivateKey)?))
    }
}
