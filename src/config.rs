use ethereum_types::H160;
use secrecy::{ExposeSecret, Secret};
use std::str::FromStr;
use url::Url;

use crate::errors::{ConfigError, EigenClientError};

/// Default address of the EigenDA service manager contract deployed on Holesky.
const EIGENDA_SVC_MANAGER_HOLESKY_ADDRESS: H160 = H160(hex_literal::hex!(
    "d4a7e1bd8015057293f0d0a557088c286942e84b"
));

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
    /// Optional path to downloaded points directory
    pub srs_points_dir: Option<String>,
    /// Url to the file containing the G1 point used for KZG
    pub g1_url: String,
    /// Url to the file containing the G2 point used for KZG
    pub g2_url: String,
}

impl Default for EigenConfig {
    fn default() -> Self {
        Self {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            settlement_layer_confirmation_depth: 0,
            eth_rpc_url: Some(SecretUrl::new(Url::from_str("https://ethereum-holesky-rpc.publicnode.com").unwrap())), // Safe to unwrap, never fails
            eigenda_svc_manager_address: EIGENDA_SVC_MANAGER_HOLESKY_ADDRESS,
            wait_for_finalization: false,
            authenticated: false,
            srs_points_dir: None,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        }
    }
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
