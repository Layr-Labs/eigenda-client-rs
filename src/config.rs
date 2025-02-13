use secrecy::{ExposeSecret, Secret};
use std::str::FromStr;

use crate::errors::{ConfigError, EigenClientError};

/// Configuration for the EigenDA remote disperser client.
#[derive(Clone, Debug, PartialEq)]
pub struct EigenConfig {
    /// URL of the Disperser RPC server
    pub disperser_rpc: String,
    /// URL of the Ethereum RPC server
    pub eigenda_eth_rpc: String,
    /// Block height needed to reach in order to consider the blob finalized
    /// a value less or equal to 0 means that the disperser will not wait for finalization
    pub settlement_layer_confirmation_depth: u32,
    /// Address of the service manager contract
    pub eigenda_svc_manager_address: String,
    /// Wait for the blob to be finalized before returning the response
    pub wait_for_finalization: bool,
    /// Authenticated dispersal
    pub authenticated: bool,
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
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
            wait_for_finalization: false,
            authenticated: false,
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
