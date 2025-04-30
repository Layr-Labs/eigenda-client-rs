pub(crate) mod blob_info;
pub mod client;
pub(crate) mod client_tests;
pub mod config;
pub mod errors;
pub(crate) mod eth_client;
pub(crate) mod sdk;
pub(crate) mod verifier;
pub(crate) mod verifier_tests;

pub use self::client::EigenClient;
// So users can use the client without having to depend on the signers crate as well.
pub use rust_eigenda_signers;

#[allow(clippy::all)]
pub(crate) mod generated {
    pub(crate) mod disperser {
        include!("generated/disperser.rs");
    }
    pub(crate) mod common {
        include!("generated/common.rs");
    }
}

#[cfg(test)]
pub fn test_eigenda_config() -> crate::config::EigenConfig {
    use std::str::FromStr;

    crate::config::EigenConfig {
                disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
                settlement_layer_confirmation_depth: 0,
                eth_rpc_url: crate::config::SecretUrl::new(url::Url::from_str("https://ethereum-holesky-rpc.publicnode.com").unwrap()), // Safe to unwrap, never fails
                eigenda_svc_manager_address: ethereum_types::H160(hex_literal::hex!(
                    "d4a7e1bd8015057293f0d0a557088c286942e84b"
                )),
                wait_for_finalization: false,
                authenticated: false,
                srs_points_source: crate::config::SrsPointsSource::Url((
                    "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
                    "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
                )),
                custom_quorum_numbers: vec![],
        }
}
