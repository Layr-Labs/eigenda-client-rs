pub mod accountant;
pub mod cert_verifier;
pub mod commitment_utils;
pub mod core;
pub mod disperser_client;
pub mod errors;
pub mod payload_disperser;
pub mod relay_client;
pub mod relay_payload_retriever;
pub mod relay_registry;
pub mod utils;
// So users can use the client without having to depend on the signers crate as well.
pub use rust_eigenda_signers;

#[allow(clippy::all)]
pub(crate) mod generated {
    pub(crate) mod common {
        include!("generated/common.rs");

        pub(crate) mod v2 {
            include!("generated/common.v2.rs");
        }
    }

    pub(crate) mod disperser {
        pub(crate) mod v2 {
            include!("generated/disperser.v2.rs");
        }
    }

    pub(crate) mod encoder {
        pub(crate) mod v2 {
            include!("generated/encoder.v2.rs");
        }
    }

    pub(crate) mod retriever {
        pub(crate) mod v2 {
            include!("generated/retriever.v2.rs");
        }
    }

    pub(crate) mod validator {
        include!("generated/validator.rs");
    }

    pub(crate) mod relay {
        include!("generated/relay.rs");
    }

    pub(crate) mod contract_bindings {
        alloy::sol! {
            #[sol(rpc)]
            IEigenDACertVerifier, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDACertVerifier.json"),
        }

        alloy::sol! {
            #[sol(rpc)]
            IEigenDACertVerifierBase, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDACertVerifierBase.json"),
        }

        alloy::sol! {
            #[sol(rpc)]
            IRelayRegistry, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDARelayRegistry.json"),
        }

        alloy::sol! {
            #[sol(rpc)]
            IEigenDACertVerifierRouter, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDACertVerifierRouter.json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use dotenv::dotenv;
    use rust_eigenda_v2_common::{EigenDACert, Payload, PayloadForm};
    use std::{env, str::FromStr, time::Duration};
    use url::Url;

    use crate::{
        core::BlobKey,
        payload_disperser::{PayloadDisperser, PayloadDisperserConfig},
        relay_client::RelayClient,
        relay_payload_retriever::{RelayPayloadRetriever, RelayPayloadRetrieverConfig, SRSConfig},
        utils::SecretUrl,
    };

    use rust_eigenda_signers::signers::private_key::Signer as PrivateKeySigner;

    const TEST_BLOB_FINALIZATION_TIMEOUT: u64 = 180;
    const TEST_PAYLOAD_DATA: &[u8] = &[1, 2, 3, 4, 5];
    pub const HOLESKY_ETH_RPC_URL: &str = "https://ethereum-holesky-rpc.publicnode.com";
    pub const HOLESKY_DISPERSER_RPC_URL: &str = "https://disperser-testnet-holesky.eigenda.xyz";
    pub const HOLESKY_RELAY_REGISTRY_ADDRESS: &str = "0xac8c6c7ee7572975454e2f0b5c720f9e74989254";
    pub const CERT_VERIFIER_ROUTER_ADDRESS: &str = "0xdd735affe77a5ed5b21ed47219f95ed841f8ffbd";
    pub const REGISTRY_COORDINATOR_ADDRESS: &str = "0x53012C69A189cfA2D9d29eb6F19B32e0A2EA3490";
    pub const OPERATOR_STATE_RETRIEVER_ADDRESS: &str = "0xB4baAfee917fb4449f5ec64804217bccE9f46C67";

    pub fn get_test_private_key_signer() -> PrivateKeySigner {
        dotenv().ok();
        let private_key = env::var("SIGNER_PRIVATE_KEY")
            .expect("SIGNER_PRIVATE_KEY must be set")
            .parse()
            .expect("valid secret key");
        PrivateKeySigner::new(private_key)
    }

    fn get_test_payload_disperser_config() -> PayloadDisperserConfig {
        PayloadDisperserConfig {
            polynomial_form: PayloadForm::Coeff,
            blob_version: 0,
            cert_verifier_router_address: CERT_VERIFIER_ROUTER_ADDRESS.to_string(),
            eth_rpc_url: get_test_holesky_rpc_url(),
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            use_secure_grpc_flag: false,
            registry_coordinator_addr: REGISTRY_COORDINATOR_ADDRESS.to_string(),
            operator_state_retriever_addr: OPERATOR_STATE_RETRIEVER_ADDRESS.to_string(),
        }
    }

    pub fn get_relay_payload_retriever_test_config() -> RelayPayloadRetrieverConfig {
        RelayPayloadRetrieverConfig {
            payload_form: PayloadForm::Coeff,
            retrieval_timeout_secs: Duration::from_secs(10),
        }
    }

    pub fn get_srs_test_config() -> SRSConfig {
        SRSConfig {
            source_path: "../../resources/g1.point".to_string(),
            order: 9999999,
            points_to_load: 9999999,
        }
    }

    pub fn get_relay_client_test_config() -> crate::relay_client::RelayClientConfig {
        crate::relay_client::RelayClientConfig {
            max_grpc_message_size: 9999999,
            relay_clients_keys: vec![0, 1, 2],
            relay_registry_address: Address::from_str(HOLESKY_RELAY_REGISTRY_ADDRESS).unwrap(),
            eth_rpc_url: get_test_holesky_rpc_url(),
        }
    }

    pub fn get_test_holesky_rpc_url() -> SecretUrl {
        SecretUrl::new(Url::from_str(HOLESKY_ETH_RPC_URL).unwrap())
    }

    pub async fn get_test_relay_client() -> RelayClient {
        RelayClient::new(get_relay_client_test_config())
            .await
            .unwrap()
    }

    async fn wait_for_blob_finalization_and_verification(
        payload_disperser: &PayloadDisperser,
        blob_key: &BlobKey,
    ) -> EigenDACert {
        let timeout = tokio::time::Duration::from_secs(TEST_BLOB_FINALIZATION_TIMEOUT);

        let start_time = tokio::time::Instant::now();
        loop {
            let cert = payload_disperser.get_cert(blob_key).await.unwrap();
            match cert {
                Some(cert) => {
                    return cert;
                }
                None => {
                    let elapsed = start_time.elapsed();
                    assert!(elapsed < timeout, "Timeout waiting for inclusion data");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_disperse_and_retrieve_blob() {
        let payload_data = TEST_PAYLOAD_DATA.to_vec();
        let payload = Payload::new(payload_data.clone());

        // First we disperse a blob using a Payload Disperser
        let payload_disperser = PayloadDisperser::new(
            get_test_payload_disperser_config(),
            get_test_private_key_signer(),
        )
        .await
        .unwrap();
        let blob_key = payload_disperser.send_payload(payload).await.unwrap();

        // Then we wait for the blob to be finalized and verified
        let eigenda_cert =
            wait_for_blob_finalization_and_verification(&payload_disperser, &blob_key).await;

        // Finally we retrieve the blob using a Relay Payload Retriever
        let relay_config = get_relay_payload_retriever_test_config();
        let srs_config = get_srs_test_config();
        let relay_client = get_test_relay_client().await;
        let mut client =
            RelayPayloadRetriever::new(relay_config, srs_config, relay_client).unwrap();

        let result = client.get_payload(eigenda_cert).await;
        let retrieved_payload = result.unwrap().serialize();
        assert_eq!(payload_data, retrieved_payload);
    }
}
