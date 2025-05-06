# rust-eigenda-v2-client

Rust client for interacting with EigenDA V2.

[More about V2 implementation](https://docs.eigenda.xyz/releases/blazar).

## Sample usage

### Dispersal and Retrieval

This example uses the holesky ETH chain.

```rs
use rust_eigenda_v2_client::{relay_payload_retriever::{RelayPayloadRetriever, RelayPayloadRetrieverConfig, SRSConfig}, relay_client::RelayPayloadRetrieverConfig, SecretUrl};
use rust_eigenda_v2_common::PayloadForm;

pub const CERT_VERIFIER_ADDRESS: H160 = H160([
    0xfe, 0x52, 0xfe, 0x19, 0x40, 0x85, 0x8d, 0xcb, 0x6e, 0x12, 0x15, 0x3e, 0x21, 0x04, 0xad,
    0x0f, 0xdf, 0xbe, 0x11, 0x62,
]);
pub const HOLESKY_RELAY_REGISTRY_ADDRESS: H160 = H160([
    0xac, 0x8c, 0x6c, 0x7e, 0xe7, 0x57, 0x29, 0x75, 0x45, 0x4e, 0x2f, 0x0b, 0x5c, 0x72, 0x0f,
    0x9e, 0x74, 0x98, 0x92, 0x54,
]);
pub const HOLESKY_ETH_RPC_URL: &str = "https://ethereum-holesky-rpc.publicnode.com";
pub const HOLESKY_DISPERSER_RPC_URL: &str = "https://disperser-testnet-holesky.eigenda.xyz";

#[tokio::main]
async fn main() {
    let data = vec![42];
    let eigenda_cert = disperse(data).await;
    let payload = retrieve(eigenda_cert).await;
    assert_eq!(data, payload);
}

async fn disperse(data: Vec<u8>) -> EigenDACert {
    let payload_config = PayloadDisperserConfig {
        polynomial_form: PayloadForm::Coeff,
        blob_version: 0,
        cert_verifier_address: CERT_VERIFIER_ADDRESS,
        eth_rpc_url: SecretUrl::new(url::Url::from_str(HOLESKY_ETH_RPC_URL).unwrap()),,
        disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
        use_secure_grpc_flag: false,
    };

    let payload_disperser =
        PayloadDisperser::new(payload_config, get_test_private_key_signer())
            .await
            .unwrap();

    let payload = Payload::new(vec![1, 2, 3, 4, 5]);
    let blob_key = payload_disperser.send_payload(payload).await.unwrap();

    // sleep so we let the dispersal process complete
    tokio::time::sleep(tokio::time::Duration::from_secs(180)).await;

    let inclusion_data = payload_disperser.get_inclusion_data(&blob_key).await.unwrap();
    let eigenda_cert = inclusion_data.unwrap();
    eigenda_cert
}

async fn retrieve(eigenda_cert: EigenDACert) -> Vec<u8> {
    let relay_config = RelayPayloadRetrieverConfig {
        payload_form: PayloadForm::Coeff,
        retrieval_timeout_secs: std::time::Duration::from_secs(10),
    };
    let srs_config = SRSConfig {
        source_path: "../resources/g1.point".to_string(),
        order: 9999999,
        points_to_load: 9999999,
    };
    let relay_client = RelayClient::new(
        RelayClientConfig {
            max_grpc_message_size: 9999999,
            relay_clients_keys: vec![0, 1, 2],
            relay_registry_address: HOLESKY_RELAY_REGISTRY_ADDRESS,
            eth_rpc_url: SecretUrl::new(url::Url::from_str(HOLESKY_ETH_RPC_URL).unwrap()),
        },
        PrivateKeySigner::new("d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"),
    ).await.unwrap();
    let mut retrieval_client =
        RelayPayloadRetriever::new(relay_config, srs_config, relay_client).unwrap();
    let payload = retrieval_client.get_payload(eigenda_cert).await.unwrap();
    return payload
}
```

## Use

```toml
[dependencies]
rust-eigenda-v2-client = "0.1.1"
```
