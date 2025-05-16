# rust-eigenda-v2-client

Rust client for interacting with EigenDA V2.

[More about V2 implementation](https://docs.eigenda.xyz/releases/blazar).

## Sample usage

### Dispersal and Retrieval

This example uses the Holesky ETH chain.

```rs
use std::str::FromStr;
use std::sync::LazyLock;

use ethereum_types::H160;
use rust_eigenda_signers::{SecretKey, signers::private_key::Signer};
use rust_eigenda_v2_client::{
    payload_disperser::{PayloadDisperser, PayloadDisperserConfig},
    relay_client::{RelayClient, RelayClientConfig},
    relay_payload_retriever::{RelayPayloadRetriever, RelayPayloadRetrieverConfig, SRSConfig},
    utils::SecretUrl,
};
use rust_eigenda_v2_common::{Payload, PayloadForm};

const CERT_VERIFIER_ADDRESS: H160 = H160([
    0xfe, 0x52, 0xfe, 0x19, 0x40, 0x85, 0x8d, 0xcb, 0x6e, 0x12, 0x15, 0x3e, 0x21, 0x04, 0xad, 0x0f,
    0xdf, 0xbe, 0x11, 0x62,
]);
const HOLESKY_RELAY_REGISTRY_ADDRESS: H160 = H160([
    0xac, 0x8c, 0x6c, 0x7e, 0xe7, 0x57, 0x29, 0x75, 0x45, 0x4e, 0x2f, 0x0b, 0x5c, 0x72, 0x0f, 0x9e,
    0x74, 0x98, 0x92, 0x54,
]);
const HOLESKY_ETH_RPC_URL: &str = "https://ethereum-holesky-rpc.publicnode.com";
const HOLESKY_DISPERSER_RPC_URL: &str = "https://disperser-testnet-holesky.eigenda.xyz";
// This private key won't work, you need to set up your own with a set
const ACCOUNTANT_PRIVATE_KEY: &str = "<YOUR_PRIVATE_KEY>";
// You need to have a g1 point downloaded locally for this example
const G1_POINT_FILE_PATH: &str = "../resources/g1.point";

static PAYLOAD_CONFIG: LazyLock<PayloadDisperserConfig> =
    LazyLock::new(|| PayloadDisperserConfig {
        polynomial_form: PayloadForm::Coeff,
        blob_version: 0,
        cert_verifier_address: CERT_VERIFIER_ADDRESS,
        eth_rpc_url: SecretUrl::new(url::Url::from_str(HOLESKY_ETH_RPC_URL).unwrap()),
        disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
        use_secure_grpc_flag: false,
    });

static RELAY_CONFIG: LazyLock<RelayPayloadRetrieverConfig> =
    LazyLock::new(|| RelayPayloadRetrieverConfig {
        payload_form: PayloadForm::Coeff,
        retrieval_timeout_secs: std::time::Duration::from_secs(10),
    });

static SRS_CONFIG: LazyLock<SRSConfig> = LazyLock::new(|| SRSConfig {
    source_path: G1_POINT_FILE_PATH.to_string(),
    order: 9999999,
    points_to_load: 9999999,
});

static RELAY_CLIENT_CONFIG: LazyLock<RelayClientConfig> = LazyLock::new(|| RelayClientConfig {
    max_grpc_message_size: 9999999,
    relay_clients_keys: vec![0, 1, 2],
    relay_registry_address: HOLESKY_RELAY_REGISTRY_ADDRESS,
    eth_rpc_url: SecretUrl::new(url::Url::from_str(HOLESKY_ETH_RPC_URL).unwrap()),
});

#[tokio::main]
async fn main() {
    let data = vec![42];

    // Disperser
    let private_key: SecretKey = ACCOUNTANT_PRIVATE_KEY.parse().unwrap();
    let signer = Signer::new(private_key);
    let payload_disperser = PayloadDisperser::new(PAYLOAD_CONFIG.clone(), signer)
        .await
        .unwrap();
    let payload = Payload::new(data.clone());
    let blob_key = payload_disperser.send_payload(payload).await.unwrap();

    // sleep so we let the dispersal process complete
    tokio::time::sleep(tokio::time::Duration::from_secs(60 * 5)).await;

    let cert = payload_disperser
        .get_cert(&blob_key)
        .await
        .unwrap();
    let eigenda_cert = cert.unwrap();

    // Retriever
    let signer = Signer::new(private_key);
    let relay_client = RelayClient::new(RELAY_CLIENT_CONFIG.clone(), signer)
        .await
        .unwrap();

    let mut retrieval_client =
        RelayPayloadRetriever::new(RELAY_CONFIG.clone(), SRS_CONFIG.clone(), relay_client).unwrap();

    let payload = retrieval_client.get_payload(eigenda_cert).await.unwrap();
    let result = payload.serialize();

    assert_eq!(data, result);
}

```

## Use

```toml
[dependencies]
rust-eigenda-v2-client = "0.1.1"
```
