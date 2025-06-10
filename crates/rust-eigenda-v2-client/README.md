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
rust-eigenda-v2-client = "0.1"
```


## Contract Bindings

In order to generate the contract bindings, use the following:

Create a new rust project

```bash
mkdir contract-bindings
cd contract-bindings
cargo init
```

Add eigenda as a submodule

```bash
git submodule add https://github.com/layr-labs/eigenda.git
```

Replace `Cargo.toml` with

```toml
[package]
name = "eigenda-contract-bindings"
version = "0.1.0"
edition = "2021"

[dependencies]
alloy = { version = "0.6", features = ["sol-types", "json"] }
```

Create `build.rs`

```rs
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;


// This build.rs script compiles the eigenda contracts (in the eigenda/contracts submodule dir)
// and copies the artifacts to the src/generated/abis directory in this crate, such that they
// can be used in the contract bindings crate.
// The goal is for these abis to be distributed with this eigenda-contract-bindings crate.
fn main() {
    // Path to eigenda contracts
    let input_contracts_dir =
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/eigenda/contracts"));
    // Check if the directory exists
    if !input_contracts_dir.exists() {
        panic!(
            "Contracts directory not found at: {:?}",
            input_contracts_dir
        );
    }

    // Create destination directory for contract artifacts
    let output_abis_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abis"));
    fs::create_dir_all(&output_abis_dir).expect("Failed to create contracts directory");

    // Navigate to the contracts directory and run forge build
    let status = Command::new("forge")
        .current_dir(&input_contracts_dir)
        .arg("build")
        .arg("--force") // Force recompilation
        .status()
        .expect("Failed to execute forge build");
    if !status.success() {
        panic!("forge build failed with status: {}", status);
    }

    // List of contract artifacts we need
    let artifacts = [
        "IEigenDACertVerifier.sol/IEigenDACertVerifier.json",
        "IEigenDACertVerifierBase.sol/IEigenDACertVerifierBase.json",
        "IEigenDARelayRegistry.sol/IEigenDARelayRegistry.json",
        // Add more artifacts as needed
    ];

    // Copy artifacts to our abis directory
    let forge_out_dir = input_contracts_dir.join("out");
    for artifact in artifacts.iter() {
        let src_path = forge_out_dir.join(artifact);
        if !src_path.exists() {
            panic!("Artifact not found: {:?}", src_path);
        }

        let json_file_name = Path::new(artifact).file_name().unwrap();
        let dst_path = output_abis_dir.join(json_file_name);

        fs::copy(&src_path, &dst_path)
            .unwrap_or_else(|_| panic!("Failed to copy artifact: {:?}", src_path));

        println!("Copied artifact: {:?}", json_file_name);
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=eigenda/contracts/src");
}

```

Run

```bash
cd eigenda/contracts
yarn install
forge install
yarn run build
cd ../..
cargo build
```
