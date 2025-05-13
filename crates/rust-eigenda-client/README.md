# rust-eigenda-client

Rust client for interacting with EigenDA (V1 implementation).

[More about V1 Client](https://docs.eigenda.xyz/api/v1/disperser/overview).

## Sample client instantiation

This example uses the Holesky ETH chain.

```rs
use std::{str::FromStr, sync::Arc};

use rust_eigenda_client::{
    EigenClient,
    client::BlobProvider,
    config::{EigenConfig, SecretUrl, SrsPointsSource},
};
use rust_eigenda_signers::signers::private_key::Signer as PrivateKeySigner;

// The `EigenClient` needs to be set with a blob provider
// used for verification
#[derive(Debug, Clone)]
struct SampleBlobProvider;

// In this example we don't need to verify blobs,
// so the struct we defined does not have any
// retrieval logic inside
#[async_trait::async_trait]
impl BlobProvider for SampleBlobProvider {
    async fn get_blob(
        &self,
        _blob_id: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        // Returning `None` means that the blob will not be compared againts the result of the blob provider
        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    let config = EigenConfig {
        disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
        settlement_layer_confirmation_depth: 0,
        eth_rpc_url: SecretUrl::new(url::Url::from_str("https://ethereum-holesky-rpc.publicnode.com").unwrap()),
        eigenda_svc_manager_address: ethereum_types::H160(hex_literal::hex!("d4a7e1bd8015057293f0d0a557088c286942e84b")),
        wait_for_finalization: false,
        authenticated: false,
        srs_points_source: SrsPointsSource::Url((
            "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        )),
        custom_quorum_numbers: vec![],
    };

    let pk = "<YOUR_PRIVATE_KEY>".parse().unwrap();
    let pk_signer = PrivateKeySigner::new(pk);
    let blob_provider = Arc::new(SampleBlobProvider);
    let client = EigenClient::new(config.clone(), pk_signer, blob_provider)
        .await
        .unwrap();

    let data = vec![42];
    let blob_id = client.dispatch_blob(data.clone()).await.unwrap();

    // sleep so we let the dispersal process complete
    tokio::time::sleep(tokio::time::Duration::from_secs(60 * 5)).await;

    let blob_info = client.get_blob_info(&blob_id).await.unwrap().unwrap();
    let blob = client
        .get_blob(
            blob_info.blob_verification_proof.blob_index,
            blob_info
                .blob_verification_proof
                .batch_medatada
                .batch_header_hash,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(data, blob);
}
```

## Use

```toml
[dependencies]
rust-eigenda-client = "0.1.5"
```
