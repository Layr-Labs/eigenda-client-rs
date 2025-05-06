# rust-eigenda-client

Rust client for interacting with EigenDA (V1 implementation).

[More about V1 Client](https://docs.eigenda.xyz/api/v1/disperser/overview).

## Sample client instantiation

This example uses the holesky ETH chain.

```rs
use rust_eigenda_signers::signers::private_key::Signer as PrivateKeySigner;
use rust_eigenda_client::{EigenClient, EigenConfig, config::{SecretUrl, SrsPointsSource}};

#[derive(Debug, Clone)]
struct SampleBlobProvider;

#[async_trait::async_trait]
impl BlobProvider for SampleBlobProvider {
    async fn get_blob(
        &self,
        _blob_id: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        // Implement your blob retrieval logic here
        Ok(None)
    }
}

#[tokio::main]
async fn main(){
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

    let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6".parse().unwrap();
    let pk_signer = PrivateKeySigner::new(pk);
    let blob_provider = Arc::new(SampleBlobProvider);
    let client = EigenClient::new(config.clone(), pk_signer, blob_provider).await.unwrap();


}
```

## Use

```toml
[dependencies]
rust-eigenda-client = "0.1.5"
```
