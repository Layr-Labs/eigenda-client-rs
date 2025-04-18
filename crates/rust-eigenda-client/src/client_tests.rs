/// EigenDA Client tests are ignored by default, because they require a remote dependency,
/// which may not always be available, causing tests to be flaky.
/// To run these tests, use the following command:
/// `cargo test client_tests -- --ignored`
#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::PrivateKeySigner;
    use crate::{
        client::BlobProvider,
        config::EigenConfig,
        errors::{CommunicationError, EigenClientError},
        test_eigenda_config, EigenClient,
    };
    use backon::{ConstantBuilder, Retryable};
    use serial_test::serial;

    use crate::blob_info::BlobInfo;

    impl<S> EigenClient<S> {
        pub(crate) async fn get_commitment(
            &self,
            blob_id: &str,
        ) -> Result<Option<BlobInfo>, EigenClientError> {
            self.client.get_commitment(blob_id).await
        }
    }

    const STATUS_QUERY_INTERVAL: Duration = Duration::from_millis(5);
    const MAX_RETRY_ATTEMPTS: usize = 1800000; // With this value we retry for a duration of 30 minutes

    async fn get_blob_info<S>(
        client: &EigenClient<S>,
        blob_id: &str,
    ) -> Result<BlobInfo, EigenClientError> {
        let blob_info = (|| async {
            let blob_info = client.get_commitment(blob_id).await?;
            if blob_info.is_none() {
                return Err(EigenClientError::Communication(
                    CommunicationError::FailedToGetBlob,
                ));
            }
            Ok(blob_info.unwrap())
        })
        .retry(
            &ConstantBuilder::default()
                .with_delay(STATUS_QUERY_INTERVAL)
                .with_max_times(MAX_RETRY_ATTEMPTS),
        )
        .when(|e| {
            matches!(
                e,
                EigenClientError::Communication(CommunicationError::FailedToGetBlob)
            )
        })
        .await?;

        Ok(blob_info)
    }

    #[derive(Debug, Clone)]
    struct MockBlobProvider;

    #[async_trait::async_trait]
    impl BlobProvider for MockBlobProvider {
        async fn get_blob(
            &self,
            _blob_id: &str,
        ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_non_auth_dispersal() {
        let config = test_eigenda_config();
        let private_key = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();

        let pk_signer = PrivateKeySigner::new(private_key);
        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();

        let blob_info = get_blob_info(&client, &result).await.unwrap();
        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_auth_dispersal() {
        let config = EigenConfig {
            authenticated: true,
            ..test_eigenda_config()
        };
        let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();

        let pk_signer = PrivateKeySigner::new(pk);
        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_wait_for_finalization() {
        let config = EigenConfig {
            wait_for_finalization: true,
            authenticated: true,
            ..test_eigenda_config()
        };
        let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();
        let pk_signer = PrivateKeySigner::new(pk);
        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_settlement_layer_confirmation_depth() {
        let config = EigenConfig {
            settlement_layer_confirmation_depth: 5,
            ..test_eigenda_config()
        };
        let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();
        let pk_signer = PrivateKeySigner::new(pk);
        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_auth_dispersal_settlement_layer_confirmation_depth() {
        let config = EigenConfig {
            settlement_layer_confirmation_depth: 5,
            authenticated: true,
            ..test_eigenda_config()
        };
        let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();
        let pk_signer = PrivateKeySigner::new(pk);
        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_custom_quorum_numbers() {
        let config = EigenConfig {
            custom_quorum_numbers: vec![2],
            ..test_eigenda_config()
        };
        let pk = "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6"
            .parse()
            .unwrap();
        let pk_signer = PrivateKeySigner::new(pk);

        let client = EigenClient::new(config.clone(), pk_signer, Arc::new(MockBlobProvider))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();

        let blob_info = get_blob_info(&client, &result).await.unwrap();
        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert!(actual_inclusion_data
            .windows(expected_inclusion_data.len())
            .any(|window| window == expected_inclusion_data)); // Checks that the verification proof is included in the inclusion data
        let retrieved_data = client
            .get_blob(
                blob_info.blob_verification_proof.blob_index,
                blob_info
                    .blob_verification_proof
                    .batch_medatada
                    .batch_header_hash,
            )
            .await
            .unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }
}
