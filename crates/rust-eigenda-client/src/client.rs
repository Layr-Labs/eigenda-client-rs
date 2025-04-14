use crate::errors::{ConfigError, EigenClientError};

use super::{
    config::{EigenConfig, EigenSecrets},
    sdk::RawEigenClient,
};
use async_trait::async_trait;
use secp256k1::SecretKey;
use secrecy::ExposeSecret;
use std::error::Error;
use std::{str::FromStr, sync::Arc};

/// Provides a way of retrieving blobs.
/// Some implementations may not need it. In that case, they can return None in the get_blob method.
/// It can be used as extra verification if you also store the blob yourself.
#[async_trait]
pub trait BlobProvider: std::fmt::Debug + Send + Sync {
    /// Returns the blob for the given blob_id.
    /// If the blob is not found, it should return None.
    async fn get_blob(
        &self,
        blob_id: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>>;
}

/// EigenClient is a client for the Eigen DA service.
#[derive(Debug, Clone)]
pub struct EigenClient {
    pub(crate) client: Arc<RawEigenClient>,
}

impl EigenClient {
    /// Creates a new EigenClient
    pub async fn new(
        config: EigenConfig,
        secrets: EigenSecrets,
        blob_provider: Arc<dyn BlobProvider>,
    ) -> Result<Self, EigenClientError> {
        let private_key = SecretKey::from_str(secrets.private_key.0.expose_secret().as_str())
            .map_err(ConfigError::Secp)?;

        let client = RawEigenClient::new(private_key, config, blob_provider).await?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// Dispatches a blob to the Eigen DA service
    pub async fn dispatch_blob(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        let blob_id = self.client.dispatch_blob(data).await?;

        Ok(blob_id)
    }

    /// Gets the inclusion data for a blob
    pub async fn get_inclusion_data(
        &self,
        blob_id: &str,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        let inclusion_data = self.client.get_inclusion_data(blob_id).await?;
        Ok(inclusion_data)
    }

    /// Returns the blob size limit
    pub fn blob_size_limit(&self) -> Option<usize> {
        Some(RawEigenClient::blob_size_limit())
    }

    /// Returns the blob
    pub async fn get_blob(
        &self,
        blob_index: u32,
        batch_header_hash: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        self.client.get_blob(blob_index, batch_header_hash).await
    }
}
