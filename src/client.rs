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

/// This trait provides a method call which given the blob id, returns the blob data or None
/// It you don't need to use it, just return None and it would be as if it didn't exist
/// It can be used as extra verification if you also store the blob yourself
#[async_trait]
pub trait GetBlobData: std::fmt::Debug + Send + Sync {
    async fn get_blob_data(
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
        get_blob_data: Arc<dyn GetBlobData>,
    ) -> Result<Self, EigenClientError> {
        let private_key = SecretKey::from_str(secrets.private_key.0.expose_secret().as_str())
            .map_err(ConfigError::Secp)?;

        let client = RawEigenClient::new(private_key, config, get_blob_data).await?;
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
}
