use ::secp256k1::Message;
use async_trait::async_trait;
use std::sync::Arc;
// Re-export key types from secp256k1
pub mod secp256k1 {
    pub use ::secp256k1::ecdsa;
    pub use ::secp256k1::ecdsa::RecoverableSignature;
    #[cfg(feature = "private-key-signer")]
    pub use ::secp256k1::SecretKey;
    pub use ::secp256k1::{Message, PublicKey};
}

pub mod ethereum_types {
    pub use ethereum_types::H160;
}

mod public_key;
mod signature;
pub mod signers;

use std::error::Error;

pub use public_key::PublicKey;
pub use signature::RecoverableSignature;

/// A trait for signing messages using different key management strategies.
#[async_trait]
pub trait Sign: Send + Sync + std::fmt::Debug {
    type Error: Error + Send + Sync + 'static;

    /// Signs a digest using the signer's key.
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error>;

    /// Returns the public key associated with this signer.
    fn public_key(&self) -> PublicKey;
}

#[async_trait]
impl<T> Sign for &T
where
    T: Sign + Sync,
{
    type Error = T::Error;

    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error> {
        (*self).sign_digest(message).await
    }

    fn public_key(&self) -> PublicKey {
        (*self).public_key()
    }
}

#[async_trait]
impl<T> Sign for Arc<T>
where
    T: Sign + Sync,
{
    type Error = T::Error;

    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error> {
        (**self).sign_digest(message).await
    }

    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }
}

#[async_trait]
impl<T> Sign for Box<T>
where
    T: Sign + Sync,
{
    type Error = T::Error;

    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error> {
        (**self).sign_digest(message).await
    }

    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }
}
