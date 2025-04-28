use std::sync::Arc;

use async_trait::async_trait;

pub mod ethereum_types {
    pub use ethereum_types::H160;
}

mod message;
mod public_key;
mod recovery_id;
mod secret_key;
mod signature;
pub mod signers;

use std::error::Error;

pub use message::Message;
pub use public_key::{Error as PublicKeyError, PublicKey};
pub use recovery_id::{InvalidRecoveryId, RecoveryId};
pub use secret_key::{Error as SecretKeyError, SecretKey};
pub use signature::RecoverableSignature;

/// A trait for signing messages using different key management strategies.
#[async_trait]
pub trait Sign: Send + Sync + std::fmt::Debug {
    /// The specific error type returned by the signer.
    type Error: Error + Send + Sync + 'static;

    /// Signs a 32-byte digest using the signer's key.
    ///
    /// # Arguments
    ///
    /// * `message`: The message digest to sign.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `RecoverableSignature` on success, or the signer's specific `Error` on failure.
    async fn sign_digest(&self, message: &Message) -> Result<RecoverableSignature, Self::Error>;

    /// Returns the public key associated with this signer.
    fn public_key(&self) -> PublicKey;
}

/// Blanket implementation for references to `Sign` implementors.
#[async_trait]
impl<T> Sign for &T
where
    T: Sign + Sync,
{
    type Error = T::Error;

    /// Delegates the signing operation to the underlying signer.
    async fn sign_digest(&self, message: &Message) -> Result<RecoverableSignature, Self::Error> {
        (*self).sign_digest(message).await
    }

    /// Delegates the public key retrieval to the underlying signer.
    fn public_key(&self) -> PublicKey {
        (*self).public_key()
    }
}

/// Blanket implementation for `Arc<T>` where `T` implements `Sign`.
#[async_trait]
impl<T> Sign for Arc<T>
where
    T: Sign + Sync,
{
    type Error = T::Error;

    /// Delegates the signing operation to the underlying signer.
    async fn sign_digest(&self, message: &Message) -> Result<RecoverableSignature, Self::Error> {
        (**self).sign_digest(message).await
    }

    /// Delegates the public key retrieval to the underlying signer.
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }
}

/// Blanket implementation for `Box<T>` where `T` implements `Sign`.
#[async_trait]
impl<T> Sign for Box<T>
where
    T: Sign + Sync,
{
    type Error = T::Error;

    /// Use our Message and RecoverableSignature types
    /// Delegates the signing operation to the underlying signer.
    async fn sign_digest(&self, message: &Message) -> Result<RecoverableSignature, Self::Error> {
        (**self).sign_digest(message).await
    }

    /// Delegates the public key retrieval to the underlying signer.
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }
}
