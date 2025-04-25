use ethereum_types::H256;
use ethers::types::{
    transaction::{eip2718::TypedTransaction, eip712::Eip712},
    Signature,
};
use secp256k1::Message;
use thiserror::Error;

use crate::Sign;

#[derive(Debug, Clone)]
pub struct Signer<S> {
    inner_signer: S,
    chain_id: u64,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create message from digest")]
    InvalidDigest,
    #[error("Failed to encode EIP712")]
    Eip712Encoding(String),
    #[error("failed to sign")]
    Signer(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl<S> Signer<S> {
    pub fn new(inner_signer: S, chain_id: u64) -> Self {
        Self {
            inner_signer,
            chain_id,
        }
    }

    async fn sign_digest_with_eip155(
        &self,
        digest: H256,
        chain_id: u64,
    ) -> Result<ethers::types::Signature, Error>
    where
        S: Sign,
    {
        let msg = Message::from_slice(&digest.to_fixed_bytes())
            .map_err(|_| Error::InvalidDigest)?;

        let sig = self
            .inner_signer
            .sign_digest(&msg)
            .await
            .map_err(|e| Error::Signer(Box::new(e)))?;

        let mut ethers_sig = Signature {
            r: sig.r().into(),
            s: sig.s().into(),
            v: sig.v().into(),
        };

        apply_eip155(&mut ethers_sig, chain_id);

        Ok(ethers_sig)
    }
}

/// Modify the v value of a signature to conform to eip155
fn apply_eip155(sig: &mut Signature, chain_id: u64) {
    let v = (chain_id * 2 + 35) + sig.v;
    sig.v = v;
}

#[async_trait::async_trait]
impl<T> ethers::signers::Signer for Signer<T>
where
    T: Sign,
{
    type Error = Error;

    /// Signs the hash of the provided message after prefixing it
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let message = message.as_ref();
        let message_hash = ethers::utils::hash_message(message);

        self.sign_digest_with_eip155(message_hash, self.chain_id)
            .await
    }

    /// Signs the transaction
    async fn sign_transaction(
        &self,
        tx: &TypedTransaction,
    ) -> Result<Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        let chain_id = tx_with_chain
            .chain_id()
            .map(|id| id.as_u64())
            .unwrap_or(self.chain_id);
        tx_with_chain.set_chain_id(chain_id);

        let sighash = tx_with_chain.sighash();
        self.sign_digest_with_eip155(sighash, chain_id).await
    }

    /// Encodes and signs the typed data according EIP-712.
    /// Payload must implement Eip712 trait.
    async fn sign_typed_data<P: Eip712 + Send + Sync>(
        &self,
        payload: &P,
    ) -> Result<Signature, Self::Error> {
        let digest = payload
            .encode_eip712()
            .map_err(|e| Error::Eip712Encoding(e.to_string()))?;

        let msg =
            Message::from_slice(digest.as_slice()).map_err(|_| Error::InvalidDigest)?;

        let sig = self
            .inner_signer
            .sign_digest(&msg)
            .await
            .map_err(|e| Error::Signer(Box::new(e)))?;

        Ok(Signature {
            r: sig.r().into(),
            s: sig.s().into(),
            v: sig.v().into(),
        })
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> ethereum_types::Address {
        self.inner_signer.public_key().address()
    }

    /// Returns the signer's chain id
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the signer's chain id
    #[must_use]
    fn with_chain_id<C: Into<u64>>(mut self, chain_id: C) -> Self {
        self.chain_id = chain_id.into();
        self
    }
}
