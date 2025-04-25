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

#[cfg(test)]
mod tests {
    use super::{Signer, *};
    use crate::signers::private_key::Signer as PrivateKeySigner;
    use ethers::core::rand::thread_rng;
    use ethers::middleware::SignerMiddleware;
    use ethers::providers::{Http, Middleware, Provider};
    use ethers::signers::Signer as EthersSignerTrait; // Alias to avoid naming conflict
    use ethers::types::TransactionRequest;
    use ethers::types::{Address, U256};
    use ethers::utils::parse_ether;
    use ethers::utils::Anvil;
    use secp256k1::SecretKey;
    use std::str::FromStr;
    use tokio;

    #[tokio::test]
    async fn test_chain_id_and_address() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let addr = pk_signer.public_key().address();
        let chain_id = 10u64;

        // When
        let signer = Signer::new(pk_signer, chain_id);

        // Then
        assert_eq!(signer.chain_id(), chain_id);
        assert_eq!(signer.address(), addr);
    }

    #[tokio::test]
    async fn test_with_chain_id() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let signer = Signer::new(pk_signer, 1);
        let new_chain_id = 5u64;

        // When
        let updated_signer = signer.with_chain_id(new_chain_id);

        // Then
        assert_eq!(updated_signer.chain_id(), new_chain_id);
    }

    #[tokio::test]
    async fn test_sign_message() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let chain_id = 1u64;
        let signer = Signer::new(pk_signer, chain_id);
        let message = "test message";

        // When
        let signature = signer.sign_message(message).await.unwrap();

        // Then
        let message_hash = ethers::utils::hash_message(message);
        signature.verify(message_hash, signer.address()).unwrap();
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let chain_id = 1u64;
        let signer = Signer::new(pk_signer.clone(), chain_id);
        let to_address =
            Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let tx = TypedTransaction::Eip1559(ethers::types::Eip1559TransactionRequest {
            to: Some(to_address.into()),
            from: Some(signer.address()),
            data: None,
            value: Some(parse_ether(1).unwrap()),
            chain_id: Some(chain_id.into()),
            max_priority_fee_per_gas: Some(U256::from(1_000_000_000u128)), // 1 Gwei
            max_fee_per_gas: Some(U256::from(20_000_000_000u128)),         // 20 Gwei
            gas: Some(U256::from(21_000u64)),
            nonce: Some(U256::zero()),
            access_list: Default::default(),
        });

        // When
        let signature = signer.sign_transaction(&tx).await.unwrap();

        // Then
        let sighash = tx.sighash();
        signature.verify(sighash, signer.address()).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Anvil on the system"]
    async fn test_integration_send_transaction_anvil() {
        // given
        let anvil = Anvil::new().spawn();
        let endpoint = anvil.endpoint();
        let provider = Provider::<Http>::try_from(endpoint)
            .unwrap()
            .interval(std::time::Duration::from_millis(10u64));

        let private_key_hex =
            SecretKey::from_slice(anvil.keys()[0].to_bytes().as_slice()).unwrap();
        let pk_signer = PrivateKeySigner::new(private_key_hex);

        let our_signer = Signer::new(pk_signer, anvil.chain_id());

        let client = SignerMiddleware::new(provider, our_signer.clone());

        let from_addr = our_signer.address();
        let to_addr = anvil.addresses()[1];
        let value = parse_ether(0.1).unwrap();

        let tx = TransactionRequest::new()
            .to(to_addr)
            .from(from_addr)
            .value(value)
            .chain_id(anvil.chain_id());

        // When
        let pending_tx = client.send_transaction(tx, None).await;

        // Then
        assert!(pending_tx.is_ok());
        let receipt = pending_tx.unwrap().await.unwrap();
        assert!(receipt.is_some(), "Transaction should be mined");
        let receipt = receipt.unwrap();
        assert_eq!(receipt.status, Some(1u64.into()), "Transaction failed");
        assert_eq!(receipt.from, from_addr);
        assert_eq!(receipt.to, Some(to_addr));
    }
}
