use alloy::{consensus::SignableTransaction, network::TxSigner, primitives::{Address, FixedBytes, U256}, signers::Signature};
use ethereum_types::H256;
use thiserror::Error;

use crate::{Message, RecoverableSignature, Sign};

#[derive(Debug, Clone)]
pub struct Signer<S> {
    inner_signer: S,
    chain_id: u64,
}

#[derive(Error, Debug)]
pub enum Error {
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
        digest: FixedBytes<32>,
        chain_id: u64,
    ) -> Result<Signature, Error>
    where
        S: Sign,
    {
        let msg = Message::new(*digest);

        let sig: RecoverableSignature = self
            .inner_signer
            .sign_digest(&msg)
            .await
            .map_err(|e| Error::Signer(Box::new(e)))?;

        let sig_bytes = sig.to_bytes();

        let alloy_sig = Signature::from_raw(&sig_bytes).unwrap();

        //apply_eip155(&mut ethers_sig, chain_id);

        Ok(alloy_sig)
    }
}

/// Modify the v value of a signature to conform to eip155
/*fn apply_eip155(sig: &mut Signature, chain_id: u64) {
    let v = (chain_id * 2 + 35) + sig.v;
    sig.v = v;
}*/

#[async_trait::async_trait]
impl<T> TxSigner<Signature> for Signer<T>
where
    T: Sign,
{

    /// Signs the transaction
    async fn sign_transaction(&self, tx: &mut dyn SignableTransaction<Signature>,) -> alloy::signers::Result<Signature> {
        let chain_id = tx
            .chain_id()
            .unwrap_or(self.chain_id);
        
        tx.set_chain_id(chain_id);

        let sighash = tx.signature_hash();
        self.sign_digest_with_eip155(sighash, chain_id).await.map_err(|e| {
            alloy::signers::Error::Other(Box::new(e))
        })
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address {
        let address = self.inner_signer.public_key().address();
        Address::from_slice(&address.0)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::network::EthereumWallet;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::rpc::types::TransactionRequest;
    use alloy::transports::http::reqwest::Url;
    use alloy::{consensus::TxEip1559, primitives::ruint::aliases::U256};
    use alloy::primitives::Address;
    use ethereum_types::H160;
    use ethers::{
        core::rand::thread_rng,
        utils::{parse_ether, Anvil},
    };
    use tokio;

    use super::{Signer, *};
    use crate::{signers::private_key::Signer as PrivateKeySigner, SecretKey};

    #[tokio::test]
    async fn test_address() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let addr = pk_signer.public_key().address();
        let chain_id = 10u64;

        // When
        let signer = Signer::new(pk_signer, chain_id);

        // Then
        let signer_address = H160::from_slice(signer.address().as_slice());
        assert_eq!(signer_address, addr);
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        // Given
        let pk_signer = PrivateKeySigner::random(&mut thread_rng());
        let chain_id = 1u64;
        let signer = Signer::new(pk_signer.clone(), chain_id);
        let to_address = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let mut tx = TxEip1559 {
            to: alloy::primitives::TxKind::Call(to_address),
            value: U256::from_str("1000000000000000000").unwrap(), // 1 Ether
            chain_id,
            max_priority_fee_per_gas: 1_000_000_000u128, // 1 Gwei
            max_fee_per_gas: 20_000_000_000u128,         // 20 Gwei
            gas_limit: 21_000u64,
            nonce: 0,
            access_list: Default::default(),
            input: Default::default(),
        };

        // When
        let signature = signer.sign_transaction(&mut tx).await.unwrap();

        // Then
        let sighash = tx.signature_hash();
        let recovered_addr = signature.recover_address_from_msg(sighash).unwrap();
        assert_eq!(recovered_addr, signer.address(), "Recovered address should match signer's address");
    }

    #[tokio::test]
    #[ignore = "requires Anvil on the system"]
    async fn test_integration_send_transaction_anvil() {
        // given
        let anvil = Anvil::new().spawn();
        let endpoint = anvil.endpoint();

        let rpc_url = Url::from_str(&endpoint).unwrap();

        let private_key_hex = SecretKey::new(anvil.keys()[0].to_bytes().into()).unwrap();
        let pk_signer = PrivateKeySigner::new(private_key_hex);

        let our_signer = Signer::new(pk_signer, anvil.chain_id());

        let wallet = EthereumWallet::from(our_signer.clone());

        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_http(rpc_url.clone());

        let from_addr = our_signer.address();
        let to_addr = Address::from_slice(anvil.addresses()[1].as_bytes());
        let value = parse_ether(0.1).unwrap();

        let tx = TransactionRequest::from_transaction(TxEip1559 {
            to: alloy::primitives::TxKind::Call(to_addr),
            value: U256::from_str("1000000000000000000").unwrap(), // 1 Ether
            chain_id: anvil.chain_id(),
            max_priority_fee_per_gas: 1_000_000_000u128, // 1 Gwei
            max_fee_per_gas: 20_000_000_000u128,         // 20 Gwei
            gas_limit: 21_000u64,
            nonce: 0,
            access_list: Default::default(),
            input: Default::default(),
        });

        // When
        let pending_tx = provider.send_transaction(tx).await.unwrap();

        // Then
        let receipt = pending_tx.get_receipt().await;
        //assert!(pending_tx.);
        assert!(receipt.is_ok(), "Transaction should be mined");
        let receipt = receipt.unwrap();
        assert_eq!(receipt.status(), true, "Transaction failed");
        assert_eq!(receipt.from, from_addr);
        assert_eq!(receipt.to, Some(to_addr));
    }
}
