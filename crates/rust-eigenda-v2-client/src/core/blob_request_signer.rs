use ethereum_types::Address;
use secp256k1::{Message, SecretKey, SECP256K1};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    errors::{ConversionError, SignerError},
    utils::PrivateKey,
};

use rust_eigenda_cert::BlobHeader;

pub trait BlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, SignerError>;

    fn sign_payment_state_request(&self, timestamp: u64) -> Result<Vec<u8>, SignerError>;

    fn account_id(&self) -> Address;
}

#[derive(Debug, Clone)]
pub struct LocalBlobRequestSigner {
    private_key: SecretKey,
}

impl LocalBlobRequestSigner {
    pub fn new(private_key: PrivateKey) -> Result<Self, SignerError> {
        let private_key = private_key.0.expose_secret();
        // Strip "0x" prefix if present
        let clean_hex = private_key.strip_prefix("0x").unwrap_or(private_key);

        // Convert hex string to bytes
        let private_key_bytes = hex::decode(clean_hex).map_err(SignerError::PrivateKey)?;

        // Create ECDSA private key
        let private_key = SecretKey::from_slice(&private_key_bytes)?;

        Ok(Self { private_key })
    }
}

impl BlobRequestSigner for LocalBlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, SignerError> {
        let blob_key = blob_header
            .blob_key()
            .map_err(ConversionError::EigenDACertConversion)?;
        let message = Message::from_slice(&blob_key.to_bytes())?;
        let sig = SECP256K1.sign_ecdsa_recoverable(&message, &self.private_key);

        let mut sig_bytes = Vec::with_capacity(65);
        let (recovery_id, signature) = sig.serialize_compact();
        sig_bytes.extend_from_slice(&signature);
        sig_bytes.push(recovery_id.to_i32() as u8);

        Ok(sig_bytes)
    }

    fn sign_payment_state_request(&self, timestamp: u64) -> Result<Vec<u8>, SignerError> {
        let account_id = self.account_id();

        let mut keccak_hash = Keccak::v256();
        keccak_hash.update(&(account_id.as_bytes().len() as u32).to_be_bytes());
        keccak_hash.update(account_id.as_bytes());
        keccak_hash.update(&timestamp.to_be_bytes());
        let mut account_id_hash: [u8; 32] = [0u8; 32];
        keccak_hash.finalize(&mut account_id_hash);

        // Hash the account ID bytes with SHA-256
        let hash = Sha256::digest(account_id_hash);

        // Create a secp256k1 message from the hash
        let message = secp256k1::Message::from_slice(hash.as_slice())?;

        // Sign the message using the private key
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &self.private_key);

        // Combine signature with recovery ID
        let mut sig_bytes = Vec::with_capacity(65);
        let (recovery_id, signature) = signature.serialize_compact();
        sig_bytes.extend_from_slice(&signature);
        sig_bytes.push(recovery_id.to_i32() as u8);

        Ok(sig_bytes)
    }

    fn account_id(&self) -> Address {
        let public_key = self.private_key.public_key(SECP256K1);
        let public_key_uncompressed = public_key.serialize_uncompressed();
        let public_key_bytes = &public_key_uncompressed[1..];
        let mut keccak = Keccak::v256();
        keccak.update(public_key_bytes);
        let mut public_key_hash: [u8; 32] = [0u8; 32];
        keccak.finalize(&mut public_key_hash);
        Address::from_slice(&public_key_hash[12..])
    }
}
