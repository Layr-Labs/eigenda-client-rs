use ethereum_types::Address;
use secp256k1::{SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use super::eigenda_cert::BlobHeader;

pub trait BlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String>;

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String>;

    fn account_id(&self) -> Result<Address, String>;
}

pub struct LocalBlobRequestSigner {
    private_key: SecretKey,
}

impl LocalBlobRequestSigner {
    pub fn new(private_key: &str) -> Result<Self, String> {
        // Strip "0x" prefix if present
        let clean_hex = private_key.strip_prefix("0x").unwrap_or(private_key);

        // Convert hex string to bytes
        let private_key_bytes =
            hex::decode(clean_hex).map_err(|e| format!("Failed to parse private key: {}", e))?;

        // Create ECDSA private key
        let private_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;

        Ok(Self { private_key })
    }
}

impl BlobRequestSigner for LocalBlobRequestSigner {
    // TODO: change error type.
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String> {
        let blob_key = blob_header.blob_key().map_err(|_| "Error")?;
        let blob_key_bytes = blob_key;

        // TODO: wait for having a single BlobCommitment type
        todo!();
    }

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String> {
        let account_id = self.account_id()?;

        // Hash the account ID bytes with SHA-256
        let hash = Sha256::digest(account_id.as_bytes());

        // Create a secp256k1 message from the hash
        let message = secp256k1::Message::from_slice(hash.as_slice())
            .map_err(|e| format!("Failed to create message from hash: {}", e))?;

        // Sign the message using the private key
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &self.private_key);

        // Combine signature with recovery ID
        let mut sig_bytes = Vec::with_capacity(65);
        let (recovery_id, signature) = signature.serialize_compact();
        sig_bytes.extend_from_slice(&signature);
        sig_bytes.push(recovery_id.to_i32() as u8);

        Ok(sig_bytes)
    }

    fn account_id(&self) -> Result<Address, String> {
        let public_key = self.private_key.public_key(&SECP256K1);
        let address = Address::from_slice(&public_key.serialize_uncompressed()[12..]);
        Ok(address)
    }
}
