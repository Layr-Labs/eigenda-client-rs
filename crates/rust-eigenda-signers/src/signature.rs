use crate::secp256k1;
use std::convert::AsRef;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableSignature(pub secp256k1::RecoverableSignature);

impl From<secp256k1::RecoverableSignature> for RecoverableSignature {
    fn from(sig: secp256k1::RecoverableSignature) -> Self {
        RecoverableSignature(sig)
    }
}

impl Deref for RecoverableSignature {
    type Target = secp256k1::RecoverableSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<secp256k1::RecoverableSignature> for RecoverableSignature {
    fn as_ref(&self) -> &secp256k1::RecoverableSignature {
        &self.0
    }
}

impl RecoverableSignature {
    /// Encodes the signature into a 65-byte vector [R || S || V], where V is 0 or 1.
    pub fn encode_as_rsv(&self) -> Vec<u8> {
        let (recovery_id, sig) = self.0.serialize_compact();

        let mut signature = vec![0u8; 65];
        signature[0..64].copy_from_slice(&sig);
        signature[64] = recovery_id.to_i32() as u8;
        signature
    }
}
