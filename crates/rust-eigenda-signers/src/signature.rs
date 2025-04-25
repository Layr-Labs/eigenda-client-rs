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

    /// Returns the R component of the signature as a 32-byte array.
    pub fn r(&self) -> [u8; 32] {
        let rsv = self.encode_as_rsv();
        let mut r = [0u8; 32];
        r.copy_from_slice(&rsv[..32]);
        r
    }

    /// Returns the S component of the signature as a 32-byte array.
    pub fn s(&self) -> [u8; 32] {
        let rsv = self.encode_as_rsv();
        let mut s = [0u8; 32];
        s.copy_from_slice(&rsv[32..64]);
        s
    }

    /// Returns the recovery identifier (V) as a `u8` (0 or 1).
    pub fn v(&self) -> u8 {
        let rsv = self.encode_as_rsv();
        rsv[64]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::secp256k1::SECP256K1;
    use ::secp256k1::{Message, SecretKey};

    fn sample_rec_sig() -> RecoverableSignature {
        // fixed secret key and message for deterministic signature
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let msg = Message::from_slice(&[0x22u8; 32]).unwrap();
        let sig = SECP256K1.sign_ecdsa_recoverable(&msg, &sk);
        RecoverableSignature::from(sig)
    }

    #[test]
    fn encode_as_rsv_length_is_65() {
        let rec_sig = sample_rec_sig();
        let rsv = rec_sig.encode_as_rsv();
        assert_eq!(rsv.len(), 65);
    }

    #[test]
    fn r_returns_first_32_bytes() {
        let rec_sig = sample_rec_sig();
        let rsv = rec_sig.encode_as_rsv();
        let r = rec_sig.r();
        assert_eq!(r.as_ref(), &rsv[..32]);
    }

    #[test]
    fn s_returns_bytes_32_to_63() {
        let rec_sig = sample_rec_sig();
        let rsv = rec_sig.encode_as_rsv();
        let s = rec_sig.s();
        assert_eq!(s.as_ref(), &rsv[32..64]);
    }

    #[test]
    fn v_returns_the_last_byte() {
        let rec_sig = sample_rec_sig();
        let rsv = rec_sig.encode_as_rsv();
        let v = rec_sig.v();
        assert_eq!(v, rsv[64]);
    }

    #[test]
    fn v_is_either_zero_or_one() {
        let rec_sig = sample_rec_sig();
        let v = rec_sig.v();
        assert!(v <= 1);
    }
}
