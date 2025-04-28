use ethabi::Token;
use ethereum_types::U256;
use rust_eigenda_v2_common::BlobHeader;
use tiny_keccak::{Hasher, Keccak};

use crate::errors::ConversionError;

/// [`BlobKey`] is the unique identifier for a blob dispersal.
///
/// It is computed as the Keccak256 hash of some serialization of the blob header
/// where the [`PaymentHeader`] has been replaced with `Hash(PaymentHeader)`, in order
/// to be easily verifiable onchain.
///
/// It can be used to retrieve a blob from relays.
///
/// Note that two blobs can have the same content but different headers,
/// so they are allowed to both exist in the system.
#[derive(Debug)]
pub struct BlobKey([u8; 32]);

impl BlobKey {
    /// Creates a new [`BlobKey`] from a slice of bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        BlobKey(bytes)
    }

    /// Returns the bytes of the [`BlobKey`].
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Creates a new [`BlobKey`] from a hex string.
    ///
    /// Note: The hex string should not include the 0x prefix.
    pub fn from_hex(hex: &str) -> Result<Self, ConversionError> {
        let bytes: [u8; 32] = hex::decode(hex)
            .map_err(|_| ConversionError::BlobKey("Invalid hex string".to_string()))?
            .try_into()
            .map_err(|_| ConversionError::BlobKey("Invalid hex string length".to_string()))?;

        Ok(BlobKey(bytes))
    }

    /// Converts the [`BlobKey`] to a hex string.
    ///
    /// Note: The hex string will not include the 0x prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Computes a new [`BlobKey`] from the given [`BlobHeader`].
    pub fn compute_blob_key(blob_header: &BlobHeader) -> Result<BlobKey, ConversionError> {
        let mut sorted_quorums = blob_header.quorum_numbers.clone();
        sorted_quorums.sort();

        let packed_bytes = ethabi::encode(&[
            Token::Uint(blob_header.version.into()), // BlobVersion
            Token::Bytes(sorted_quorums.clone()),    // SortedQuorums
            Token::Tuple(vec![
                // AbiBlobCommitments
                // Commitment
                Token::Tuple(vec![
                    Token::Uint(
                        U256::from_dec_str(&blob_header.commitment.commitment.x.to_string())
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                    ), // commitment X
                    Token::Uint(
                        U256::from_dec_str(&blob_header.commitment.commitment.y.to_string())
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                    ), // commitment Y
                ]),
                // Most cryptography library serializes a G2 point by having
                // A0 followed by A1 for both X, Y field of G2. However, ethereum
                // precompile assumes an ordering of A1, A0. We choose
                // to conform with Ethereum order when serializing a blobHeaderV2
                // for instance, gnark, https://github.com/Consensys/gnark-crypto/blob/de0d77f2b4d520350bc54c612828b19ce2146eee/ecc/bn254/marshal.go#L1078
                // Ethereum, https://eips.ethereum.org/EIPS/eip-197#definition-of-the-groups
                // LengthCommitment
                Token::Tuple(vec![
                    // X
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_commitment.x.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_commitment.x.c0.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                    // Y
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_commitment.y.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_commitment.y.c0.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                ]),
                // Same as above
                // LengthProof
                Token::Tuple(vec![
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_proof.x.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_proof.x.c0.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_proof.y.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_header.commitment.length_proof.y.c0.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                ]),
                Token::Uint(blob_header.commitment.length.into()), // DataLength
            ]),
        ]);

        let mut keccak = Keccak::v256();
        keccak.update(&packed_bytes);
        let mut header_hash = [0u8; 32];
        keccak.finalize(&mut header_hash);

        let s2 = vec![
            Token::FixedBytes(header_hash.to_vec()),
            Token::FixedBytes(blob_header.payment_header_hash.to_vec()),
        ];

        let packed_bytes = ethabi::encode(&s2);

        let mut keccak = Keccak::v256();
        keccak.update(&packed_bytes);
        let mut blob_key = [0u8; 32];
        keccak.finalize(&mut blob_key);
        Ok(BlobKey(blob_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_key_from_hex() {
        let hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let blob_key = BlobKey::from_hex(hex).unwrap();
        assert_eq!(blob_key.to_hex(), hex);
    }

    #[test]
    fn test_blob_key_from_bytes() {
        let bytes = [1; 32];
        let blob_key = BlobKey::from_bytes(bytes);
        assert_eq!(blob_key.to_bytes(), bytes);
    }
}
