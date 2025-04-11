use ethabi::Token;
use ethereum_types::U256;
use tiny_keccak::{Hasher, Keccak};

use crate::errors::ConversionError;

use super::eigenda_cert::BlobCommitment;

// BlobKey is the unique identifier for a blob dispersal.
//
// It is computed as the Keccak256 hash of some serialization of the blob header
// where the PaymentHeader has been replaced with Hash(PaymentHeader), in order
// to be easily verifiable onchain.
//
// It can be used to retrieve a blob from relays.
//
// Note that two blobs can have the same content but different headers,
// so they are allowed to both exist in the system.
#[derive(Debug)]
pub struct BlobKey([u8; 32]);

impl BlobKey {
    pub(crate) fn compute_blob_key(
        blob_version: u16,
        blob_commitments: BlobCommitment,
        quorum_numbers: Vec<u8>,
        payment_metadata_hash: [u8; 32],
    ) -> Result<BlobKey, ConversionError> {
        let mut sorted_quorums = quorum_numbers;
        sorted_quorums.sort();

        let packed_bytes = ethabi::encode(&[
            Token::Uint(blob_version.into()),     // BlobVersion
            Token::Bytes(sorted_quorums.clone()), // SortedQuorums
            Token::Tuple(vec![
                // AbiBlobCommitments
                // Commitment
                Token::Tuple(vec![
                    Token::Uint(
                        U256::from_dec_str(&blob_commitments.commitment.x.to_string())
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                    ), // commitment X
                    Token::Uint(
                        U256::from_dec_str(&blob_commitments.commitment.y.to_string())
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
                                &blob_commitments.length_commitment.x.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_commitments.length_commitment.x.c0.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                    // Y
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_commitments.length_commitment.y.c1.to_string(),
                            )
                            .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(
                                &blob_commitments.length_commitment.y.c0.to_string(),
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
                            U256::from_dec_str(&blob_commitments.length_proof.x.c1.to_string())
                                .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(&blob_commitments.length_proof.x.c0.to_string())
                                .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                    Token::FixedArray(vec![
                        Token::Uint(
                            U256::from_dec_str(&blob_commitments.length_proof.y.c1.to_string())
                                .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                        Token::Uint(
                            U256::from_dec_str(&blob_commitments.length_proof.y.c0.to_string())
                                .map_err(|e| ConversionError::U256Conversion(e.to_string()))?,
                        ),
                    ]),
                ]),
                Token::Uint(blob_commitments.length.into()), // DataLength
            ]),
        ]);

        let mut keccak = Keccak::v256();
        keccak.update(&packed_bytes);
        let mut header_hash = [0u8; 32];
        keccak.finalize(&mut header_hash);

        let s2 = vec![
            Token::FixedBytes(header_hash.to_vec()),
            Token::FixedBytes(payment_metadata_hash.to_vec()),
        ];

        let packed_bytes = ethabi::encode(&s2);

        let mut keccak = Keccak::v256();
        keccak.update(&packed_bytes);
        let mut blob_key = [0u8; 32];
        keccak.finalize(&mut blob_key);
        Ok(BlobKey(blob_key))
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
