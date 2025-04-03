use std::u16;

use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ethabi::Token;
use ethereum_types::U256;
use tiny_keccak::{Hasher, Keccak};

use crate::errors::{BlobError, ConversionError, EigenClientError};
use crate::generated::disperser::v2::BlobStatusReply;

use crate::generated::{
    common::{
        v2::{
            BatchHeader as ProtoBatchHeader, BlobCertificate as ProtoBlobCertificate,
            BlobHeader as ProtoBlobHeader, PaymentHeader as ProtoPaymentHeader,
        },
        BlobCommitment as ProtoBlobCommitment,
    },
    disperser::v2::BlobInclusionInfo as ProtoBlobInclusionInfo,
};

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct G1Commitment {
    pub(crate) x: Vec<u8>,
    pub(crate) y: Vec<u8>,
}

impl TryFrom<Vec<u8>> for G1Commitment {
    type Error = ConversionError;

    // TODO: How many bytes does each field take?
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return Err(ConversionError::G1Point(format!(
                "Invalid byte length {}",
                value.len()
            )));
        }

        let mut x = vec![0u8; 32];
        let mut y = vec![0u8; 32];
        x.copy_from_slice(&value[0..32]);
        y.copy_from_slice(&value[32..64]);
        Ok(G1Commitment { x, y })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct G2Commitment {
    pub(crate) x_a0: Vec<u8>,
    pub(crate) x_a1: Vec<u8>,
    pub(crate) y_a0: Vec<u8>,
    pub(crate) y_a1: Vec<u8>,
}

impl TryFrom<Vec<u8>> for G2Commitment {
    type Error = ConversionError;

    // TODO: How many bytes does each field take?
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 128 {
            return Err(ConversionError::G2Point(format!(
                "Invalid byte length {}",
                value.len()
            )));
        }

        let mut x_a0 = vec![0u8; 32];
        let mut x_a1 = vec![0u8; 32];
        let mut y_a0 = vec![0u8; 32];
        let mut y_a1 = vec![0u8; 32];
        x_a0.copy_from_slice(&value[0..32]);
        x_a1.copy_from_slice(&value[32..64]);
        y_a0.copy_from_slice(&value[64..96]);
        y_a1.copy_from_slice(&value[96..128]);
        Ok(G2Commitment {
            x_a0,
            x_a1,
            y_a0,
            y_a1,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct PaymentHeader {
    pub(crate) account_id: String,
    pub(crate) timestamp: i64,
    pub(crate) cumulative_payment: Vec<u8>,
}

impl From<ProtoPaymentHeader> for PaymentHeader {
    fn from(value: ProtoPaymentHeader) -> Self {
        PaymentHeader {
            account_id: value.account_id,
            timestamp: value.timestamp,
            cumulative_payment: value.cumulative_payment,
        }
    }
}

impl PaymentHeader {
    pub fn hash(&self) -> Result<[u8; 32], ConversionError> {
        let cumulative_payment =
            U256::try_from(self.cumulative_payment.as_slice()).map_err(|_| {
                ConversionError::PaymentHeader("Invalid cumulative payment".to_string())
            })?;
        let token = Token::Tuple(vec![
            Token::String(self.account_id.clone()),
            Token::Int(self.timestamp.into()),
            Token::Uint(cumulative_payment),
        ]);

        let encoded = ethabi::encode(&[token]);

        let mut hasher = Keccak::v256();
        hasher.update(&encoded);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        Ok(hash)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobCommitment {
    pub(crate) commitment: G1Commitment,
    pub(crate) length_commitment: G2Commitment,
    pub(crate) length_proof: G2Commitment,
    pub(crate) length: u32,
}

impl BlobCommitment {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::Tuple(vec![
                Token::Uint(U256::from_big_endian(&self.commitment.x)),
                Token::Uint(U256::from_big_endian(&self.commitment.y)),
            ]),
            Token::Tuple(vec![
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.length_commitment.x_a1)),
                    Token::Uint(U256::from_big_endian(&self.length_commitment.x_a0)),
                ]),
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.length_commitment.y_a1)),
                    Token::Uint(U256::from_big_endian(&self.length_commitment.y_a0)),
                ]),
            ]),
            Token::Tuple(vec![
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.length_proof.x_a1)),
                    Token::Uint(U256::from_big_endian(&self.length_proof.x_a0)),
                ]),
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.length_proof.y_a1)),
                    Token::Uint(U256::from_big_endian(&self.length_proof.y_a0)),
                ]),
            ]),
            Token::Uint(self.length.into()),
        ]
    }
}

impl TryFrom<ProtoBlobCommitment> for BlobCommitment {
    type Error = ConversionError;

    fn try_from(value: ProtoBlobCommitment) -> Result<Self, Self::Error> {
        let commitment = G1Commitment::try_from(value.commitment)?;
        let length_commitment = G2Commitment::try_from(value.length_commitment)?;
        let length_proof = G2Commitment::try_from(value.length_proof)?;
        let length = value.length;

        Ok(Self {
            commitment,
            length_commitment,
            length_proof,
            length,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobHeader {
    pub(crate) version: u16,
    pub(crate) quorum_numbers: Vec<u8>,
    pub(crate) commitment: BlobCommitment,
    pub(crate) payment_header_hash: [u8; 32],
}

impl BlobHeader {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::Uint(self.version.into()),
            Token::Bytes(self.quorum_numbers.clone()),
            Token::Tuple(self.commitment.to_tokens()),
            Token::FixedBytes(self.payment_header_hash.to_vec()),
        ]
    }
}

impl TryFrom<ProtoBlobHeader> for BlobHeader {
    type Error = ConversionError;

    fn try_from(value: ProtoBlobHeader) -> Result<Self, Self::Error> {
        let version: u16 = match value.version.try_into() {
            Ok(version) => version,
            Err(_) => {
                return Err(ConversionError::BlobHeader(format!(
                    "Invalid version {}",
                    value.version
                )))
            }
        };

        let mut quorum_numbers: Vec<u8> = Vec::new();
        for number in value.quorum_numbers.iter() {
            quorum_numbers.push((*number).try_into().map_err(|_| {
                ConversionError::BlobHeader(format!("Invalid quorum number {}", number))
            })?);
        }

        let commitment = BlobCommitment::try_from(value.commitment.ok_or(
            ConversionError::BlobHeader("Missing commitment".to_string()),
        )?)?;

        let payment_header_hash = PaymentHeader::from(value.payment_header.ok_or(
            ConversionError::BlobHeader("Missing payment header".to_string()),
        )?)
        .hash()?;

        Ok(Self {
            version,
            quorum_numbers,
            commitment,
            payment_header_hash,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobCertificate {
    pub(crate) blob_header: BlobHeader,
    pub(crate) signature: Vec<u8>,
    pub(crate) relay_keys: Vec<u32>,
}

impl BlobCertificate {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::Tuple(self.blob_header.to_tokens()),
            Token::Bytes(self.signature.clone()),
            Token::Array(self.relay_keys.iter().map(|k| Token::Uint((*k).into())).collect()),
        ]
    }
}

impl TryFrom<ProtoBlobCertificate> for BlobCertificate {
    type Error = ConversionError;

    fn try_from(value: ProtoBlobCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_header: BlobHeader::try_from(value.blob_header.ok_or(
                ConversionError::BlobCertificate("Missing blob header".to_string()),
            )?)?,
            signature: value.signature,
            relay_keys: value.relay_keys,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobInclusionInfo {
    pub(crate) blob_certificate: BlobCertificate,
    pub(crate) blob_index: u32,
    pub(crate) inclusion_proof: Vec<u8>,
}

impl BlobInclusionInfo {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::Tuple(self.blob_certificate.to_tokens()),
            Token::Uint(self.blob_index.into()),
            Token::Bytes(self.inclusion_proof.clone()),
        ]
    }
}

impl TryFrom<ProtoBlobInclusionInfo> for BlobInclusionInfo {
    type Error = ConversionError;

    fn try_from(value: ProtoBlobInclusionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_certificate: BlobCertificate::try_from(value.blob_certificate.ok_or(
                ConversionError::BlobInclusion("Missing blob certificate".to_string()),
            )?)?,
            blob_index: value.blob_index,
            inclusion_proof: value.inclusion_proof,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BatchHeaderV2 {
    pub(crate) batch_root: [u8; 32],
    pub(crate) reference_block_number: u32,
}

impl BatchHeaderV2 {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::FixedBytes(self.batch_root.to_vec()),
            Token::Uint(self.reference_block_number.into()),
        ]
    }
}

impl TryFrom<ProtoBatchHeader> for BatchHeaderV2 {
    type Error = ConversionError;

    fn try_from(value: ProtoBatchHeader) -> Result<Self, Self::Error> {
        let batch_root: [u8; 32] = match value.batch_root.clone().try_into() {
            Ok(root) => root,
            Err(_) => {
                return Err(ConversionError::BatchHeader(format!(
                    "Invalid batch root: {}",
                    hex::encode(value.batch_root)
                )))
            }
        };
        let reference_block_number = value.reference_block_number.try_into().map_err(|_| {
            ConversionError::BatchHeader(format!(
                "Invalid reference block number: {}",
                value.reference_block_number
            ))
        })?;
        Ok(Self {
            batch_root,
            reference_block_number,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct NonSignerStakesAndSignature {
    pub(crate) non_signer_quorum_bitmap_indices: Vec<u32>,
    pub(crate) non_signer_pubkeys: Vec<G1Affine>,
    pub(crate) quorum_apks: Vec<G1Affine>,
    pub(crate) apk_g2: G2Affine, 
    pub(crate) sigma: G1Affine,
    pub(crate) quorum_apk_indices: Vec<u32>,
    pub(crate) total_stake_indices: Vec<u32>,
    pub(crate) non_signer_stake_indices: Vec<Vec<u32>>,
}

impl NonSignerStakesAndSignature {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![
            Token::Array(
                self.non_signer_quorum_bitmap_indices
                    .iter()
                    .map(|k| Token::Uint((*k).into()))
                    .collect(),
            ),
            Token::Array(
                self.non_signer_pubkeys
                    .iter()
                    .map(|k| Token::Tuple(
                        vec![
                            Token::Uint(U256::from_big_endian(&k.x.into_bigint().to_bytes_be())),
                            Token::Uint(U256::from_big_endian(&k.y.into_bigint().to_bytes_be())),
                        ]
                    ))
                    .collect(),
            ),
            Token::Array(
                self.quorum_apks
                    .iter()
                    .map(|k| Token::Tuple(vec![
                        Token::Uint(U256::from_big_endian(&k.x.into_bigint().to_bytes_be())),
                        Token::Uint(U256::from_big_endian(&k.y.into_bigint().to_bytes_be())),
                    ]))
                    .collect(),
            ),
            Token::Tuple(vec![
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.apk_g2.x.c1.into_bigint().to_bytes_be())),
                    Token::Uint(U256::from_big_endian(&self.apk_g2.x.c0.into_bigint().to_bytes_be())),
                ]),
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&self.apk_g2.y.c1.into_bigint().to_bytes_be())),
                    Token::Uint(U256::from_big_endian(&self.apk_g2.y.c0.into_bigint().to_bytes_be())),
                ]),
            ]),
            Token::Tuple(vec![
                Token::Uint(U256::from_big_endian(&self.sigma.x.into_bigint().to_bytes_be())),
                Token::Uint(U256::from_big_endian(&self.sigma.y.into_bigint().to_bytes_be())),
            ]),
            Token::Array(
                self.quorum_apk_indices
                    .iter()
                    .map(|k| Token::Uint((*k).into()))
                    .collect(),
            ),
            Token::Array(
                self.total_stake_indices
                    .iter()
                    .map(|k| Token::Uint((*k).into()))
                    .collect(),
            ),
            Token::Array(
                self.non_signer_stake_indices
                    .iter()
                    .map(|k| Token::Array(k.iter().map(|i| Token::Uint((*i).into())).collect()))
                    .collect(),
            ),
        ]
    }
}

// EigenDACert contains all data necessary to retrieve and validate a blob
//
// This struct represents the composition of a eigenDA blob certificate, as it would exist in a rollup inbox.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct EigenDACert {
    pub(crate) blob_inclusion_info: BlobInclusionInfo,
    pub(crate) batch_header: BatchHeaderV2,
    pub(crate) non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    pub(crate) signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub(crate) fn new(
        blob_status_reply: BlobStatusReply,
        non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    ) -> Result<Self, EigenClientError> {
        let binding_inclusion_info = BlobInclusionInfo::try_from(
            blob_status_reply
                .blob_inclusion_info
                .ok_or(BlobError::MissingField("blob_inclusion_info".to_string()))?,
        )?;

        let signed_batch = blob_status_reply
            .signed_batch
            .ok_or(BlobError::MissingField("signed_batch".to_string()))?;
        let binding_batch_header = BatchHeaderV2::try_from(
            signed_batch
                .header
                .ok_or(BlobError::MissingField("header".to_string()))?,
        )?;

        let mut signed_quorum_numbers: Vec<u8> = Vec::new();
        for q in signed_batch
            .attestation
            .ok_or(BlobError::MissingField("attestation".to_string()))?
            .quorum_numbers
        {
            signed_quorum_numbers.push(
                q.try_into()
                    .map_err(|_| BlobError::InvalidQuorumNumber(q))?,
            );
        }

        Ok(Self {
            blob_inclusion_info: binding_inclusion_info,
            batch_header: binding_batch_header,
            non_signer_stakes_and_signature,
            signed_quorum_numbers,
        })
    }

    /// Computes the blob_key of the blob that belongs to the EigenDACert
    pub(crate) fn compute_blob_key(&self) -> Result<BlobKey, ConversionError> {
        let blob_header = self
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .clone();

        let blob_commitments = blob_header.commitment;

        let blob_key_bytes = compute_blob_key_bytes(
            blob_header.version,
            blob_commitments,
            blob_header.quorum_numbers,
            blob_header.payment_header_hash,
        )?;

        let blob_key: BlobKey = match blob_key_bytes.try_into() {
            Ok(key) => key,
            Err(_) => {
                return Err(ConversionError::BlobKey(
                    "Failed to parse blob key".to_string(),
                ))
            }
        };
        Ok(blob_key)
    }
}

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
pub(crate) type BlobKey = [u8; 32];

fn compute_blob_key_bytes(
    blob_version: u16,
    blob_commitments: BlobCommitment,
    quorum_numbers: Vec<u8>,
    payment_metadata_hash: [u8; 32],
) -> Result<Vec<u8>, ConversionError> {
    let mut sorted_quorums = quorum_numbers;
    sorted_quorums.sort();

    let packed_bytes = ethabi::encode(&[
        Token::Uint(blob_version.into()), // BlobVersion
        Token::Bytes(
            sorted_quorums
                .iter()
                .flat_map(|q| q.to_be_bytes())
                .collect(),
        ), // SortedQuorums
        Token::Tuple(vec![
            // AbiBlobCommitments
            // Commitment
            Token::Tuple(vec![
                Token::Uint(U256::from_big_endian(&blob_commitments.commitment.x)), // commitment X
                Token::Uint(U256::from_big_endian(&blob_commitments.commitment.y)), // commitment Y
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
                    Token::Uint(U256::from_big_endian(
                        &blob_commitments.length_commitment.x_a1,
                    )),
                    Token::Uint(U256::from_big_endian(
                        &blob_commitments.length_commitment.x_a0,
                    )),
                ]),
                // Y
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(
                        &blob_commitments.length_commitment.y_a1,
                    )),
                    Token::Uint(U256::from_big_endian(
                        &blob_commitments.length_commitment.y_a0,
                    )),
                ]),
            ]),
            // Same as above
            // LengthProof
            Token::Tuple(vec![
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&blob_commitments.length_proof.x_a1)),
                    Token::Uint(U256::from_big_endian(&blob_commitments.length_proof.x_a0)),
                ]),
                Token::FixedArray(vec![
                    Token::Uint(U256::from_big_endian(&blob_commitments.length_proof.y_a1)),
                    Token::Uint(U256::from_big_endian(&blob_commitments.length_proof.y_a0)),
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
    blob_key
        .try_into()
        .map_err(|_| ConversionError::BlobKey("Failed to parse blob key".to_string()))
}
