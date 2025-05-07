use crate::errors::ConversionError;
use ethabi::Token;
use ethereum_types::U256;

use super::{
    generated::common::G1Commitment as DisperserG1Commitment,
    generated::disperser::{
        BatchHeader as DisperserBatchHeader, BatchMetadata as DisperserBatchMetadata,
        BlobHeader as DisperserBlobHeader, BlobInfo as DisperserBlobInfo,
        BlobQuorumParam as DisperserBlobQuorumParam,
        BlobVerificationProof as DisperserBlobVerificationProof,
    },
};

/// Represents the serialized coordinates of a G1 KZG commitment.
#[derive(Debug, PartialEq, Clone)]
pub struct G1Commitment {
    /// The X coordinate of the KZG commitment. This is the raw byte representation of the field element.
    /// Should contain 32 bytes.
    pub x: Vec<u8>,
    /// The Y coordinate of the KZG commitment. This is the raw byte representation of the field element.
    /// Should contain 32 bytes.
    pub y: Vec<u8>,
}

impl G1Commitment {
    fn to_tokens(&self) -> Vec<Token> {
        let x = Token::Uint(U256::from_big_endian(&self.x));
        let y = Token::Uint(U256::from_big_endian(&self.y));

        vec![x, y]
    }
}

impl From<DisperserG1Commitment> for G1Commitment {
    fn from(value: DisperserG1Commitment) -> Self {
        Self {
            x: value.x,
            y: value.y,
        }
    }
}

/// Internal of BlobInfo (aka EigenDACertV1)
/// Contains data related to the blob quorums
#[derive(Debug, PartialEq, Clone)]
pub struct BlobQuorumParam {
    /// The ID of the quorum.
    pub quorum_number: u8,
    /// The max percentage of stake within the quorum that can be held by or delegated to adversarial operators.
    pub adversary_threshold_percentage: u32,
    /// The min percentage of stake that must attest in order to consider the dispersal successful.
    pub confirmation_threshold_percentage: u32,
    /// The length of each chunk in bn254 field elements (32 bytes each).
    pub chunk_length: u32,
}

impl BlobQuorumParam {
    fn to_tokens(&self) -> Vec<Token> {
        let quorum_number = Token::Uint(U256::from(self.quorum_number));
        let adversary_threshold_percentage =
            Token::Uint(U256::from(self.adversary_threshold_percentage));
        let confirmation_threshold_percentage =
            Token::Uint(U256::from(self.confirmation_threshold_percentage));
        let chunk_length = Token::Uint(U256::from(self.chunk_length));

        vec![
            quorum_number,
            adversary_threshold_percentage,
            confirmation_threshold_percentage,
            chunk_length,
        ]
    }
}

impl TryFrom<DisperserBlobQuorumParam> for BlobQuorumParam {
    type Error = ConversionError;

    fn try_from(value: DisperserBlobQuorumParam) -> Result<Self, Self::Error> {
        let quorum_number = match value.quorum_number.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(ConversionError::Cast(format!(
                    "{} as u8",
                    value.quorum_number
                )))
            }
        };

        Ok(Self {
            quorum_number,
            adversary_threshold_percentage: value.adversary_threshold_percentage,
            confirmation_threshold_percentage: value.confirmation_threshold_percentage,
            chunk_length: value.chunk_length,
        })
    }
}

/// Internal of BlobInfo (aka EigenDACertV1)
/// Contains all metadata related to a blob including
/// commitment and parameters for encoding
#[derive(Debug, PartialEq, Clone)]
pub struct BlobHeader {
    /// KZG commitment of the blob
    pub commitment: G1Commitment,
    /// The length of the blob in symbols
    pub data_length: u32,
    /// The params of the quorums that this blob participates in
    pub blob_quorum_params: Vec<BlobQuorumParam>,
}

impl BlobHeader {
    pub fn to_tokens(&self) -> Vec<Token> {
        let commitment = self.commitment.to_tokens();
        let data_length = Token::Uint(U256::from(self.data_length));
        let blob_quorum_params = self
            .blob_quorum_params
            .clone()
            .into_iter()
            .map(|quorum| Token::Tuple(quorum.to_tokens()))
            .collect();

        vec![
            Token::Tuple(commitment),
            data_length,
            Token::Array(blob_quorum_params),
        ]
    }
}

impl TryFrom<DisperserBlobHeader> for BlobHeader {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobHeader) -> Result<Self, Self::Error> {
        let mut blob_quorum_params = vec![];
        for quorum in value.blob_quorum_params {
            blob_quorum_params.push(BlobQuorumParam::try_from(quorum)?);
        }
        Ok(Self {
            commitment: G1Commitment::from(
                value
                    .commitment
                    .ok_or(ConversionError::NotPresent("BlobHeader".to_string()))?,
            ),
            data_length: value.data_length,
            blob_quorum_params,
        })
    }
}

/// Contains the metadata associated with a Batch for which DA nodes must attest;
/// DA nodes sign on the hash of the batch header
#[derive(Debug, PartialEq, Clone)]
pub struct BatchHeader {
    /// The root of the merkle tree with the hashes of blob headers as leaves
    pub batch_root: Vec<u8>,
    /// All quorums associated with blobs in this batch. Sorted in ascending order
    pub quorum_numbers: Vec<u8>,
    /// The percentage of stake that has signed for this batch
    /// The `quorum_signed_percentages[i]` is percentage for the `quorum_numbers[i]`
    pub quorum_signed_percentages: Vec<u8>,
    /// The Ethereum block number at which the batch was created
    pub reference_block_number: u32,
}

impl BatchHeader {
    pub fn to_tokens(&self) -> Vec<Token> {
        let batch_root = Token::FixedBytes(self.batch_root.clone());
        let quorum_numbers = Token::Bytes(self.quorum_numbers.clone());
        let quorum_signed_percentages = Token::Bytes(self.quorum_signed_percentages.clone());
        let reference_block_number = Token::Uint(U256::from(self.reference_block_number));

        vec![
            batch_root,
            quorum_numbers,
            quorum_signed_percentages,
            reference_block_number,
        ]
    }
}

impl From<DisperserBatchHeader> for BatchHeader {
    fn from(value: DisperserBatchHeader) -> Self {
        Self {
            batch_root: value.batch_root,
            quorum_numbers: value.quorum_numbers,
            quorum_signed_percentages: value.quorum_signed_percentages,
            reference_block_number: value.reference_block_number,
        }
    }
}

/// Internal of BlobInfo (aka EigenDACertV1)
/// Metadata of a Batch
#[derive(Debug, PartialEq, Clone)]
pub struct BatchMetadata {
    /// Contains the metadata associated with a Batch for which DA nodes must attest
    pub batch_header: BatchHeader,
    /// The hash of all public keys of the operators that did not sign the batch
    pub signatory_record_hash: Vec<u8>,
    /// The fee payment paid by users for dispersing this batch
    pub fee: Vec<u8>,
    /// The Ethereum block number at which the batch is confirmed onchain
    pub confirmation_block_number: u32,
    /// The hash of the batch header
    pub batch_header_hash: Vec<u8>,
}

impl BatchMetadata {
    pub fn to_tokens(&self) -> Vec<Token> {
        let batch_header = Token::Tuple(self.batch_header.to_tokens());
        let signatory_record_hash = Token::FixedBytes(self.signatory_record_hash.clone());
        let confirmation_block_number = Token::Uint(U256::from(self.confirmation_block_number));
        let batch_header_hash = Token::Bytes(self.batch_header_hash.clone());
        let fee = Token::Bytes(self.fee.clone());

        vec![
            batch_header,
            signatory_record_hash,
            confirmation_block_number,
            batch_header_hash,
            fee,
        ]
    }
}

impl TryFrom<DisperserBatchMetadata> for BatchMetadata {
    type Error = ConversionError;
    fn try_from(value: DisperserBatchMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            batch_header: BatchHeader::from(
                value
                    .batch_header
                    .ok_or(ConversionError::NotPresent("BatchMetadata".to_string()))?,
            ),
            signatory_record_hash: value.signatory_record_hash,
            fee: value.fee,
            confirmation_block_number: value.confirmation_block_number,
            batch_header_hash: value.batch_header_hash,
        })
    }
}

/// Internal of BlobInfo (aka EigenDACertV1)
/// Proof of a blob certificate verification
#[derive(Debug, PartialEq, Clone)]
pub struct BlobVerificationProof {
    /// Incremental ID assigned to a batch by EigenDAServiceManager
    pub batch_id: u32,
    /// The index of the blob in the batch
    pub blob_index: u32,
    /// Metadata of the batch
    pub batch_medatada: BatchMetadata,
    /// Merkle proof for a blob header's inclusion in a batch
    pub inclusion_proof: Vec<u8>,
    /// Indexes of quorums in `batch_header.quorum_numbers` that match
    /// the quorums in `batch_header.blob_quorum_params`
    pub quorum_indexes: Vec<u8>,
}

impl BlobVerificationProof {
    pub fn to_tokens(&self) -> Vec<Token> {
        let batch_id = Token::Uint(U256::from(self.batch_id));
        let blob_index = Token::Uint(U256::from(self.blob_index));
        let batch_medatada = Token::Tuple(self.batch_medatada.to_tokens());
        let inclusion_proof = Token::Bytes(self.inclusion_proof.clone());
        let quorum_indexes = Token::Bytes(self.quorum_indexes.clone());

        vec![
            batch_id,
            blob_index,
            batch_medatada,
            inclusion_proof,
            quorum_indexes,
        ]
    }
}

impl TryFrom<DisperserBlobVerificationProof> for BlobVerificationProof {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobVerificationProof) -> Result<Self, Self::Error> {
        Ok(Self {
            batch_id: value.batch_id,
            blob_index: value.blob_index,
            batch_medatada: BatchMetadata::try_from(value.batch_metadata.ok_or(
                ConversionError::NotPresent("BlobVerificationProof".to_string()),
            )?)?,
            inclusion_proof: value.inclusion_proof,
            quorum_indexes: value.quorum_indexes,
        })
    }
}

/// Data returned by the disperser when a blob is dispersed
/// It contains a header with blob metadata and the proof of
/// the blob verification
#[derive(Debug, PartialEq, Clone)]
pub struct BlobInfo {
    pub blob_header: BlobHeader,
    pub blob_verification_proof: BlobVerificationProof,
}

impl BlobInfo {
    pub fn to_tokens(&self) -> Vec<Token> {
        let blob_header_tokens = self.blob_header.to_tokens();
        let blob_verification_proof_tokens = self.blob_verification_proof.to_tokens();

        vec![Token::Tuple(vec![
            Token::Tuple(blob_header_tokens),
            Token::Tuple(blob_verification_proof_tokens),
        ])]
    }
}

impl TryFrom<DisperserBlobInfo> for BlobInfo {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_header: BlobHeader::try_from(
                value
                    .blob_header
                    .ok_or(ConversionError::NotPresent("BlobInfo".to_string()))?,
            )?,
            blob_verification_proof: BlobVerificationProof::try_from(
                value
                    .blob_verification_proof
                    .ok_or(ConversionError::NotPresent("BlobInfo".to_string()))?,
            )?,
        })
    }
}
