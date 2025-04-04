use ark_bn254::{G1Affine, G2Affine};
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
use crate::utils::{g1_commitment_from_bytes, g2_commitment_from_bytes};

use super::BlobKey;

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
        let cumulative_payment = U256::from(self.cumulative_payment.as_slice());
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
    pub(crate) commitment: G1Affine,
    pub(crate) length_commitment: G2Affine,
    pub(crate) length_proof: G2Affine,
    pub(crate) length: u32,
}

impl TryFrom<ProtoBlobCommitment> for BlobCommitment {
    type Error = ConversionError;

    fn try_from(value: ProtoBlobCommitment) -> Result<Self, Self::Error> {
        let commitment = g1_commitment_from_bytes(&value.commitment)?;
        let length_commitment = g2_commitment_from_bytes(&value.length_commitment)?;
        let length_proof = g2_commitment_from_bytes(&value.length_proof)?;
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
    version: u16,
    quorum_numbers: Vec<u8>,
    commitment: BlobCommitment,
    payment_header_hash: [u8; 32],
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
    blob_header: BlobHeader,
    signature: Vec<u8>,
    relay_keys: Vec<u32>,
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
    blob_certificate: BlobCertificate,
    blob_index: u32,
    inclusion_proof: Vec<u8>,
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
    batch_root: [u8; 32],
    reference_block_number: u32,
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
pub struct NonSignerStakesAndSignature {
    non_signer_quorum_bitmap_indices: Vec<u32>,
    non_signer_pubkeys: Vec<G1Affine>,
    quorum_apks: Vec<G1Affine>,
    apk_g2: G2Affine,
    sigma: G1Affine,
    quorum_apk_indices: Vec<u32>,
    total_stake_indices: Vec<u32>,
    non_signer_stake_indices: Vec<Vec<u32>>,
}

// EigenDACert contains all data necessary to retrieve and validate a blob
//
// This struct represents the composition of a eigenDA blob certificate, as it would exist in a rollup inbox.
#[derive(Debug, PartialEq, Clone)]
pub struct EigenDACert {
    blob_inclusion_info: BlobInclusionInfo,
    batch_header: BatchHeaderV2,
    non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub fn new(
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
    pub fn compute_blob_key(&self) -> Result<BlobKey, ConversionError> {
        let blob_header = self
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .clone();

        let blob_commitments = blob_header.commitment;

        BlobKey::compute_blob_key(
            blob_header.version,
            blob_commitments,
            blob_header.quorum_numbers,
            blob_header.payment_header_hash,
        )
    }
}
