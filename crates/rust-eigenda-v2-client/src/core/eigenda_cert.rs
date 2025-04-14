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
pub struct BlobHeader {
    pub(crate) version: u16,
    pub(crate) quorum_numbers: Vec<u8>,
    pub(crate) commitment: BlobCommitment,
    pub(crate) payment_header_hash: [u8; 32],
}

impl BlobHeader {
    pub fn blob_key(&self) -> Result<BlobKey, ConversionError> {
        BlobKey::compute_blob_key(self)
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

        BlobKey::compute_blob_key(&blob_header)
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use ark_ff::PrimeField;

    use crate::core::eigenda_cert::{BlobCommitment, BlobHeader, PaymentHeader};

    #[test]
    fn test_blob_key() {
        let commitment_x = Fq::from_be_bytes_mod_order(&[
            47, 227, 202, 245, 187, 25, 196, 187, 223, 98, 97, 40, 194, 244, 32, 4, 86, 33, 187, 1,
            12, 189, 12, 90, 30, 142, 112, 147, 146, 88, 249, 104,
        ]);
        let commitment_y = Fq::from_be_bytes_mod_order(&[
            20, 91, 31, 26, 187, 114, 156, 101, 50, 219, 233, 184, 99, 191, 205, 182, 6, 159, 229,
            182, 109, 197, 9, 213, 141, 125, 13, 219, 52, 178, 139, 146,
        ]);

        let length_commitment_x0 = Fq::from_be_bytes_mod_order(&[
            8, 65, 223, 70, 245, 141, 117, 195, 15, 108, 165, 232, 225, 16, 48, 241, 231, 234, 102,
            199, 125, 117, 21, 163, 169, 94, 92, 250, 30, 145, 48, 171,
        ]);
        let length_commitment_x1 = Fq::from_be_bytes_mod_order(&[
            39, 3, 247, 81, 154, 56, 239, 185, 210, 149, 195, 180, 108, 221, 16, 192, 77, 138, 32,
            157, 171, 219, 234, 248, 239, 93, 143, 126, 56, 204, 132, 102,
        ]);

        let length_commitment_y0 = Fq::from_be_bytes_mod_order(&[
            14, 234, 250, 97, 56, 209, 123, 188, 191, 0, 109, 187, 173, 92, 82, 77, 236, 38, 75,
            145, 102, 0, 177, 111, 42, 228, 130, 88, 227, 21, 3, 90,
        ]);
        let length_commitment_y1 = Fq::from_be_bytes_mod_order(&[
            13, 18, 145, 28, 229, 160, 11, 188, 145, 68, 148, 75, 22, 196, 32, 197, 2, 113, 249,
            176, 226, 81, 16, 168, 135, 74, 84, 143, 61, 183, 164, 42,
        ]);

        let length_proof_x0 = Fq::from_be_bytes_mod_order(&[
            4, 58, 192, 64, 99, 97, 56, 104, 197, 61, 137, 206, 145, 118, 143, 216, 15, 40, 191,
            251, 238, 37, 248, 97, 241, 136, 54, 180, 15, 235, 174, 42,
        ]);
        let length_proof_x1 = Fq::from_be_bytes_mod_order(&[
            35, 146, 74, 104, 5, 13, 42, 164, 44, 141, 107, 115, 154, 6, 65, 146, 27, 136, 169,
            149, 78, 27, 120, 242, 27, 172, 53, 196, 199, 133, 149, 205,
        ]);

        let length_proof_y0 = Fq::from_be_bytes_mod_order(&[
            14, 180, 121, 174, 188, 158, 3, 195, 182, 93, 117, 123, 138, 52, 168, 68, 157, 43, 93,
            68, 112, 237, 17, 72, 183, 227, 111, 102, 189, 137, 223, 43,
        ]);
        let length_proof_y1 = Fq::from_be_bytes_mod_order(&[
            31, 226, 236, 78, 97, 43, 93, 185, 199, 205, 181, 172, 68, 53, 100, 1, 200, 41, 56,
            150, 142, 207, 252, 194, 255, 160, 210, 92, 132, 123, 146, 191,
        ]);

        let commitments = BlobCommitment {
            commitment: G1Affine::new(commitment_x, commitment_y),
            length_commitment: G2Affine::new(
                Fq2::new(length_commitment_x0, length_commitment_x1),
                Fq2::new(length_commitment_y0, length_commitment_y1),
            ),
            length_proof: G2Affine::new(
                Fq2::new(length_proof_x0, length_proof_x1),
                Fq2::new(length_proof_y0, length_proof_y1),
            ),
            length: 64,
        };
        let payment_header = PaymentHeader {
            account_id: "0x0000000000000000000000000000000000000123".to_string(),
            timestamp: 5,
            cumulative_payment: num_bigint::BigInt::from(100).to_signed_bytes_be(),
        };
        let blob_header = BlobHeader {
            version: 0,
            quorum_numbers: vec![0, 1],
            commitment: commitments,
            payment_header_hash: payment_header.hash().unwrap(),
        };

        let blob_key = blob_header.blob_key().unwrap();
        // e2fc52cb6213041838c20164eac05a7660b741518d5c14060e47c89ed3dd175b has verified in solidity  with chisel
        assert_eq!(
            hex::encode(blob_key.to_bytes()),
            "e2fc52cb6213041838c20164eac05a7660b741518d5c14060e47c89ed3dd175b"
        );
    }
}
