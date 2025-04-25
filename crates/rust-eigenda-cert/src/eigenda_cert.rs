use ark_bn254::{G1Affine, G2Affine};
use ethabi::Token;
use ethereum_types::U256;
use serde::ser::Error;
use tiny_keccak::{Hasher, Keccak};

use crate::{
    commitment_utils::{
        g1_commitment_from_bytes, g1_commitment_to_bytes, g2_commitment_from_bytes,
        g2_commitment_to_bytes,
    },
    errors::{ConversionError, EigenDACertError},
};

use crate::core::BlobKey;

#[derive(Debug, PartialEq, Clone)]
/// PaymentHeader represents the header information for a blob
pub struct PaymentHeader {
    /// account_id is the ETH account address for the payer
    pub account_id: String,
    /// Timestamp represents the nanosecond of the dispersal request creation
    pub timestamp: i64,
    /// cumulative_payment represents the total amount of payment (in wei) made by the user up to this point
    pub cumulative_payment: Vec<u8>,
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
/// BlomCommitments contains the blob's commitment, degree proof, and the actual degree.
pub struct BlobCommitments {
    pub commitment: G1Affine,
    pub length_commitment: G2Affine,
    pub length_proof: G2Affine,
    pub length: u32,
}

/// Helper struct for BlobCommitments,
/// for simpler serialization, and deserialization
#[derive(serde::Serialize, serde::Deserialize)]
struct BlobCommitmentsHelper {
    commitment: Vec<u8>,
    length_commitment: Vec<u8>,
    length_proof: Vec<u8>,
    length: u32,
}

impl TryFrom<&BlobCommitments> for BlobCommitmentsHelper {
    type Error = ConversionError;

    fn try_from(b: &BlobCommitments) -> Result<Self, Self::Error> {
        Ok(BlobCommitmentsHelper {
            commitment: g1_commitment_to_bytes(&b.commitment)?,
            length_commitment: g2_commitment_to_bytes(&b.length_commitment)?,
            length_proof: g2_commitment_to_bytes(&b.length_proof)?,
            length: b.length,
        })
    }
}

impl TryFrom<BlobCommitmentsHelper> for BlobCommitments {
    type Error = ConversionError;

    fn try_from(helper: BlobCommitmentsHelper) -> Result<Self, Self::Error> {
        Ok(BlobCommitments {
            commitment: g1_commitment_from_bytes(&helper.commitment)?,
            length_commitment: g2_commitment_from_bytes(&helper.length_commitment)?,
            length_proof: g2_commitment_from_bytes(&helper.length_proof)?,
            length: helper.length,
        })
    }
}

impl serde::Serialize for BlobCommitments {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BlobCommitmentsHelper::try_from(self)
            .map_err(|e| S::Error::custom(format!("Conversion failed: {}", e)))?
            .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for BlobCommitments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = BlobCommitmentsHelper::deserialize(deserializer)?;
        Self::try_from(helper).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobHeader {
    pub version: u16,
    pub quorum_numbers: Vec<u8>,
    pub commitment: BlobCommitments,
    pub payment_header_hash: [u8; 32],
}

impl BlobHeader {
    pub fn blob_key(&self) -> Result<BlobKey, ConversionError> {
        BlobKey::compute_blob_key(self)
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
/// BlobCertificate contains a full description of a blob and how it is dispersed. Part of the certificate
/// is provided by the blob submitter (i.e. the blob header), and part is provided by the disperser (i.e. the relays).
/// Validator nodes eventually sign the blob certificate once they are in custody of the required chunks
/// (note that the signature is indirect; validators sign the hash of a Batch, which contains the blob certificate).
pub struct BlobCertificate {
    pub blob_header: BlobHeader,
    pub signature: Vec<u8>,
    pub relay_keys: Vec<u32>,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
/// BlobInclusionInfo is the information needed to verify the inclusion of a blob in a batch.
pub struct BlobInclusionInfo {
    pub blob_certificate: BlobCertificate,
    pub blob_index: u32,
    pub inclusion_proof: Vec<u8>,
}

/// SignedBatch is a batch of blobs with a signature.
pub struct SignedBatch {
    pub header: BatchHeaderV2,
    pub attestation: Attestation,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchHeaderV2 {
    pub batch_root: [u8; 32],
    pub reference_block_number: u32,
}

#[derive(Debug, PartialEq, Clone)]
pub struct NonSignerStakesAndSignature {
    pub non_signer_quorum_bitmap_indices: Vec<u32>,
    pub non_signer_pubkeys: Vec<G1Affine>,
    pub quorum_apks: Vec<G1Affine>,
    pub apk_g2: G2Affine,
    pub sigma: G1Affine,
    pub quorum_apk_indices: Vec<u32>,
    pub total_stake_indices: Vec<u32>,
    pub non_signer_stake_indices: Vec<Vec<u32>>,
}

/// Helper struct for serialization and deserialization of NonSignerStakesAndSignature
#[derive(serde::Serialize, serde::Deserialize)]
struct NonSignerStakesAndSignatureHelper {
    non_signer_quorum_bitmap_indices: Vec<u32>,
    non_signer_pubkeys: Vec<Vec<u8>>,
    quorum_apks: Vec<Vec<u8>>,
    apk_g2: Vec<u8>,
    sigma: Vec<u8>,
    quorum_apk_indices: Vec<u32>,
    total_stake_indices: Vec<u32>,
    non_signer_stake_indices: Vec<Vec<u32>>,
}

impl TryFrom<&NonSignerStakesAndSignature> for NonSignerStakesAndSignatureHelper {
    type Error = ConversionError;

    fn try_from(n: &NonSignerStakesAndSignature) -> Result<Self, Self::Error> {
        Ok(NonSignerStakesAndSignatureHelper {
            non_signer_quorum_bitmap_indices: n.non_signer_quorum_bitmap_indices.clone(),
            non_signer_pubkeys: n
                .non_signer_pubkeys
                .iter()
                .map(g1_commitment_to_bytes)
                .collect::<Result<_, _>>()?,
            quorum_apks: n
                .quorum_apks
                .iter()
                .map(g1_commitment_to_bytes)
                .collect::<Result<_, _>>()?,
            apk_g2: g2_commitment_to_bytes(&n.apk_g2)?,
            sigma: g1_commitment_to_bytes(&n.sigma)?,
            quorum_apk_indices: n.quorum_apk_indices.clone(),
            total_stake_indices: n.total_stake_indices.clone(),
            non_signer_stake_indices: n.non_signer_stake_indices.clone(),
        })
    }
}

impl TryFrom<NonSignerStakesAndSignatureHelper> for NonSignerStakesAndSignature {
    type Error = ConversionError;

    fn try_from(helper: NonSignerStakesAndSignatureHelper) -> Result<Self, Self::Error> {
        Ok(NonSignerStakesAndSignature {
            non_signer_quorum_bitmap_indices: helper.non_signer_quorum_bitmap_indices,
            non_signer_pubkeys: helper
                .non_signer_pubkeys
                .iter()
                .map(|b| g1_commitment_from_bytes(b))
                .collect::<Result<_, _>>()?,
            quorum_apks: helper
                .quorum_apks
                .iter()
                .map(|b| g1_commitment_from_bytes(b))
                .collect::<Result<_, _>>()?,
            apk_g2: g2_commitment_from_bytes(&helper.apk_g2)?,
            sigma: g1_commitment_from_bytes(&helper.sigma)?,
            quorum_apk_indices: helper.quorum_apk_indices,
            total_stake_indices: helper.total_stake_indices,
            non_signer_stake_indices: helper.non_signer_stake_indices,
        })
    }
}

impl serde::Serialize for NonSignerStakesAndSignature {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        NonSignerStakesAndSignatureHelper::try_from(self)
            .map_err(|e| S::Error::custom(format!("Conversion failed: {}", e)))?
            .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for NonSignerStakesAndSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = NonSignerStakesAndSignatureHelper::deserialize(deserializer)?;
        Self::try_from(helper).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Attestation {
    pub non_signer_pubkeys: Vec<G1Affine>,
    pub quorum_apks: Vec<G1Affine>,
    pub sigma: G1Affine,
    pub apk_g2: G2Affine,
    pub quorum_numbers: Vec<u32>,
}

// EigenDACert contains all data necessary to retrieve and validate a blob
//
// This struct represents the composition of a eigenDA blob certificate, as it would exist in a rollup inbox.
#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct EigenDACert {
    pub blob_inclusion_info: BlobInclusionInfo,
    pub batch_header: BatchHeaderV2,
    pub non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    pub signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// Computes the blob_key of the blob that belongs to the EigenDACert
    pub fn compute_blob_key(&self) -> Result<BlobKey, ConversionError> {
        let blob_header = self
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .clone();

        BlobKey::compute_blob_key(&blob_header)
    }

    /// Transforms the EigenDACert into bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, EigenDACertError> {
        bincode::serialize(self).map_err(|e| EigenDACertError::SerializationError(e.to_string()))
    }

    /// Builds a new EigenDACert from bytes using bincode
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EigenDACertError> {
        bincode::deserialize(bytes).map_err(|e| EigenDACertError::SerializationError(e.to_string()))
    }
}
