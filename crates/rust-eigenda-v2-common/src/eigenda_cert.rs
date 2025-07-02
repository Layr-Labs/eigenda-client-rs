use ark_bn254::{G1Affine, G2Affine};
use serde::ser::Error;

use crate::{
    utils::{
        g1_commitment_from_bytes, g1_commitment_to_bytes, g2_commitment_from_bytes,
        g2_commitment_to_bytes,
    },
    ConversionError, EigenDACertError,
};

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
            .map_err(|e| S::Error::custom(format!("Conversion failed: {e}")))?
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
            .map_err(|e| S::Error::custom(format!("Conversion failed: {e}")))?
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

/// Contains all data necessary to retrieve and validate a [`Blob`]
///
/// This struct represents the composition of a EigenDA blob certificate, as it would exist in a rollup inbox.
#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct EigenDACert {
    pub blob_inclusion_info: BlobInclusionInfo,
    pub batch_header: BatchHeaderV2,
    pub non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    pub signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// Transforms the EigenDACert into bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, EigenDACertError> {
        bincode::serialize(self).map_err(|e| EigenDACertError::SerializationError(e.to_string()))
    }

    /// Builds a new EigenDACert from bytes using bincode
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EigenDACertError> {
        bincode::deserialize(bytes).map_err(|e| EigenDACertError::SerializationError(e.to_string()))
    }

    /// Encodes an EigenDACert into ABI-encoded bytes
    pub fn to_abi_encoded(&self) -> Result<Vec<u8>, ConversionError> {
        let cert_contract: EigenDACertV3Contract = self.clone().try_into()?;

        let encoded = cert_contract.abi_encode();

        Ok(encoded)
    }
}

use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use ark_ff::{BigInteger, PrimeField};
use ethabi::Token;
use tiny_keccak::{Hasher, Keccak};

alloy_sol_types::sol! {
    struct G1PointContract {
        uint256 X;
        uint256 Y;
    }

    struct G2PointContract {
        uint256[2] X;
        uint256[2] Y;
    }

    struct BlobInclusionInfoContract {
        BlobCertificateContract blobCertificate;
        uint32 blobIndex;
        bytes inclusionProof;
    }

    struct BlobCertificateContract {
        BlobHeaderV2Contract blobHeader;
        bytes signature;
        uint32[] relayKeys;
    }

    struct BlobHeaderV2Contract {
        uint16 version;
        bytes quorumNumbers;
        BlobCommitmentContract commitment;
        bytes32 paymentHeaderHash;
    }

    struct BlobCommitmentContract {
        G1PointContract commitment;
        G2PointContract lengthCommitment;
        G2PointContract lengthProof;
        uint32 length;
    }

    struct BatchHeaderV2Contract {
        bytes32 batchRoot;
        uint32 referenceBlockNumber;
    }

    struct NonSignerStakesAndSignatureContract {
        uint32[] nonSignerQuorumBitmapIndices;
        G1PointContract[] nonSignerPubkeys;
        G1PointContract[] quorumApks;
        G2PointContract apkG2;
        G1PointContract sigma;
        uint32[] quorumApkIndices;
        uint32[] totalStakeIndices;
        uint32[][] nonSignerStakeIndices;
    }

    struct EigenDACertV3Contract {
        BatchHeaderV2Contract batchHeader;
        BlobInclusionInfoContract blobInclusionInfo;
        NonSignerStakesAndSignatureContract nonSignerStakesAndSignature;
        bytes signedQuorumNumbers;
    }
}

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
        let cumulative_payment =
            ethabi::ethereum_types::U256::from(self.cumulative_payment.as_slice());
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

impl TryFrom<BlobCommitments> for BlobCommitmentContract {
    type Error = ConversionError;
    fn try_from(value: BlobCommitments) -> Result<Self, Self::Error> {
        let commitment = g1_contract_point_from_g1_affine(&value.commitment)?;
        let length_commitment = g2_contract_point_from_g2_affine(&value.length_commitment)?;
        let length_proof = g2_contract_point_from_g2_affine(&value.length_proof)?;
        let length = value.length;

        Ok(Self {
            commitment,
            lengthCommitment: length_commitment,
            lengthProof: length_proof,
            length,
        })
    }
}

impl TryFrom<BlobHeader> for BlobHeaderV2Contract {
    type Error = ConversionError;

    fn try_from(value: BlobHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            version: value.version,
            quorumNumbers: value.quorum_numbers.into(),
            commitment: value.commitment.clone().try_into()?,
            paymentHeaderHash: value.payment_header_hash.into(),
        })
    }
}

impl TryFrom<BlobCertificate> for BlobCertificateContract {
    type Error = ConversionError;

    fn try_from(value: BlobCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            blobHeader: value.blob_header.try_into()?,
            signature: value.signature.into(),
            relayKeys: value.relay_keys,
        })
    }
}

impl TryFrom<BlobInclusionInfo> for BlobInclusionInfoContract {
    type Error = ConversionError;

    fn try_from(value: BlobInclusionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blobCertificate: value.blob_certificate.try_into()?,
            blobIndex: value.blob_index,
            inclusionProof: value.inclusion_proof.clone().into(),
        })
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

/// SignedBatch is a batch of blobs with a signature.
pub struct SignedBatch {
    pub header: BatchHeaderV2,
    pub attestation: Attestation,
}

impl From<BatchHeaderV2> for BatchHeaderV2Contract {
    fn from(value: BatchHeaderV2) -> Self {
        Self {
            batchRoot: value.batch_root.into(),
            referenceBlockNumber: value.reference_block_number,
        }
    }
}

impl TryFrom<NonSignerStakesAndSignature> for NonSignerStakesAndSignatureContract {
    type Error = ConversionError;

    fn try_from(value: NonSignerStakesAndSignature) -> Result<Self, Self::Error> {
        let non_signer_pubkeys: Vec<G1PointContract> = value
            .non_signer_pubkeys
            .iter()
            .map(g1_contract_point_from_g1_affine)
            .collect::<Result<Vec<_>, _>>()?;

        let quorum_apks = value
            .quorum_apks
            .iter()
            .map(g1_contract_point_from_g1_affine)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            nonSignerQuorumBitmapIndices: value.non_signer_quorum_bitmap_indices.clone(),
            nonSignerPubkeys: non_signer_pubkeys,
            quorumApks: quorum_apks,
            apkG2: g2_contract_point_from_g2_affine(&value.apk_g2)?,
            sigma: g1_contract_point_from_g1_affine(&value.sigma)?,
            quorumApkIndices: value.quorum_apk_indices.clone(),
            totalStakeIndices: value.total_stake_indices.clone(),
            nonSignerStakeIndices: value.non_signer_stake_indices.clone(),
        })
    }
}

fn g2_contract_point_from_g2_affine(
    g2_affine: &G2Affine,
) -> Result<G2PointContract, ConversionError> {
    let xc1: [u8; 32] = g2_affine
        .x
        .c1
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G2Point("Could not convert from g2 core to g2 contract".to_string())
        })?;
    let xc0: [u8; 32] = g2_affine
        .x
        .c0
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G2Point("Could not convert from g2 core to g2 contract".to_string())
        })?;
    let yc1: [u8; 32] = g2_affine
        .y
        .c1
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G2Point("Could not convert from g2 core to g2 contract".to_string())
        })?;
    let yc0: [u8; 32] = g2_affine
        .y
        .c0
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G2Point("Could not convert from g2 core to g2 contract".to_string())
        })?;
    Ok(G2PointContract {
        X: [U256::from_be_bytes(xc1), U256::from_be_bytes(xc0)],
        Y: [U256::from_be_bytes(yc1), U256::from_be_bytes(yc0)],
    })
}

fn g1_contract_point_from_g1_affine(
    g1_affine: &G1Affine,
) -> Result<G1PointContract, ConversionError> {
    let x: [u8; 32] = g1_affine
        .x
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G1Point("Could not convert from g1 core to g1 contract".to_string())
        })?;
    let y: [u8; 32] = g1_affine
        .y
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| {
            ConversionError::G1Point("Could not convert from g1 core to g1 contract".to_string())
        })?;
    Ok(G1PointContract {
        X: U256::from_be_bytes(x),
        Y: U256::from_be_bytes(y),
    })
}

impl TryFrom<EigenDACert> for EigenDACertV3Contract {
    type Error = ConversionError;

    fn try_from(value: EigenDACert) -> Result<Self, Self::Error> {
        Ok(Self {
            batchHeader: value.batch_header.into(),
            blobInclusionInfo: value.blob_inclusion_info.try_into()?,
            nonSignerStakesAndSignature: value.non_signer_stakes_and_signature.try_into()?,
            signedQuorumNumbers: value.signed_quorum_numbers.into(),
        })
    }
}
