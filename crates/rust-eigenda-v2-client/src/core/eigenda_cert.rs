use alloy::primitives::U256 as AlloyU256;
use alloy::sol;
use alloy::sol_types::SolValue;
// This file contains the needed conversions from proto and contract types
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ethabi::Token;
use ethereum_types::U256;
use tiny_keccak::{Hasher, Keccak};

use crate::errors::{BlobError, ConversionError, EigenClientError};
use crate::generated::disperser::v2::{
    Attestation as ProtoAttestation, BlobStatusReply, SignedBatch as SignedBatchProto,
};

use crate::commitment_utils::g1_commitment_from_bytes;

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

use rust_eigenda_v2_common::{
    g2_commitment_from_bytes, BatchHeaderV2, BlobCertificate, BlobCommitments, BlobHeader,
    BlobInclusionInfo, EigenDACert, NonSignerStakesAndSignature,
};

sol! {
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

impl From<ProtoPaymentHeader> for PaymentHeader {
    fn from(value: ProtoPaymentHeader) -> Self {
        PaymentHeader {
            account_id: value.account_id,
            timestamp: value.timestamp,
            cumulative_payment: value.cumulative_payment,
        }
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

impl TryFrom<ProtoBlobCommitment> for BlobCommitments {
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

        let commitment = BlobCommitments::try_from(value.commitment.ok_or(
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

impl TryFrom<SignedBatchProto> for SignedBatch {
    type Error = ConversionError;

    fn try_from(value: SignedBatchProto) -> Result<Self, Self::Error> {
        let header = match value.header {
            Some(header) => BatchHeaderV2 {
                batch_root: header.batch_root.try_into().map_err(|_| {
                    ConversionError::SignedBatch("Failed parsing batch root".to_string())
                })?,
                reference_block_number: header.reference_block_number.try_into().map_err(|_| {
                    ConversionError::SignedBatch(
                        "Failed parsing reference block number".to_string(),
                    )
                })?,
            },
            None => return Err(ConversionError::SignedBatch("Header is None".to_string())),
        };

        let attestation = match value.attestation {
            Some(value) => value.try_into()?,
            None => {
                return Err(ConversionError::SignedBatch(
                    "Attestation is None".to_string(),
                ))
            }
        };

        Ok(Self {
            header,
            attestation,
        })
    }
}

impl From<BatchHeaderV2> for BatchHeaderV2Contract {
    fn from(value: BatchHeaderV2) -> Self {
        Self {
            batchRoot: value.batch_root.into(),
            referenceBlockNumber: value.reference_block_number,
        }
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

impl TryFrom<ProtoAttestation> for Attestation {
    type Error = ConversionError;

    fn try_from(value: ProtoAttestation) -> Result<Self, Self::Error> {
        Ok(Self {
            non_signer_pubkeys: value
                .non_signer_pubkeys
                .iter()
                .map(|p| g1_commitment_from_bytes(p))
                .collect::<Result<Vec<_>, _>>()?,
            quorum_apks: value
                .quorum_apks
                .iter()
                .map(|p| g1_commitment_from_bytes(p))
                .collect::<Result<Vec<_>, _>>()?,
            sigma: g1_commitment_from_bytes(&value.sigma)?,
            apk_g2: g2_commitment_from_bytes(&value.apk_g2)?,
            quorum_numbers: value.quorum_numbers,
        })
    }
}

pub(crate) fn build_cert_from_reply(
    blob_status_reply: &BlobStatusReply,
    non_signer_stakes_and_signature: NonSignerStakesAndSignature,
) -> Result<EigenDACert, EigenClientError> {
    let binding_inclusion_info = BlobInclusionInfo::try_from(
        blob_status_reply
            .blob_inclusion_info
            .clone()
            .ok_or(BlobError::MissingField("blob_inclusion_info".to_string()))?,
    )?;

    let signed_batch = blob_status_reply
        .signed_batch
        .clone()
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

    Ok(EigenDACert {
        blob_inclusion_info: binding_inclusion_info,
        batch_header: binding_batch_header,
        non_signer_stakes_and_signature,
        signed_quorum_numbers,
    })
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
        X: [AlloyU256::from_be_bytes(xc1), AlloyU256::from_be_bytes(xc0)],
        Y: [AlloyU256::from_be_bytes(yc1), AlloyU256::from_be_bytes(yc0)],
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
        X: AlloyU256::from_be_bytes(x),
        Y: AlloyU256::from_be_bytes(y),
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

/// Encodes an EigenDACert into ABI-encoded bytes
pub fn eigenda_cert_to_abi_encoded(cert: &EigenDACert) -> Result<Vec<u8>, ConversionError> {
    let cert_contract: EigenDACertV3Contract = cert.clone().try_into()?;

    let encoded = cert_contract.abi_encode();

    Ok(encoded)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use ark_ff::{BigInt, Fp2, PrimeField};
    use ethereum_types::H160;

    use crate::{
        cert_verifier::CertVerifier,
        core::{
            eigenda_cert::{
                build_cert_from_reply, BatchHeaderV2, BlobCertificate, BlobCommitments, BlobHeader,
                BlobInclusionInfo, PaymentHeader,
            },
            BlobKey,
        },
        generated::{
            common::{
                v2::{
                    BatchHeader as BatchHeaderProto, BlobCertificate as BlobCertificateProto,
                    BlobHeader as BlobHeaderProto, PaymentHeader as PaymentHeaderProto,
                },
                BlobCommitment as BlobCommitmentProto,
            },
            disperser::v2::{
                Attestation, BlobInclusionInfo as BlobInclusionInfoProto, SignedBatch,
            },
        },
        tests::{
            get_test_holesky_rpc_url, get_test_private_key_signer, CERT_VERIFIER_ROUTER_ADDRESS,
        },
    };

    use super::{BlobStatusReply, EigenDACert, NonSignerStakesAndSignature};

    fn get_test_reply() -> (BlobStatusReply, NonSignerStakesAndSignature) {
        let blob_status_reply = BlobStatusReply {
            signed_batch: Some(SignedBatch {
                header: Some(BatchHeaderProto {
                    batch_root: vec![
                        233, 19, 14, 15, 65, 33, 120, 11, 158, 216, 117, 11, 227, 47, 29, 155, 79,
                        182, 24, 94, 146, 218, 107, 168, 123, 102, 91, 170, 206, 53, 139, 120,
                    ],
                    reference_block_number: 3677228,
                }),
                attestation: Some(Attestation {
                    non_signer_pubkeys: vec![vec![
                        149, 116, 165, 233, 216, 150, 77, 230, 96, 225, 164, 64, 31, 105, 148, 81,
                        196, 61, 51, 216, 252, 183, 63, 121, 78, 173, 12, 22, 161, 96, 62, 209,
                    ]],
                    apk_g2: vec![
                        128, 240, 67, 205, 245, 139, 18, 92, 198, 206, 71, 79, 179, 90, 69, 162,
                        218, 199, 207, 74, 138, 102, 16, 185, 204, 246, 154, 154, 124, 148, 53,
                        211, 33, 22, 115, 242, 239, 223, 221, 73, 130, 66, 206, 2, 238, 161, 128,
                        140, 150, 135, 255, 137, 141, 213, 108, 114, 206, 30, 72, 81, 211, 242, 5,
                        81,
                    ],
                    sigma: vec![
                        204, 195, 219, 236, 124, 241, 73, 77, 182, 143, 252, 46, 168, 213, 195,
                        205, 174, 113, 109, 29, 5, 215, 39, 52, 229, 160, 163, 122, 233, 136, 5,
                        43,
                    ],
                    quorum_numbers: vec![0, 1],
                    quorum_signed_percentages: vec![80, 100],
                    quorum_apks: vec![
                        vec![
                            213, 80, 149, 82, 54, 82, 201, 67, 137, 35, 54, 247, 77, 10, 85, 54,
                            216, 249, 216, 213, 4, 27, 185, 120, 200, 109, 119, 219, 5, 38, 27, 0,
                        ],
                        vec![
                            149, 180, 60, 155, 181, 219, 189, 21, 124, 76, 206, 221, 182, 31, 35,
                            178, 11, 104, 1, 197, 178, 20, 16, 206, 61, 243, 11, 96, 200, 242, 2,
                            216,
                        ],
                    ],
                }),
            }),
            blob_inclusion_info: Some(BlobInclusionInfoProto {
                blob_certificate: Some(BlobCertificateProto {
                    blob_header: Some(BlobHeaderProto {
                        version: 0,
                        quorum_numbers: vec![0, 1],
                        commitment: Some(BlobCommitmentProto {
                            commitment: vec![
                                232, 2, 196, 90, 47, 44, 136, 140, 220, 190, 143, 211, 205, 225,
                                191, 16, 207, 168, 84, 185, 10, 94, 237, 61, 43, 217, 173, 222, 51,
                                240, 232, 208,
                            ],
                            length_commitment: vec![
                                148, 250, 45, 9, 249, 227, 179, 68, 60, 236, 203, 111, 184, 253,
                                98, 119, 216, 93, 227, 68, 79, 24, 237, 232, 114, 174, 94, 55, 57,
                                219, 223, 236, 19, 162, 109, 209, 5, 251, 122, 189, 110, 148, 207,
                                115, 135, 46, 187, 183, 224, 106, 195, 173, 71, 19, 64, 204, 222,
                                121, 46, 26, 9, 5, 207, 103,
                            ],
                            length_proof: vec![
                                164, 242, 183, 79, 135, 39, 163, 7, 205, 3, 117, 112, 14, 51, 32,
                                109, 225, 106, 139, 95, 30, 170, 141, 223, 234, 166, 196, 135, 89,
                                209, 191, 105, 39, 10, 17, 9, 148, 157, 81, 31, 16, 65, 3, 153,
                                149, 103, 207, 2, 243, 32, 46, 164, 209, 123, 18, 90, 216, 219,
                                115, 179, 28, 217, 65, 167,
                            ],
                            length: 64,
                        }),
                        payment_header: Some(PaymentHeaderProto {
                            account_id: "0xD9309b3CF1B7DBF59f53461c2a66e2783dD1766f".to_string(),
                            timestamp: 1744727058739877000,
                            cumulative_payment: vec![],
                        }),
                    }),
                    signature: vec![
                        168, 15, 169, 88, 137, 74, 179, 18, 3, 126, 94, 63, 143, 103, 188, 210, 49,
                        46, 135, 26, 105, 222, 214, 37, 128, 4, 228, 62, 188, 96, 144, 186, 119,
                        225, 173, 54, 9, 235, 152, 171, 108, 56, 209, 37, 220, 184, 124, 220, 79,
                        32, 8, 168, 171, 53, 1, 116, 168, 63, 109, 43, 34, 59, 66, 115, 0,
                    ],
                    relay_keys: vec![1, 2],
                }),
                blob_index: 0,
                inclusion_proof: vec![],
            }),
            status: 4,
        };

        let non_signer_pubkeys = vec![G1Affine::new(
            BigInt::from_str(
                "9704669172386967228841698723444408761927945332160049913630816478196003782353",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "3015390035914263831218138863592333251373169306354028727332933629302878348905",
            )
            .unwrap()
            .into(),
        )];

        let quorum_apks = vec![
            G1Affine::new(
                BigInt::from_str(
                    "9640948162073083414565750363679859421843464655523632220274628669727733848832",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "19643370125309743269553422865066622968340763429691280615064085723043238518365",
                )
                .unwrap()
                .into(),
            ),
            G1Affine::new(
                BigInt::from_str(
                    "9817020594633164190020731292959226780976321240116097510692294534725289247448",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "6543934278976149913385688504460018919257753414424306454948368312689483583934",
                )
                .unwrap()
                .into(),
            ),
        ];

        let apk_g2 = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "14965994889071619819446937262508283023425732847803582775082308126897001858385",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "424511265199836222171189838201654012504607225718840732994210815543791072723",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "10334432992602034872979025009842481721144509800260495829990482515621755075795",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "9841818323264649074514261459775280044000073958159617760595021082785845935923",
                )
                .unwrap()
                .into(),
            ),
        );

        let sigma = G1Affine::new(
            BigInt::from_str(
                "5773807218786325796539249080007257311780942381488879944227700219398473647403",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "18640028175250638736778274290057138634148717423467124530433456101853729482956",
            )
            .unwrap()
            .into(),
        );

        let non_signer_stakes_and_signature = NonSignerStakesAndSignature {
            non_signer_quorum_bitmap_indices: vec![20],
            non_signer_pubkeys,
            quorum_apks,
            apk_g2,
            sigma,
            quorum_apk_indices: vec![1746, 2176],
            total_stake_indices: vec![2310, 2442],
            non_signer_stake_indices: vec![vec![28], vec![]],
        };

        (blob_status_reply, non_signer_stakes_and_signature)
    }

    fn get_test_eigenda_cert() -> EigenDACert {
        let commitment = G1Affine::new(
            BigInt::from_str(
                "18097402811107380983985671453467841691840893735219410444705609758165039114448",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "16999158799766630235672780371511628484587074466180058883339027662416423479934",
            )
            .unwrap()
            .into(),
        );

        let length_commitment = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "8880931273186827351261965262476328318208931614937724042685885477123587952487",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "9488279585401480508933934734292808714637816354493020600238094832843399880684",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "9351449145134164501355679055588713512002655821146694096751192274844423102179",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "5865560055521561571799675834708494429719140059224985519677590504619849199063",
                )
                .unwrap()
                .into(),
            ),
        );

        let length_proof = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "17657987153373524011587225477415793193070321684460829118659094242192581542311",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "16712104702324673391829417082915453826023854019199011233132756277153391296361",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "20551952027861764477813347143115786861997666834655173209349588364117435832818",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "6669181637093186586935873308827307102680507380028905776710748175870382273671",
                )
                .unwrap()
                .into(),
            ),
        );

        let non_signer_pubkeys = vec![G1Affine::new(
            BigInt::from_str(
                "9704669172386967228841698723444408761927945332160049913630816478196003782353",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "3015390035914263831218138863592333251373169306354028727332933629302878348905",
            )
            .unwrap()
            .into(),
        )];

        let quorum_apks = vec![
            G1Affine::new(
                BigInt::from_str(
                    "9640948162073083414565750363679859421843464655523632220274628669727733848832",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "19643370125309743269553422865066622968340763429691280615064085723043238518365",
                )
                .unwrap()
                .into(),
            ),
            G1Affine::new(
                BigInt::from_str(
                    "9817020594633164190020731292959226780976321240116097510692294534725289247448",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "6543934278976149913385688504460018919257753414424306454948368312689483583934",
                )
                .unwrap()
                .into(),
            ),
        ];

        let apk_g2 = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "14965994889071619819446937262508283023425732847803582775082308126897001858385",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "424511265199836222171189838201654012504607225718840732994210815543791072723",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "10334432992602034872979025009842481721144509800260495829990482515621755075795",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "9841818323264649074514261459775280044000073958159617760595021082785845935923",
                )
                .unwrap()
                .into(),
            ),
        );

        let sigma = G1Affine::new(
            BigInt::from_str(
                "5773807218786325796539249080007257311780942381488879944227700219398473647403",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "18640028175250638736778274290057138634148717423467124530433456101853729482956",
            )
            .unwrap()
            .into(),
        );

        EigenDACert {
            blob_inclusion_info: BlobInclusionInfo {
                blob_certificate: BlobCertificate {
                    blob_header: BlobHeader {
                        version: 0,
                        quorum_numbers: vec![0, 1],
                        commitment: BlobCommitments {
                            commitment,
                            length_commitment,
                            length_proof,
                            length: 64,
                        },
                        payment_header_hash: [
                            99, 114, 16, 1, 243, 70, 66, 44, 180, 153, 204, 46, 153, 207, 150, 9,
                            74, 52, 71, 46, 38, 218, 196, 247, 84, 79, 185, 121, 213, 80, 162, 149,
                        ],
                    },
                    signature: vec![
                        168, 15, 169, 88, 137, 74, 179, 18, 3, 126, 94, 63, 143, 103, 188, 210, 49,
                        46, 135, 26, 105, 222, 214, 37, 128, 4, 228, 62, 188, 96, 144, 186, 119,
                        225, 173, 54, 9, 235, 152, 171, 108, 56, 209, 37, 220, 184, 124, 220, 79,
                        32, 8, 168, 171, 53, 1, 116, 168, 63, 109, 43, 34, 59, 66, 115, 0,
                    ],
                    relay_keys: vec![1, 2],
                },
                blob_index: 0,
                inclusion_proof: vec![],
            },
            batch_header: BatchHeaderV2 {
                batch_root: [
                    233, 19, 14, 15, 65, 33, 120, 11, 158, 216, 117, 11, 227, 47, 29, 155, 79, 182,
                    24, 94, 146, 218, 107, 168, 123, 102, 91, 170, 206, 53, 139, 120,
                ],
                reference_block_number: 3677228,
            },
            non_signer_stakes_and_signature: NonSignerStakesAndSignature {
                non_signer_quorum_bitmap_indices: vec![20],
                non_signer_pubkeys,
                quorum_apks,
                apk_g2,
                sigma,
                quorum_apk_indices: vec![1746, 2176],
                total_stake_indices: vec![2310, 2442],
                non_signer_stake_indices: vec![vec![28], vec![]],
            },
            signed_quorum_numbers: vec![0, 1],
        }
    }

    #[test]
    fn test_cert_serialization() {
        let cert = get_test_eigenda_cert();
        let cert_bytes = cert.to_bytes().unwrap();
        let deserialized = EigenDACert::from_bytes(&cert_bytes).unwrap();
        assert_eq!(cert, deserialized);
    }

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

        let commitments = BlobCommitments {
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

        let blob_key = BlobKey::compute_blob_key(&blob_header).unwrap();
        // e2fc52cb6213041838c20164eac05a7660b741518d5c14060e47c89ed3dd175b has verified in solidity  with chisel
        assert_eq!(
            hex::encode(blob_key.to_bytes()),
            "e2fc52cb6213041838c20164eac05a7660b741518d5c14060e47c89ed3dd175b"
        );
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_build_eigenda_cert() {
        let (blob_status_reply, non_signer_stakes_and_signature) = get_test_reply();
        let eigenda_cert =
            build_cert_from_reply(&blob_status_reply, non_signer_stakes_and_signature).unwrap();

        let expected_eigenda_cert = get_test_eigenda_cert();
        assert_eq!(expected_eigenda_cert, eigenda_cert);

        let cert_verifier = CertVerifier::new(
            H160::from_str(CERT_VERIFIER_ROUTER_ADDRESS).unwrap(),
            get_test_holesky_rpc_url(),
            get_test_private_key_signer(),
        )
        .unwrap();
        let res = cert_verifier.check_da_cert(&eigenda_cert).await;
        assert!(res.is_ok())
    }
}
