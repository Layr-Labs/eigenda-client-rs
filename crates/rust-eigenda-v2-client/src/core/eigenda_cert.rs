use std::u16;

use ark_bn254::{G1Affine, G2Affine};
use ethabi::Token;
use ethereum_types::U256;
use tiny_keccak::{Hasher, Keccak};

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
// TODO: replace this dummy error with a proper error type
pub(crate) struct EigenDACertError;

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct G1Commitment {
    pub(crate) x: Vec<u8>,
    pub(crate) y: Vec<u8>,
}

impl TryFrom<Vec<u8>> for G1Commitment {
    type Error = EigenDACertError;

    // TODO: How many bytes does each field take?
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return Err(EigenDACertError);
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
    type Error = EigenDACertError;

    // TODO: How many bytes does each field take?
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 128 {
            return Err(EigenDACertError);
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
    pub fn hash(&self) -> Result<[u8; 32], EigenDACertError> {
        let cumulative_payment =
            U256::try_from(self.cumulative_payment.as_slice()).map_err(|_| EigenDACertError)?;
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
    commitment: G1Commitment,
    length_commitment: G2Commitment,
    length_proof: G2Commitment,
    length: u32,
}

impl TryFrom<ProtoBlobCommitment> for BlobCommitment {
    type Error = EigenDACertError;

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
pub(crate) struct V2BlobHeader {
    version: u16,
    quorum_numbers: Vec<u8>,
    commitment: BlobCommitment,
    payment_header_hash: [u8; 32],
}

impl TryFrom<ProtoBlobHeader> for V2BlobHeader {
    type Error = EigenDACertError;

    fn try_from(value: ProtoBlobHeader) -> Result<Self, Self::Error> {
        let version: u16 = match value.version.try_into() {
            Ok(version) => version,
            Err(_) => return Err(EigenDACertError),
        };

        let mut quorum_numbers: Vec<u8> = Vec::new();
        for number in value.quorum_numbers.iter() {
            quorum_numbers.push((*number).try_into().map_err(|_| EigenDACertError)?);
        }

        let commitment = BlobCommitment::try_from(value.commitment.ok_or(EigenDACertError)?)?;

        let payment_header_hash =
            PaymentHeader::from(value.payment_header.ok_or(EigenDACertError)?).hash()?;

        Ok(Self {
            version,
            quorum_numbers,
            commitment,
            payment_header_hash,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct V2BlobCertificate {
    blob_header: V2BlobHeader,
    signature: Vec<u8>,
    relay_keys: Vec<u32>,
}

impl TryFrom<ProtoBlobCertificate> for V2BlobCertificate {
    type Error = EigenDACertError;

    fn try_from(value: ProtoBlobCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_header: V2BlobHeader::try_from(value.blob_header.ok_or(EigenDACertError)?)?,
            signature: value.signature,
            relay_keys: value.relay_keys,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobInclusionInfo {
    blob_certificate: V2BlobCertificate,
    blob_index: u32,
    inclusion_proof: Vec<u8>,
}

impl TryFrom<ProtoBlobInclusionInfo> for BlobInclusionInfo {
    type Error = EigenDACertError;

    fn try_from(value: ProtoBlobInclusionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_certificate: V2BlobCertificate::try_from(
                value.blob_certificate.ok_or(EigenDACertError)?,
            )?,
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
    type Error = EigenDACertError;

    fn try_from(value: ProtoBatchHeader) -> Result<Self, Self::Error> {
        let batch_root: [u8; 32] = value.batch_root.try_into().map_err(|_| EigenDACertError)?;
        let reference_block_number = value
            .reference_block_number
            .try_into()
            .map_err(|_| EigenDACertError)?;
        Ok(Self {
            batch_root,
            reference_block_number,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct NonSignerStakesAndSignature {
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
pub(crate) struct EigenDACert {
    blob_inclusion_info: BlobInclusionInfo,
    batch_header: BatchHeaderV2,
    non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub(crate) fn new(
        blob_status_reply: BlobStatusReply,
        non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    ) -> Result<Self, EigenDACertError> {
        let binding_inclusion_info =
            BlobInclusionInfo::try_from(blob_status_reply.blob_inclusion_info.ok_or(EigenDACertError)?)?;

        let signed_batch = blob_status_reply.signed_batch.ok_or(EigenDACertError)?;
        let binding_batch_header = BatchHeaderV2::try_from(signed_batch.header.ok_or(EigenDACertError)?)?;

        let mut signed_quorum_numbers: Vec<u8> = Vec::new();
        for q in signed_batch.attestation.ok_or(EigenDACertError)?.quorum_numbers {
            signed_quorum_numbers.push(q.try_into().map_err(|_| EigenDACertError)?);
        }

        Ok(Self {
            blob_inclusion_info: binding_inclusion_info,
            batch_header: binding_batch_header,
            non_signer_stakes_and_signature,
            signed_quorum_numbers,
        })
    }

    /// Computes the blob_key of the blob that belongs to the EigenDACert
    pub(crate) fn compute_blob_key(&self) -> Result<BlobKey, EigenDACertError> {
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
            Err(_) => panic!("invalid blob key length: expected 32 bytes"),
        };
        Ok(blob_key)
    }
}

// BlobKey is the unique identifier for a blob dispersal.
//
// It is computed as the Keccak256 hash of some serialization of the blob header
// where the PaymentHeader has been replaced with Hash(PaymentHeader), in order
// to be easily verifiable onchain. See the BlobKey method of BlobHeader for more
// details.
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
) -> Result<Vec<u8>, EigenDACertError> {
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
    blob_key.try_into().map_err(|_| EigenDACertError)
}
