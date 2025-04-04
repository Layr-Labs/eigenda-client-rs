use crate::{core::PaymentMetadata, errors::ConversionError};
use ark_bn254::{G1Affine, G2Affine};

use super::BlobKey;

#[derive(Debug, PartialEq)]
pub struct BlobCommitment {
    pub(crate) commitment: G1Affine,
    pub(crate) length_commitment: G2Affine,
    pub(crate) length_proof: G2Affine,
    /// Length in field elements (32 bytes) of the blob. It must be a power of 2.
    pub(crate) data_length: usize,
}

impl BlobCommitment {
    pub fn new(
        commitment: G1Affine,
        length_commitment: G2Affine,
        length_proof: G2Affine,
        data_length: usize,
    ) -> Result<Self, String> {
        if data_length % 32 != 0 {
            return Err(format!(
                "data length ({} bytes) must be a multiple of 32",
                data_length,
            ));
        }
        Ok(Self {
            commitment,
            length_commitment,
            length_proof,
            data_length,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct BlobHeader {
    /// Blob version
    pub(crate) blob_version: u16,
    /// Contains the commitments for the blob.
    pub(crate) blob_commitments: BlobCommitment,
    /// Contains the quorums that the blob was dispersed to.
    pub(crate) quorum_numbers: Vec<u8>,
    /// Contains the payment information for the blob.
    pub(crate) payment_metadata: PaymentMetadata,
}

impl BlobHeader {
    pub fn blob_key(&self) -> Result<BlobKey, ConversionError> {
        let payment_metadata_hash = todo!();
        let blob_commitments = todo!();

        BlobKey::compute_blob_key(
            self.blob_version,
            blob_commitments,
            self.quorum_numbers,
            payment_metadata_hash,
        )
    }
}
