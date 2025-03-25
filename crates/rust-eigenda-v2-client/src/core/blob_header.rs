use crate::core::PaymentMetadata;
use ark_bn254::{G1Affine, G2Affine};

#[derive(Debug, PartialEq, )]
pub struct BlobCommitment {
    commitment: G1Affine,
    length_commitment: G2Affine,
    length_proof: G2Affine,
    /// Length in field elements (32 bytes) of the blob. It must be a power of 2.
    data_length: usize,
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
    blob_version: u16,
    /// Contains the commitments for the blob.
    blob_commitments: Vec<BlobCommitment>,
    /// Contains the quorums that the blob was dispersed to.
    quorum_numbers: Vec<u8>,
    /// Contains the payment information for the blob.
    payment_metadata: PaymentMetadata,
}

impl BlobHeader {
    pub fn blob_key(&self) -> Result<BlobKey, String> {
        self.compute_blob_key()
    }

    fn compute_blob_key(&self) -> Result<BlobKey, String> {
        // should reuse compute_key from eigenDA cert PR 
        todo!()
    }
}

pub struct BlobKey;
