use ark_bn254::{Fr, G1Affine};

/// Proof is used to open a commitment. In the case of Kzg, this is also a kzg commitment, and is different from a Commitment only semantically.
pub type Proof = G1Affine;
/// Symbol is a symbol in the field used for polynomial commitments
pub type Symbol = Fr;

/// Frame is a chunk of data with the associated multi-reveal proof
pub struct Frame {
    /// proof is the multireveal proof corresponding to the chunk
    pub proof: Proof,
    // coeffs contains the coefficients of the interpolating polynomial of the chunk
    pub coeffs: Vec<Symbol>,
}

pub type ChunkNumber = usize;

#[derive(Clone)]
pub struct EncodingParams {
    pub(crate) num_chunks: u64, // number of total chunks that are padded to power of 2
    pub(crate) chunk_len: u64,  // number of Fr symbol stored inside a chunk
}
