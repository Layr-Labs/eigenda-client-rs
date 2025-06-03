use ethereum_types::U256;
use std::collections::HashMap;

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

/// OperatorInfo contains information about an operator which is stored on the blockchain state,
/// corresponding to a particular quorum
#[derive(Clone, Debug)]
pub struct OperatorInfo {
    // Stake is the amount of stake held by the operator in the quorum
    pub(crate) stake: U256,
    // Index is the index of the operator within the quorum
    pub(crate) index: usize,
    // Socket is the socket address of the operator
    // Populated only when using GetOperatorStateWithSocket; otherwise it is an empty string
    pub(crate) socket: String,
}

#[derive(Clone, Debug)]
/// OperatorState contains information about the current state of operators which is stored in the blockchain state
pub struct OperatorState {
    /// Operators is a map from quorum ID to a map from the operators in that quorum to their StoredOperatorInfo. Membership
    /// in the map implies membership in the quorum.
    pub operators: HashMap<u8, HashMap<usize, OperatorInfo>>,
    /// Totals is a map from quorum ID to the total stake (Stake) and total count (Index) of all operators in that quorum
    pub totals: HashMap<u8, OperatorInfo>,
    /// BlockNumber is the block number at which this state was retrieved
    pub _block_number: usize,
}

#[derive(Clone, Debug)]
pub struct BlobVersionParameters {
    pub coding_rate: u32,
    pub max_num_operators: u32,
    pub num_chunks: u32,
}
