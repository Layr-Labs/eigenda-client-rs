use std::{collections::HashMap, str::FromStr, sync::Arc};

use ark_bn254::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ethereum_types::U256;
use rust_kzg_bn254_primitives::{helpers::pairings_verify, traits::ReadPointFromBytes};
use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::{
    core::{
        eigenda_cert::{BlobCommitment, BlobKey},
        BYTES_PER_SYMBOL,
    },
    errors::{
        BlobError, ConversionError, EigenClientError, RetrievalClientError, TonicError,
        VerifierError,
    },
    eth_client::EthClient,
    generated::validator::{
        retrieval_client::RetrievalClient as GrpcRetrievalClient, GetChunksRequest,
    },
};

// TODO: Relocate structs?

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

#[derive(Clone)]
pub struct Encoder {
    pub(crate) num_chunks: u64, // number of total chunks that are padded to power of 2
    pub(crate) chunk_len: u64,  // number of Fr symbol stored inside a chunk
}

impl Encoder {
    pub(crate) fn from_params(params: EncodingParams) -> Self {
        Self {
            num_chunks: params.num_chunks,
            chunk_len: params.chunk_len,
        }
    }

    pub(crate) fn num_evaluations(&self) -> u64 {
        self.num_chunks * self.chunk_len
    }

    // https://github.com/Layr-Labs/eigenda/blob/57a7b3b20907dfe0f46dc534a0d2673203e69267/encoding/rs/interpolation.go#L19
    pub(crate) fn get_interpolation_poly_eval(&self, interpolation_poly: &[Fr], j: usize) -> Vec<Fr> {
        unimplemented!()
    }

    fn zero_poly_via_multiplication(&self, missing_indices: Vec<usize>, length: u64) -> (Vec<Fr>, Vec<Fr>) {
        unimplemented!()
    }

    pub(crate) fn recover_poly_from_samples(&self, samples: Vec<Fr>) -> Vec<Fr> {
        // TODO: using a single additional temporary array, all the FFTs can run in-place.

        // TODO: received samples will change for a Vec<Option<Fr>>
        let mut missing_indices = Vec::new();
        for (i, sample) in samples.iter().enumerate() {
            if *sample == Fr::default() {
                missing_indices.push(i);
            }
        };

        let (zero_eval, zero_poly) = self.zero_poly_via_multiplication(missing_indices, samples.len() as u64);

        for (i, sample) in samples.iter().enumerate() {
            let eval_at_i = zero_eval[i];
            panic!("check if zero")
        };

        unimplemented!()

	}

    pub(crate) fn fft(&self, data: Vec<Fr>) -> Vec<Fr> {
        unimplemented!()
    }
}

pub struct BlobVersionParameters {
    coding_rate: u32,
    max_num_operators: u32,
    num_chunks: u32,
}

/// Trait that defines the methods for the eth_client used by the retrieval client
#[async_trait::async_trait]
pub trait RetrievalEthClient: Sync + Send + std::fmt::Debug {
    async fn get_all_versioned_blob_params(
        &self,
    ) -> Result<HashMap<u16, BlobVersionParameters>, RetrievalClientError>;
}

/// OperatorState contains information about the current state of operators which is stored in the blockchain state
pub struct OperatorState {
    // Operators is a map from quorum ID to a map from the operators in that quorum to their StoredOperatorInfo. Membership
    // in the map implies membership in the quorum.
    operators: HashMap<u8, HashMap<usize, OperatorInfo>>,
    // Totals is a map from quorum ID to the total stake (Stake) and total count (Index) of all operators in that quorum
    totals: HashMap<u8, OperatorInfo>,
    // BlockNumber is the block number at which this state was retrieved
    _block_number: usize,
}

/// Trait that defines the methods for the chain_state used by the retrieval client
#[async_trait::async_trait]
pub trait RetrievalChainStateProvider: Sync + Send + std::fmt::Debug {
    async fn get_operator_state_with_socket(
        &self,
        block_number: u64,
        quorums: Vec<u8>,
    ) -> Result<OperatorState, RetrievalClientError>;
}

/// Trait that defines the methods for the verifier used by the retrieval client
#[async_trait::async_trait]
pub trait RetrievalVerifier: Sync + Send + std::fmt::Debug {
    async fn verify_frames(
        &self,
        chunks: &[Frame],
        indices: &[ChunkNumber],
        commitments: BlobCommitment,
        params: EncodingParams,
        kzg: KZG,
        srs: SRS,
    ) -> Result<(), VerifierError>;

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: Vec<BlobCommitment>,
    ) -> Result<(), VerifierError>;

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        max_input_size: usize,
    ) -> Result<Vec<u8>, VerifierError>;
}

/// Serializes a slice of field elements to a vector of bytes in big-endian format.
/// The resulting byte vector's length will not exceed `max_data_size`.
fn to_byte_array(data_fr: &[Fr], max_data_size: usize) -> Vec<u8> {
    let bytes_per_symbol = Fr::MODULUS_BIT_SIZE as usize / 8;
    let mut data = Vec::with_capacity(data_fr.len() * bytes_per_symbol);

    for &element in data_fr.iter() {
        let mut bytes = element.into_bigint().to_bytes_be(); // Get big-endian byte representation
                                                             // Ensure the byte array is exactly `bytes_per_symbol` in length
        if bytes.len() < bytes_per_symbol {
            let padding = vec![0u8; bytes_per_symbol - bytes.len()];
            bytes = [padding, bytes].concat();
        }
        data.extend_from_slice(&bytes);
        if data.len() >= max_data_size {
            data.truncate(max_data_size);
            break;
        }
    }

    data
}

#[async_trait::async_trait]
impl RetrievalVerifier for EthClient {
    async fn verify_frames(
        &self,
        frames: &[Frame],
        indices: &[ChunkNumber],
        commitments: BlobCommitment,
        params: EncodingParams,
        kzg: KZG,
        srs: SRS,
    ) -> Result<(), VerifierError> {
        if frames.len() != indices.len() {
            panic!(
                "invalid number of frames and indices: {} != {}",
                frames.len(),
                indices.len()
            );
        }

        for (i, frame) in frames.iter().enumerate() {
            let j = match (indices[i] as u64) < params.num_chunks {
                true => {
                    // Equivalent of: ReverseBitsLimited(uint32(numChunks), uint32(i)) in go
                    let length = params.num_chunks;
                    let value = indices[i];
                    let used_bits = 32 - length.leading_zeros();
                    let unused_bit_len = 32 - used_bits;
                    value.reverse_bits() >> unused_bit_len
                }
                false => panic!("cannot create number of frame higher than possible"),
            };

            let n = frame.coeffs.len();
            if n >= srs.order as usize {
                panic!(
                    "requested power {} is larger than SRSOrder {}",
                    n, srs.order
                );
            }
            // TODO: should be: kzg.get_g2_points()[n];
            // But we don't have access to this method with the new kzg/srs structs
            let g2_at_n = G2Affine::default();

            let commitment = commitments.commitment;

            // TODO: We might not be using the expanded roots of unity here.
            // maybe use directly: `calculate_roots_of_unity` with a correct value
            // for `length_of_data_after_padding`.
            // line bellow might panic due to index out of bounds:
            let x = &kzg.get_roots_of_unities()[j];

            let mut x_pow = Fr::ONE;
            for _ in 0..frame.coeffs.len() {
                x_pow *= x
            }

            // [x^n]_2
            let xn2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y)
                .mul_bigint(x_pow.into_bigint());

            // [s^n - x^n]_2
            let xn_minus_yn = (g2_at_n - xn2).into_affine();

            // [interpolation_polynomial(s)]_1
            let srs_g1 = srs.g1[0..frame.coeffs.len()].to_vec();
            let is1 = G1Projective::msm(&srs_g1, &frame.coeffs)
                .unwrap()
                .into_affine();

            // [commitment - interpolation_polynomial(s)]_1 = [commit]_1 - [interpolation_polynomial(s)]_1
            let commit_minus_interpolation = (commitment - is1).into_affine();

            // Verify the pairing equation
            //
            // e([commitment - interpolation_polynomial(s)], [1]) = e([proof],  [s^n - x^n])
            //    equivalent to
            // e([commitment - interpolation_polynomial]^(-1), [1]) * e([proof],  [s^n - x^n]) = 1_T
            //
            let kzg_gen_g2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y);
            if !pairings_verify(
                commit_minus_interpolation,
                kzg_gen_g2,
                frame.proof,
                xn_minus_yn,
            ) {
                return Err(VerifierError::FailedToVerifyCommitEquivalenceBatch);
            };
        }

        Ok(())
    }

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: Vec<BlobCommitment>,
    ) -> Result<(), VerifierError> {
        let commitments_amount = commitments.len();
        let mut g1commits = Vec::new();
        let mut g2commits = Vec::new();

        for blob_commitment in commitments {
            g1commits.push(blob_commitment.commitment);
            g2commits.push(blob_commitment.length_commitment);
        }

        let mut random_scalars = Vec::new();
        for _ in 0..commitments_amount {
            random_scalars.push(Fr::rand(&mut rand::thread_rng())); // TODO: USE OTHER RNG!
        }

        let lhs_g1 = G1Projective::msm(&g1commits, &random_scalars)
            .unwrap()
            .into_affine();
        let lhs_g2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y);
        let rhs_g1 = G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
        let rhs_g2 = G2Projective::msm(&g2commits, &random_scalars)
            .unwrap()
            .into_affine();

        if !pairings_verify(lhs_g1, lhs_g2, rhs_g1, rhs_g2) {
            return Err(VerifierError::FailedToVerifyCommitEquivalenceBatch);
        };
        Ok(())
    }

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        max_input_size: usize,
    ) -> Result<Vec<u8>, VerifierError> {
        let encoder = Encoder::from_params(params);
        let mut frames = Vec::new();
        for chunk in chunks {
            frames.push(chunk.coeffs);
        }

        let chunk_len = encoder.chunk_len as usize;
        let data_len = (max_input_size + chunk_len - 1) / chunk_len;
        let num_sys = data_len / chunk_len;
        if frames.len() < num_sys {
            panic!("number of frame must be sufficient")
        }

        let mut samples: Vec<Fr> = vec![Fr::default(); encoder.num_evaluations() as usize];
        // copy evals based on frame coeffs into samples
        for (i, chunk_number) in indices.iter().enumerate() {
            let frame = frames[i].clone();
            let e = match *chunk_number < encoder.num_chunks as usize {
                true => {
                    let value = *chunk_number;
                    let bit_index = if encoder.num_chunks == 0 {
                        0
                    } else {
                        32 - (encoder.num_chunks - 1).leading_zeros()
                    };
                    let unused_bit_len = 32 - bit_index;
                    value.reverse_bits() >> unused_bit_len
                }
                false => panic!("cannot create number of frame higher than possible"),
            };

            let evals = encoder.get_interpolation_poly_eval(&frame, e);

            // Some pattern i butterfly swap. Find the leading coset, then increment by number of coset
            for j in 0..chunk_len {
                let p = j * encoder.num_chunks as usize + e;
                samples.insert(p, evals[j]);
            }
        }

        // We assume that if any Fr is still default after filling data,
        // then there are missing Frs.
        // TODO: change samples: Vec<Fr> for Vec<Option<Fr>>
        let reconstructed_data = match samples.iter().any(|sample| *sample == Fr::default()) {
            true => encoder.recover_poly_from_samples(samples),
            false => samples.clone(),
        };

        let reconstructed_poly = encoder.fft(reconstructed_data);

        Ok(to_byte_array(&reconstructed_poly, max_input_size))
    }
}

/// RetrievalClient can retrieve blobs from the DA nodes.
/// To retrieve a blob from the relay, use RelayClient instead.
pub struct RetrievalClient<
    E: RetrievalEthClient,
    C: RetrievalChainStateProvider,
    V: RetrievalVerifier,
> {
    client: Arc<Mutex<GrpcRetrievalClient<Channel>>>,
    eth_client: E,
    chain_state: C,
    verifier: V,
}

impl<E: RetrievalEthClient, C: RetrievalChainStateProvider, V: RetrievalVerifier>
    RetrievalClient<E, C, V>
{
    pub async fn new(
        eth_client: E,
        chain_state: C,
        verifier: V,
        grpc_endpoint_url: &str,
    ) -> Result<Self, RetrievalClientError> {
        let endpoint = Endpoint::from_str(grpc_endpoint_url)
            .map_err(TonicError::TransportError)?
            .tls_config(ClientTlsConfig::new())
            .map_err(TonicError::TransportError)?;
        let client = Arc::new(Mutex::new(
            GrpcRetrievalClient::connect(endpoint)
                .await
                .map_err(TonicError::TransportError)?,
        ));

        Ok(Self {
            client,
            eth_client,
            chain_state,
            verifier,
        })
    }

    pub async fn get_blob(
        &self,
        blob_key: BlobKey,
        blob_version: u16,
        blob_commitments: BlobCommitment,
        reference_block_number: u64,
        quorum_id: u8,
    ) -> Result<Vec<u8>, EigenClientError> {
        self.verifier
            .verify_commit_equivalence_batch(vec![blob_commitments.clone()])
            .await
            .map_err(RetrievalClientError::VerifierError)?;

        let operator_state = self
            .chain_state
            .get_operator_state_with_socket(reference_block_number, vec![quorum_id])
            .await?;
        let operators = operator_state
            .operators
            .get(&quorum_id)
            .ok_or(RetrievalClientError::MissingOperator(quorum_id))?;

        let blob_versions = self.eth_client.get_all_versioned_blob_params().await?;
        let blob_param = blob_versions
            .get(&blob_version)
            .ok_or(RetrievalClientError::MissingBlobVersionParams(blob_version))?;

        let encoding_params = get_encoding_params(blob_commitments.length, blob_param)?;

        let assignments = get_assignments(&operator_state, blob_param, quorum_id)?;

        // Fetch chunks from all operators
        let mut replies: Vec<RetrievedChunks> = Vec::new();
        for op_id in 0..operators.len() {
            // TODO: this is done with a worker pool in go's client
            // We should work on a more parallelized implementation.
            let retrieved_chunk = self
                .get_chunks_from_operator(op_id, blob_key, quorum_id)
                .await?;
            replies.push(retrieved_chunk);
        }

        let mut chunks: Vec<Frame> = Vec::new();
        let mut indices: Vec<ChunkNumber> = Vec::new();
        for _ in 0..operators.len() {
            let reply = replies.remove(0);

            let assignment = assignments
                .get(&reply.operator_id)
                .ok_or(RetrievalClientError::MissingAssignment(reply.operator_id))?;

            let assignment_indices = assignment.get_indices();

            self.verifier
                .verify_frames(
                    &reply.chunks,
                    &assignment_indices,
                    blob_commitments.clone(),
                    encoding_params.clone(),
                    KZG::new(),                  // TODO: IMPLEMENT
                    SRS::new("", 0, 0).unwrap(), // TODO: IMPLEMENT
                )
                .await
                .map_err(RetrievalClientError::VerifierError)?;

            chunks.extend(reply.chunks);
            indices.extend(assignment_indices);
        }

        if chunks.is_empty() {
            return Err(RetrievalClientError::EmptyChunksResponse.into());
        }

        self.verifier
            .decode(
                chunks,
                indices,
                encoding_params,
                blob_commitments.length as usize * BYTES_PER_SYMBOL,
            )
            .await
            .map_err(|e| EigenClientError::RetrievalClient(e.into()))
    }

    pub async fn get_chunks_from_operator(
        &self,
        op_id: usize,
        blob_key: BlobKey,
        quorum_id: u8,
    ) -> Result<RetrievedChunks, EigenClientError> {
        let request = GetChunksRequest {
            blob_key: blob_key.to_vec(),
            quorum_id: quorum_id as u32,
        };
        let reply = self
            .client
            .lock()
            .await
            .get_chunks(request)
            .await
            .map_err(|e| RetrievalClientError::Tonic(TonicError::StatusError(e)))?
            .into_inner();

        if reply.chunk_encoding_format == 0 {
            return Err(RetrievalClientError::EncodingFormatUnkown.into());
        }

        let mut chunks = Vec::new();
        for chunk in reply.chunks {
            let frame = deserialize_gnark(chunk).map_err(EigenClientError::Conversion)?;
            chunks.push(frame);
        }

        Ok(RetrievedChunks {
            operator_id: op_id,
            chunks,
        })
    }
}

pub struct RetrievedChunks {
    operator_id: usize,
    chunks: Vec<Frame>,
}

/// OperatorInfo contains information about an operator which is stored on the blockchain state,
/// corresponding to a particular quorum
#[derive(Clone)]
pub struct OperatorInfo {
    // Stake is the amount of stake held by the operator in the quorum
    stake: U256,
    // Index is the index of the operator within the quorum
    index: usize,
    // Socket is the socket address of the operator
    // Populated only when using GetOperatorStateWithSocket; otherwise it is an empty string
    _socket: String,
}

fn get_encoding_params(
    length: u32,
    blob_param: &BlobVersionParameters,
) -> Result<EncodingParams, BlobError> {
    let length = get_chunk_length(length, blob_param)?;

    Ok(EncodingParams {
        num_chunks: blob_param.num_chunks as u64,
        chunk_len: length as u64,
    })
}

fn get_chunk_length(length: u32, blob_param: &BlobVersionParameters) -> Result<u32, BlobError> {
    if length == 0 {
        return Err(BlobError::InvalidBlobLengthZero);
    }

    if blob_param.num_chunks == 0 {
        return Err(BlobError::EmptyChunks);
    }

    if !length.is_power_of_two() {
        return Err(BlobError::InvalidBlobLengthNotPowerOfTwo(length as usize));
    }

    let mut chunk_length = length.saturating_mul(blob_param.coding_rate) / blob_param.num_chunks;
    if chunk_length == 0 {
        chunk_length = 1;
    }

    Ok(chunk_length)
}

// Assignment contains information about the set of chunks that a specific node will receive
pub struct Assignment {
    start_index: usize,
    num_chunks: usize,
}

impl Assignment {
    /// get_indices generates the list of ChunkNumber associated with a given assignment
    pub fn get_indices(&self) -> Vec<ChunkNumber> {
        let mut indices = Vec::new();
        for ind in 0..self.num_chunks {
            indices.push(self.start_index + ind);
        }
        indices
    }
}

fn get_assignments(
    state: &OperatorState,
    blob_param: &BlobVersionParameters,
    quorum_id: u8,
) -> Result<HashMap<usize, Assignment>, RetrievalClientError> {
    let operators = state
        .operators
        .get(&quorum_id)
        .ok_or(RetrievalClientError::MissingOperator(quorum_id))?;

    let num_operators = operators.len();
    if num_operators > blob_param.max_num_operators as usize {
        return Err(RetrievalClientError::TooManyOperators(
            num_operators,
            blob_param.max_num_operators as usize,
        ));
    }

    // TODO: Maybe not very "rusty" to have a struct defined inside a fn call
    struct OperatorAssignment {
        pub op_id: usize,
        pub index: u32,
        pub chunks: u32,
        pub stake: U256,
    }

    let total_stake = state
        .totals
        .get(&quorum_id)
        .ok_or(RetrievalClientError::MissingTotalStake(quorum_id))?
        .stake;

    // Calculate number of chunks - num_operators once and reuse
    let diff_chunks_ops = U256::from(blob_param.num_chunks as usize - num_operators);
    let mut chunk_assignments: Vec<OperatorAssignment> = Vec::new();

    // Calculate initial chunk assignments based on stake
    let mut total_calculated_chunks = 0;
    for (op_id, operator) in operators.iter() {
        // Calculate chunks for this operator: (stake * (numChunks - numOperators)) / totalStake (rounded up)
        let num = operator.stake * diff_chunks_ops;
        // chunks is calculated by rounding up ((a + b - 1) / b)
        let chunks = ((num + total_stake - U256::one()) / total_stake)
            .try_into()
            .map_err(|e: &str| RetrievalClientError::InvalidChunks(e.to_string()))?;

        chunk_assignments.push(OperatorAssignment {
            op_id: *op_id,
            index: operator.index as u32,
            chunks,
            stake: operator.stake,
        });

        total_calculated_chunks += chunks;
    }

    // Sort by stake (decreasing) with index as tie-breaker
    chunk_assignments.sort_by(|a, b| b.stake.cmp(&a.stake).then(b.index.cmp(&a.index)));

    // Distribute any remaining chunks
    let (delta, underflow) = blob_param
        .num_chunks
        .overflowing_sub(total_calculated_chunks);
    if underflow {
        return Err(RetrievalClientError::InvalidChunks(format!(
            "total chunks {} exceeds maximun {}",
            total_calculated_chunks, blob_param.num_chunks
        )));
    }

    let mut assignments = HashMap::new();
    let mut index = 0;

    for (i, assignment) in chunk_assignments.iter_mut().enumerate() {
        // Add remaining chunks to operators with highest stake first
        if i < delta as usize {
            assignment.chunks += 1;
        }

        // Always add operators to the assignments map, even with zero chunks
        assignments.insert(
            assignment.op_id,
            Assignment {
                start_index: index,
                num_chunks: assignment.chunks as usize,
            },
        );
        index += assignment.chunks as usize;
    }

    Ok(assignments)
}

const SIZE_OF_G1_AFFINE_COMPRESSED: usize = 32;

fn deserialize_gnark(data: Vec<u8>) -> Result<Frame, ConversionError> {
    if data.len() <= SIZE_OF_G1_AFFINE_COMPRESSED {
        return Err(ConversionError::G1Point("Invalid data length".to_string()));
    }

    let proof = G1Affine::read_point_from_bytes_be(&data[0..SIZE_OF_G1_AFFINE_COMPRESSED])
        .map_err(|e| ConversionError::G1Point(e.to_string()))?;

    if (data.len() - SIZE_OF_G1_AFFINE_COMPRESSED) % BYTES_PER_SYMBOL != 0 {
        return Err(ConversionError::G1Point("Invalid chunk length".to_string()));
    }

    let mut coeffs = Vec::new();
    for bytes in data[SIZE_OF_G1_AFFINE_COMPRESSED..].chunks(BYTES_PER_SYMBOL) {
        coeffs.push(Fr::from_be_bytes_mod_order(bytes));
    }

    Ok(Frame { proof, coeffs })
}
