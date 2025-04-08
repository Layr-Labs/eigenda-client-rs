use std::{collections::HashMap, str::FromStr, sync::Arc};

use ark_bn254::{Fr, G1Affine};
use ark_ff::PrimeField;
use ethabi::{ParamType, Token};
use ethereum_types::U256;
use rust_kzg_bn254_primitives::traits::ReadPointFromBytes;
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::{
    core::{
        eigenda_cert::{BlobCommitment, BlobKey},
        BYTES_PER_SYMBOL,
    },
    errors::{
        AbiEncodeError, BlobError, ConversionError, EigenClientError, EthClientError,
        RetrievalClientError, TonicError,
    },
    eth_client::EthClient,
    generated::validator::{
        retrieval_client::RetrievalClient as GrpcRetrievalClient, GetChunksRequest,
    },
    utils::{u16_from_token, u32_from_token},
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
    _num_chunks: u64, // number of total chunks that are padded to power of 2
    _chunk_len: u64,  // number of Fr symbol stored inside a chunk
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

#[async_trait::async_trait]
impl RetrievalEthClient for EthClient {
    async fn get_all_versioned_blob_params(
        &self,
    ) -> Result<HashMap<u16, BlobVersionParameters>, RetrievalClientError> {
        // Solidity: function nextBlobVersion() view returns(uint16)
        let func_selector = ethabi::short_signature("nextBlobVersion", &[]);
        let data = func_selector.to_vec();
        let response_bytes = self
            .call(
                self.threshold_registry_addr,
                bytes::Bytes::copy_from_slice(&data),
                None,
            )
            .await?;
        let output_type = [ParamType::Uint(16)];

        let tokens =
            ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;

        // Safe unwrap because decode guarantees type correctness and non-empty output
        let next_blob_version_token = tokens.iter().next().unwrap();
        let next_blob_version = u16_from_token(next_blob_version_token)?;

        let mut blob_params = HashMap::new();
        for blob_version in 0..next_blob_version {
            // Solidity: function getBlobParams(uint16 version) view returns((uint32,uint32,uint8))
            let func_selector = ethabi::short_signature("getBlobParams", &[]);
            let mut data = func_selector.to_vec();
            let mut blob_version_token = Token::Uint(U256::from(blob_version))
                .into_bytes()
                .ok_or(AbiEncodeError::EncodeTokenAsBytes)?;
            data.append(&mut blob_version_token);

            let response_bytes = self
                .call(
                    self.threshold_registry_addr,
                    bytes::Bytes::copy_from_slice(&data),
                    None,
                )
                .await?;
            let output_type = [ParamType::Uint(32), ParamType::Uint(32), ParamType::Uint(8)];
            let tokens =
                ethabi::decode(&output_type, &response_bytes).map_err(EthClientError::EthAbi)?;
            let mut tokens_iter = tokens.iter();

            // Safe unwrap because decode guarantees type correctness and non-empty output
            let coding_rate_token = tokens_iter.next().unwrap();
            let max_num_operators_token = tokens_iter.next().unwrap();
            let num_chunks_token = tokens_iter.next().unwrap();
            blob_params.insert(
                blob_version.into(),
                BlobVersionParameters {
                    coding_rate: u32_from_token(coding_rate_token)?,
                    max_num_operators: u32_from_token(max_num_operators_token)?,
                    num_chunks: u32_from_token(num_chunks_token)?,
                },
            );
        }

        Ok(blob_params)
    }
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
    ) -> Result<(), RetrievalClientError>;

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: BlobCommitment,
    ) -> Result<(), RetrievalClientError>;

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        input_size: usize,
    ) -> Result<Vec<u8>, RetrievalClientError>;
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
            .verify_commit_equivalence_batch(blob_commitments.clone())
            .await?;

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
                )
                .await?;

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
            .map_err(EigenClientError::RetrievalClient)
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
        _num_chunks: blob_param.num_chunks as u64,
        _chunk_len: length as u64,
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
