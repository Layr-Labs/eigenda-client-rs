use crate::eth_client::RpcErrorResponse;

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    RetrievalClient(#[from] RetrievalClientError),
}

/// Errors specific to Eth Abi encoding and decoding
#[derive(Debug, thiserror::Error)]
pub enum AbiEncodeError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Invalid token type: {0}")]
    InvalidTokenType(String),
    #[error("Could not encode token as bytes")]
    EncodeTokenAsBytes,
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse payload: {0}")]
    Payload(String),
    #[error("Failed to parse payment header: {0}")]
    PaymentHeader(String),
    #[error("Failed to parse encoded payload: {0}")]
    EncodedPayload(String),
    #[error("Failed to convert polynomial: {0}")]
    Poly(String),
    #[error("Failed to parse G1 point: {0}")]
    G1Point(String),
    #[error("Failed to parse G2 point: {0}")]
    G2Point(String),
    #[error("Failed to parse blob header: {0}")]
    BlobHeader(String),
    #[error("Failed to parse blob certificate: {0}")]
    BlobCertificate(String),
    #[error("Failed to parse blob inclusion: {0}")]
    BlobInclusion(String),
    #[error("Failed to parse batch header: {0}")]
    BatchHeader(String),
    #[error("Failed to parse blob key: {0}")]
    BlobKey(String),
    #[error("Failed to convert U256: {0}")]
    U256Conversion(String),
    #[error("Failed to convert u32: {0}")]
    U32Conversion(String),
    #[error("Failed to convert u16: {0}")]
    U16Conversion(String),
    #[error(transparent)]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
}

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Invalid blob length: {0}")]
    InvalidBlobLength(usize),
    #[error("Blob length is zero")]
    InvalidBlobLengthZero,
    #[error("Blob length is not a power of two")]
    InvalidBlobLengthNotPowerOfTwo(usize),
    #[error("Mismatch between commitment ({0}) and blob ({1})")]
    CommitmentAndBlobLengthMismatch(usize, usize),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(usize),
    #[error("Invalid quorum number: {0}")]
    InvalidQuorumNumber(u32),
    #[error("No chunks found")]
    EmptyChunks,
    #[error("Missing field: {0}")]
    MissingField(String),
}

/// Errors specific to the Retriever Client type
#[derive(Debug, thiserror::Error)]
pub enum RetrievalClientError {
    #[error("Unkown encoding format")]
    EncodingFormatUnkown,
    #[error("Failed to retrieve any chunks")]
    EmptyChunksResponse,
    #[error("Invalid chunks: {0}")]
    InvalidChunks(String),
    #[error("too many operators ({0}) to get assignments: max number of operators is {1}")]
    TooManyOperators(usize, usize),
    #[error("Missing operator for quorum id: {0}")]
    MissingOperator(u8),
    #[error("Missing total stake for quorum id: {0}")]
    MissingTotalStake(u8),
    #[error("Missing parameters for blob version: {0}")]
    MissingBlobVersionParams(u16),
    #[error("Missing assignment in operator reply: {0}")]
    MissingAssignment(usize),
    #[error(transparent)]
    VerifierError(#[from] VerifierError),
    #[error(transparent)]
    Tonic(#[from] TonicError),
    #[error(transparent)]
    EthClient(#[from] EthClientError),
    #[error(transparent)]
    AbiDecode(#[from] AbiEncodeError),
}

/// Errors specific to Tonic
#[derive(Debug, thiserror::Error)]
pub enum TonicError {
    #[error(transparent)]
    StatusError(#[from] tonic::Status),
    #[error(transparent)]
    TransportError(#[from] tonic::transport::Error),
}

/// Errors for the EthClient
#[derive(Debug, thiserror::Error)]
pub enum EthClientError {
    #[error(transparent)]
    HTTPClient(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJSON(#[from] serde_json::Error),
    #[error(transparent)]
    HexEncoding(#[from] hex::FromHexError),
    #[error(transparent)]
    EthAbi(#[from] ethabi::Error),
    #[error("RPC: {0}")]
    Rpc(RpcErrorResponse),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// Errors for the verifier
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("Failed to verify commit equivalence batch")]
    FailedToVerifyCommitEquivalenceBatch,
}
