use crate::relay_client::RelayKey;

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
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
    #[error("Missing field: {0}")]
    MissingField(String),
}

/// Errors specific to the Relay Client
#[derive(Debug, thiserror::Error)]
pub enum RelayClientError {
    #[error("Max grpc message size must be greater than 0")]
    InvalidMaxGrpcMessageSize,
    #[error("Failed RPC call: {0}")]
    FailedRPC(#[from] tonic::Status),
    #[error("Failed connection call")]
    FailedConnection(#[from] tonic::transport::Error),
    #[error("Invalid relay key {0}")]
    InvalidRelayKey(RelayKey),
    #[error("Request cannot be empty")]
    EmptyRequest,
    #[error("Failed to fetch current timestamp")]
    FailedToFetchCurrentTimestamp,
    #[error("Invalid disperser URI: {0}")]
    InvalidURI(String),
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
    Rpc(crate::eth_client::RpcErrorResponse),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}
