use ark_bn254::{Fr, G1Affine};
use rust_kzg_bn254_primitives::errors::KzgError;

use crate::relay_client::RelayKey;
use hex::FromHexError;
use prost::DecodeError;

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    PayloadDisperser(#[from] PayloadDisperserError),
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
    #[error("Failed to parse signed batch: {0}")]
    SignedBatch(String),
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
    #[error(transparent)]
    Bn254(#[from] Bn254Error),
}

/// Errors specific to the Relay Payload Retriever
#[derive(Debug, thiserror::Error)]
pub enum RelayPayloadRetrieverError {
    #[error(transparent)]
    RelayClient(#[from] RelayClientError),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Kzg(#[from] KzgError),
    #[error("Unable to retrieve payload")]
    UnableToRetrievePayload,
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("Retrieval request to relay timed out")]
    RetrievalTimeout,
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
    #[error(transparent)]
    EthClient(#[from] EthClientError),
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

/// Errors related to the BN254 and its points
#[derive(Debug, thiserror::Error)]
pub enum Bn254Error {
    #[error("Insufficient SRS in memory: have {0}, need {1}")]
    InsufficientSrsInMemory(usize, usize),
    #[error("Failed calculating multi scalar multiplication on base {:?} with scalars {:?}", .0, .1)]
    FailedComputingMSM(Vec<G1Affine>, Vec<Fr>),
}

/// Errors specific to the Accountant
#[derive(Debug, thiserror::Error)]
pub enum AccountantError {
    #[error("Neither reservation nor on-demand payment is available")]
    PaymentNotAvailable,
    #[error("Payment reply is not complete")]
    PaymentReply,
}

/// Errors specific to the Disperser Client
#[derive(Debug, thiserror::Error)]
pub enum DisperseError {
    #[error(transparent)]
    Accountant(AccountantError),
    #[error("Failed to initialize disperser config: {0}")]
    ConfigInitialization(String),
    #[error(transparent)]
    Tonic(#[from] tonic::transport::Error),
    #[error("Failed to parse URL: {0}")]
    InvalidURI(String),
    #[error("Empty quorums must be provided")]
    EmptyQuorums,
    #[error("Blob commitment is empty")]
    EmptyBlobCommitment,
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Blob commitment length {0} does not match symbol length {1}")]
    CommitmentLengthMismatch(u32, usize),
    #[error("Invalid Account id")]
    AccountID,
    #[error("Failed RPC call: {0}")]
    FailedRPC(#[from] tonic::Status),
    #[error("Calculated and disperser blob key mismatch")]
    BlobKeyMismatch,
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("Failed to get current time")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Signer(#[from] SignerError),
}

/// Errors specific to the Signer
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Failed to parse private key: {0}")]
    PrivateKey(#[from] FromHexError),
    #[error(transparent)]
    Secp(#[from] secp256k1::Error),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
}
/// Errors specific to the PayloadDisperser
#[derive(Debug, thiserror::Error)]
pub enum PayloadDisperserError {
    #[error(transparent)]
    Disperser(#[from] DisperseError),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Blob status is unknown or failed")]
    BlobStatus,
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    CertVerifier(#[from] CertVerifierError),
}

/// Errors specific to the CertVerifier
#[derive(Debug, thiserror::Error)]
pub enum CertVerifierError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Alloy(#[from] alloy_contract::Error),
}
