use ark_bn254::G1Affine;
use tokio::sync::mpsc::error::SendError;
use tonic::{transport::Error as TonicError, Status};

use crate::{blob_info::BlobQuorumParam, eth_client::RpcErrorResponse, generated::disperser};

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    EthClient(#[from] EthClientError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error(transparent)]
    Communication(#[from] CommunicationError),
    #[error(transparent)]
    BlobStatus(#[from] BlobStatusError),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Private Key Error")]
    PrivateKey,
    #[error("ETH RPC URL not set")]
    NoEthRpcUrl,
    #[error(transparent)]
    Tonic(#[from] TonicError),
}

#[derive(Debug, thiserror::Error)]
pub enum CommunicationError {
    #[error("No response from server")]
    NoResponseFromServer,
    #[error("No payload in response")]
    NoPayloadInResponse,
    #[error("Failed to get blob data")]
    FailedToGetBlob,
    #[error("Failed to send DisperseBlobRequest: {0}")]
    DisperseBlob(SendError<disperser::AuthenticatedRequest>),
    #[error("Failed to send AuthenticationData: {0}")]
    AuthenticationData(SendError<disperser::AuthenticatedRequest>),
    #[error("Error from server: {0}")]
    ErrorFromServer(String),
    #[error(transparent)]
    Signing(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    BlobProvider(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, thiserror::Error)]
pub enum BlobStatusError {
    #[error("Blob still processing")]
    BlobStillProcessing,
    #[error("Blob dispatched failed")]
    BlobDispatchedFailed,
    #[error("Insufficient signatures")]
    InsufficientSignatures,
    #[error("No blob header in response")]
    NoBlobHeaderInResponse,
    #[error("Received unknown blob status")]
    ReceivedUnknownBlobStatus,
    #[error(transparent)]
    Prost(#[from] prost::DecodeError),
    #[error(transparent)]
    Status(#[from] Status),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to convert {0}")]
    NotPresent(String),
    #[error("Failed to cast {0}")]
    Cast(String),
    #[error("hash digest was not 32B as expected. This is a bug, please report it")]
    InvalidDigest,
}

/// Errors for the EthClient
#[derive(Debug, thiserror::Error)]
pub enum EthClientError {
    #[error(transparent)]
    HTTPClient(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJSON(#[from] serde_json::Error),
    #[error("RPC: {0}")]
    Rpc(RpcErrorResponse),
}

#[derive(Debug, thiserror::Error)]
pub enum KzgError {
    #[error("Kzg setup error: {0}")]
    Setup(String),
    #[error(transparent)]
    Internal(#[from] rust_kzg_bn254::errors::KzgError),
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceManagerError {
    #[error(transparent)]
    EthClient(#[from] EthClientError),
    #[error("Decoding error: {0}")]
    Decoding(String),
}

/// Errors for the Verifier
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    ServiceManager(#[from] ServiceManagerError),
    #[error(transparent)]
    Kzg(#[from] KzgError),
    #[error("Wrong proof")]
    WrongProof,
    #[error("Different commitments: expected {expected:?}, got {actual:?}")]
    DifferentCommitments {
        expected: Box<G1Affine>,
        actual: Box<G1Affine>,
    },
    #[error("Different roots: expected {expected:?}, got {actual:?}")]
    DifferentRoots { expected: String, actual: String },
    #[error("Empty hashes")]
    EmptyHash,
    #[error("Different hashes: expected {expected:?}, got {actual:?}")]
    DifferentHashes { expected: String, actual: String },
    #[error("Wrong quorum params: {blob_quorum_params:?}")]
    WrongQuorumParams { blob_quorum_params: BlobQuorumParam },
    #[error("Quorum not confirmed")]
    QuorumNotConfirmed,
    #[error("Commitment not on curve: {0}")]
    CommitmentNotOnCurve(G1Affine),
    #[error("Commitment not on correct subgroup: {0}")]
    CommitmentNotOnCorrectSubgroup(G1Affine),
    #[error("Point download error: {0}")]
    PointDownloadError(String),
    #[error("Data Mismatch")]
    DataMismatch,
    #[error(transparent)]
    Conversion(#[from] ConversionError),
}
