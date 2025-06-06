use ark_bn254::{Fr, G1Affine};
use ethereum_types::H160;
use rust_kzg_bn254_primitives::errors::KzgError;

use crate::relay_client::RelayKey;
use prost::DecodeError;

/// Errors returned by the client.
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    PayloadDisperser(#[from] Box<PayloadDisperserError>),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse payload: {0}")]
    Payload(String),
    #[error("Failed to parse encoded payload: {0}")]
    EncodedPayload(String),
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
    #[error("Failed to serialize ark: {0}")]
    ArkSerialization(String),
    #[error("Failed to parse signed batch: {0}")]
    SignedBatch(String),
    #[error("Private Key Error")]
    PrivateKey,
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    // #[error(transparent)]
    // Wallet(#[from] Wallet), // TODO: REPLACE WITH ALLOY COUNTERPART
    #[error(transparent)]
    EigenDACommon(#[from] rust_eigenda_v2_common::ConversionError),
    #[error("Failed to convert U256: {0}")]
    U256Conversion(String),
    #[error("Failed to parse attestation: {0}")]
    Attestation(String),
    #[error("Failed to parse checkDACert Status: {0}")]
    InvalidCheckDACertStatus(u8),
    #[error("Failed to parse address: {0}")]
    Address(String),
}

/// Errors specific to the [`RelayPayloadRetriever`].
#[derive(Debug, thiserror::Error)]
pub enum RelayPayloadRetrieverError {
    #[error(transparent)]
    RelayClient(#[from] Box<RelayClientError>),
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

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Invalid quorum number: {0}")]
    InvalidQuorumNumber(u32),
    #[error("Missing field: {0}")]
    MissingField(String),
    #[error(transparent)]
    Bn254(#[from] Bn254Error),
    #[error(transparent)]
    CommonBlob(#[from] rust_eigenda_v2_common::BlobError),
}

/// Errors related to the BN254 and its points
#[derive(Debug, thiserror::Error)]
pub enum Bn254Error {
    #[error("Insufficient SRS in memory: have {0}, need {1}")]
    InsufficientSrsInMemory(usize, usize),
    #[error("Failed calculating multi scalar multiplication on base {:?} with scalars {:?}", .0, .1)]
    FailedComputingMSM(Vec<G1Affine>, Vec<Fr>),
}

/// Errors specific to the [`RelayClient`].
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
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Failed to parse relay key to URL: {0}")]
    RelayKeyToUrl(u32),
}

impl From<RelayClientError> for RelayPayloadRetrieverError {
    fn from(err: RelayClientError) -> Self {
        RelayPayloadRetrieverError::RelayClient(Box::new(err))
    }
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
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
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
    FailedRPC(#[from] Box<tonic::Status>),
    #[error("Calculated and disperser blob key mismatch")]
    BlobKeyMismatch,
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("Failed to get current time")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Signer(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl From<tonic::Status> for DisperseError {
    fn from(err: tonic::Status) -> Self {
        DisperseError::FailedRPC(Box::new(err))
    }
}

/// Errors specific to the [`PayloadDisperser`].
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
    #[error("Expected >0 quorum numbers in blob header")]
    NoQuorumNumbers,
    #[error("Batch quorum number count and signed percentage count don't match")]
    QuorumNumbersMismatch,
    #[error("Expected batch header to be present in signed batch")]
    BatchHeaderNotPresent,
    #[error("Signed percentage not found for quorum: {0}")]
    SignedPercentageNotFound(u32),
    #[error("Confirmation threshold not met for quorum {quorum_number}, signed percentage {signed_percentage}, threshold {threshold}")]
    ConfirmationThresholdNotMet {
        quorum_number: u32,
        signed_percentage: u8,
        threshold: u8,
    },
    #[error("Failed to initialize Eigen SDK")]
    EigenSDKNotInitialized,
    #[error("Failed to check signature indices")]
    GetCheckSignaturesIndices,
}

impl From<PayloadDisperserError> for EigenClientError {
    fn from(err: PayloadDisperserError) -> Self {
        EigenClientError::PayloadDisperser(Box::new(err))
    }
}

/// Errors specific to the CertVerifier
#[derive(Debug, thiserror::Error)]
pub enum CertVerifierError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Invalid cert verifier contract address: {0}")]
    InvalidCertVerifierAddress(H160),
    #[error("Error while calling contract function: {0}")]
    Contract(String),
    #[error("Error while signing: {0}")]
    Signing(String),
    #[error("Error while verifying checkDACert: {0}")]
    VerificationFailed(String),
    #[error("Error while verifying checkDACert, Null Error returned, this is a bug in the contracts, please report it")]
    VerificationFailedNullError,
}
