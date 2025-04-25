/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenDACertError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error("Serialization failed for EigenDA certificate {0}")]
    SerializationError(String),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse G1 point: {0}")]
    G1Point(String),
    #[error("Failed to parse G2 point: {0}")]
    G2Point(String),
    #[error(transparent)]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
    #[error("Failed to parse signed batch: {0}")]
    SignedBatch(String),
    #[error("Failed to parse batch header: {0}")]
    BatchHeader(String),
    #[error("Failed to parse blob inclusion: {0}")]
    BlobInclusion(String),
    #[error("Failed to parse blob certificate: {0}")]
    BlobCertificate(String),
    #[error("Failed to parse blob header: {0}")]
    BlobHeader(String),
    #[error("Failed to parse blob key: {0}")]
    BlobKey(String),
    #[error("Failed to convert U256: {0}")]
    U256Conversion(String),
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
