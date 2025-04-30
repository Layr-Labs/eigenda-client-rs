/// Errors specific to the EigenDA certificate
#[derive(Debug, thiserror::Error)]
pub enum EigenDACertError {
    #[error("Serialization failed for EigenDA certificate {0}")]
    SerializationError(String),
}

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Blob length is zero")]
    InvalidBlobLengthZero,
    #[error("Blob length is not a power of two")]
    InvalidBlobLengthNotPowerOfTwo(usize),
    #[error("Mismatch between commitment ({0}) and blob ({1})")]
    CommitmentAndBlobLengthMismatch(usize, usize),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(usize),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse G1 point: {0}")]
    G1Point(String),
    #[error("Failed to parse G2 point: {0}")]
    G2Point(String),
    #[error("Failed to convert polynomial: {0}")]
    Poly(String),
    #[error("Failed to parse payload: {0}")]
    Payload(String),
    #[error("Failed to parse encoded payload: {0}")]
    EncodedPayload(String),
    #[error("Failed to serialize ark: {0}")]
    ArkSerialization(String),
}
