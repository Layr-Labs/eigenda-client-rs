/// Errors specific to the EigenDA certificate
#[derive(Debug, thiserror::Error)]
pub enum EigenDACertError {
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
}
