mod blob;
mod encoded_payload;
mod payload;

pub use blob::Blob;
pub use encoded_payload::EncodedPayload;
pub use payload::Payload;

pub(crate) const BYTES_PER_SYMBOL: u8 = 32;

/// Payload encoding version
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}

/// The form of a payload dictates what conversion, if any, must be performed when creating a blob from the payload.
pub enum PayloadForm {
    /// Evaluation form, where the payload is in evaluation form
    Eval,
    /// Coefficient form, where the payload is in coefficient form
    Coeff,
}
