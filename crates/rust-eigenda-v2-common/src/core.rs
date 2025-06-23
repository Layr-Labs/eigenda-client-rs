mod blob;
mod check_da_cert_status;
mod encoded_payload;
mod payload;

pub use blob::Blob;
pub use check_da_cert_status::CheckDACertStatus;
pub use encoded_payload::EncodedPayload;
pub use payload::Payload;

pub(crate) const BYTES_PER_SYMBOL: usize = 32;

/// Payload encoding version
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}

/// The form of a payload dictates what conversion, if any, must be performed when creating a blob from the payload.
#[derive(Clone, Copy, Debug)]
pub enum PayloadForm {
    /// Evaluation form, where the payload is in evaluation form.
    Eval,
    /// Coefficient form, where the payload is in coefficient form.
    Coeff,
}
