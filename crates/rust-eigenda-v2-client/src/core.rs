mod blob;
pub mod eigenda_cert;
mod encoded_payload;
mod payload;
mod blob_request_signer;
mod blob_header;
mod payment;
mod blob_key;

pub use blob::Blob;
pub use encoded_payload::EncodedPayload;
pub use payload::Payload;
pub use blob_request_signer::{BlobRequestSigner, LocalBlobRequestSigner};
pub use blob_header::BlobHeader;
pub use payment::{PaymentMetadata, ReservedPayment, OnDemandPayment};
pub use blob_key::BlobKey;

pub(crate) const BYTES_PER_SYMBOL: usize = 32;

/// Payload encoding version
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}

/// The form of a payload dictates what conversion, if any, must be performed when creating a blob from the payload.
#[derive(Clone, Copy)]
pub enum PayloadForm {
    /// Evaluation form, where the payload is in evaluation form
    Eval,
    /// Coefficient form, where the payload is in coefficient form
    Coeff,
}
