mod blob;
mod encoded_payload;
mod payload;

pub use encoded_payload::EncodedPayload;
pub use payload::Payload;

pub(crate) const BYTES_PER_SYMBOL: u8 = 32;

/// Payload encoding version
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}
