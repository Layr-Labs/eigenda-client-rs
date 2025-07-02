use crate::core::Blob;
use crate::errors::ConversionError;

use super::encoded_payload::EncodedPayload;

/// Payload represents arbitrary user data, without any processing.
#[derive(Debug, PartialEq)]
pub struct Payload {
    bytes: Vec<u8>,
}

impl Payload {
    /// Wraps an arbitrary array of bytes into a Payload type.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Converts the [`Payload`] bytes into a [`Blob`].
    pub fn to_blob(&self) -> Result<Blob, ConversionError> {
        let encoded_payload = EncodedPayload::new(self)?;
        let field_elements = encoded_payload.to_field_elements();

        let blob_length_symbols = field_elements.len().next_power_of_two();

        Ok(Blob {
            coeff_polynomial: field_elements,
            blob_length_symbols,
        })
    }

    /// Returns the bytes that underlie the payload, i.e. the unprocessed user data.
    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
