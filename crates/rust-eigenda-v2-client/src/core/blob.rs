use ark_bn254::Fr;

use crate::errors::{BlobError, EigenClientError};
use crate::utils::coeff_to_eval_poly;

use crate::core::{EncodedPayload, Payload, PayloadForm, BYTES_PER_SYMBOL};

/// [`Blob`] is data that is dispersed on EigenDA.
///
/// A Blob is represented under the hood by an array of field elements, which represent a polynomial in coefficient form.
#[derive(Debug, PartialEq)]
pub struct Blob {
    pub coeff_polynomial: Vec<Fr>,
    /// blob_length_symbols must be a power of 2, and should match the blob_length claimed in the blob_commitment
    ///
    /// This value must be specified, rather than computed from the length of the coeff_polynomial, due to an edge case
    /// illustrated by the following example: imagine a user disperses a very small blob, only 64 bytes, and the last 40
    /// bytes are trailing zeros. When a different user fetches the blob from a relay, it's possible that the relay could
    /// truncate the trailing zeros. If we were to say that blob_length_symbols = next_power_of_2(len(coeff_polynomial)), then the
    /// user fetching and reconstructing this blob would determine that the blob length is 1 symbol, when it's actually 2.
    pub blob_length_symbols: usize,
}

impl Blob {
    /// Initializes a [`Blob`]` from bytes
    pub fn deserialize_blob(bytes: Vec<u8>, blob_length_symbols: usize) -> Result<Blob, BlobError> {
        // we check that length of bytes is <= blob length, rather than checking for equality, because it's possible
        // that the bytes being deserialized have had trailing 0s truncated.
        if bytes.len() > blob_length_symbols * BYTES_PER_SYMBOL {
            return Err(BlobError::CommitmentAndBlobLengthMismatch(
                blob_length_symbols,
                bytes.len() / BYTES_PER_SYMBOL,
            ));
        }

        let coeff_polynomial = rust_kzg_bn254_primitives::helpers::to_fr_array(&bytes);

        Ok(Blob {
            coeff_polynomial,
            blob_length_symbols,
        })
    }

    /// Gets the raw bytes of the [`Blob`].
    pub fn serialize(&self) -> Vec<u8> {
        rust_kzg_bn254_primitives::helpers::to_byte_array(
            &self.coeff_polynomial,
            self.blob_length_symbols * BYTES_PER_SYMBOL,
        )
    }

    /// Converts the [`Blob`] into a [`Payload`].
    ///
    /// The payload_form indicates how payloads are interpreted. The way that payloads are interpreted dictates what
    /// conversion, if any, must be performed when creating a payload from the blob.
    pub fn to_payload(&self, payload_form: PayloadForm) -> Result<Payload, EigenClientError> {
        let encoded_payload = self.to_encoded_payload(payload_form)?;
        encoded_payload
            .decode()
            .map_err(EigenClientError::Conversion)
    }

    /// Accepts the length of an array that has been padded with pad_payload
    ///
    /// It returns what the length of the output array would be, if you called remove_internal_padding on it.
    fn get_unpadded_data_length(&self, input_len: usize) -> Result<usize, BlobError> {
        if input_len % BYTES_PER_SYMBOL != 0 {
            return Err(BlobError::InvalidDataLength(input_len));
        }
        let chunck_count = input_len / BYTES_PER_SYMBOL;
        let bytes_per_chunk = BYTES_PER_SYMBOL - 1;

        Ok(chunck_count * bytes_per_chunk)
    }

    /// Gets the size in bytes of the largest payload that could fit inside the blob.
    fn get_max_permissible_payloadlength(
        &self,
        blob_length_symbols: usize,
    ) -> Result<usize, BlobError> {
        if blob_length_symbols == 0 {
            return Err(BlobError::InvalidBlobLengthZero);
        }
        if !blob_length_symbols.is_power_of_two() {
            return Err(BlobError::InvalidBlobLengthNotPowerOfTwo(
                blob_length_symbols,
            ));
        }

        self.get_unpadded_data_length(blob_length_symbols * BYTES_PER_SYMBOL - 32)
    }

    /// Creates an [`EncodedPayload`] from the blob.
    ///
    /// The payload_form indicates how payloads are interpreted. The way that payloads are interpreted dictates what
    /// conversion, if any, must be performed when creating an encoded payload from the blob.
    pub fn to_encoded_payload(
        &self,
        payload_form: PayloadForm,
    ) -> Result<EncodedPayload, EigenClientError> {
        let payload_elements = match payload_form {
            PayloadForm::Coeff => self.coeff_polynomial.clone(),
            PayloadForm::Eval => {
                coeff_to_eval_poly(self.coeff_polynomial.clone(), self.blob_length_symbols)?
            }
        };

        let max_possible_payload_length =
            self.get_max_permissible_payloadlength(self.blob_length_symbols)?;
        Ok(EncodedPayload::from_field_elements(
            &payload_elements,
            max_possible_payload_length,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::core::{blob::Blob, payload::Payload, PayloadForm};

    fn blob_conversion_for_form(payload_bytes: Vec<u8>, payload_form: PayloadForm) {
        let blob: Blob = Payload::new(payload_bytes.clone())
            .to_blob(payload_form)
            .unwrap();
        let blob_deserialized =
            Blob::deserialize_blob(blob.serialize(), blob.blob_length_symbols).unwrap();

        let payload_from_blob = blob.to_payload(payload_form).unwrap();

        let payload_from_deserialized_blob = blob_deserialized.to_payload(payload_form).unwrap();

        assert_eq!(
            payload_from_blob.serialize(),
            payload_from_deserialized_blob.serialize()
        );
        assert_eq!(payload_bytes, payload_from_blob.serialize());
    }

    fn test_blob_conversion(original_data: &[u8]) {
        blob_conversion_for_form(original_data.to_vec(), PayloadForm::Coeff);
        blob_conversion_for_form(original_data.to_vec(), PayloadForm::Eval);
    }

    proptest! {

        #[test]
        fn fuzz_blob_conversion(original_data in prop::collection::vec(any::<u8>(), 0..1000)) {
            test_blob_conversion(&original_data);
        }
    }
}
