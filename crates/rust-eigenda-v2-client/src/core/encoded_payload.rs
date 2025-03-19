use crate::core::Payload;
use ark_bn254::Fr;
use rust_kzg_bn254_primitives::helpers::{to_byte_array, to_fr_array};

const BYTES_PER_SYMBOL: u8 = 32;

// Payload encoding version
//
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}

/// `EncodedPayload` represents a payload that has had an encoding applied to it
///
/// Encoding Format:
///
/// The encoded payload consists of two parts:
///
/// 1. Header (32 bytes):
///    - Byte 0: Always 0x00 (reserved)
///    - Byte 1: Encoding Version byte (e.g., 0x00 for PayloadEncodingVersion::Zero)
///    - Bytes 2-5: Big-endian u32 representing the original payload length
///    - Bytes 6-31: Reserved (filled with 0x00)
///
/// 2. Data (multiple of 32 bytes):
///    Each 32-byte chunk contains:
///    - Byte 0: 0x00 (padding byte to ensure the data is in valid field element range)
///    - Bytes 1-31: 31 bytes of actual payload data (or padding for the last chunk)
///
/// The padding ensures that all data is compatible with the bn254 curve's field element
/// limitations, as each 32-byte segment represents a field element.
#[derive(Debug, PartialEq)]
pub struct EncodedPayload {
    /// the size of these bytes is guaranteed to be a multiple of 32
    bytes: Vec<u8>,
}

impl EncodedPayload {
    /// Creates a new `EncodedPayload` from a `Payload`, performing the `PayloadEncodingVersion0` encoding
    pub fn new(payload: &Payload) -> Result<EncodedPayload, String> {
        let mut header = [0u8; 32].to_vec();
        header[1] = PayloadEncodingVersion::Zero as u8;

        let payload_bytes: Vec<u8> = payload.serialize();

        // add payload length to the header
        let payload_length: u32 = payload_bytes.len() as u32;
        header[2..6].copy_from_slice(&payload_length.to_be_bytes());

        // encode payload modulo bn254, and align to 32 bytes
        let encoded_data = pad_to_bn254(&payload_bytes);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&encoded_data);

        Ok(EncodedPayload { bytes })
    }

    /// Decodes the `EncodedPayload` back into a `Payload`.
    pub fn decode(&self) -> Result<Payload, String> {
        let expected_data_length = match self.bytes[2..6].try_into() {
            Ok(arr) => u32::from_be_bytes(arr),
            Err(_) => return Err("Invalid header format: couldn't read data length".to_string()),
        };
        // decode raw data modulo bn254
        let unpadded_data = remove_internal_padding(&self.bytes[32..])?;
        let unpadded_data_length = unpadded_data.len() as u32;

        // data length is checked when constructing an encoded payload. If this error is encountered, that means there
        // must be a flaw in the logic at construction time (or someone was bad and didn't use the proper construction methods)
        if unpadded_data_length < expected_data_length {
            // TODO: add error handling
            return Err("Invalid header format: data length is less than expected".to_string());
        }

        if unpadded_data_length > expected_data_length + 31 {
            // TODO: add error handling
            return Err("Invalid header format: data length is greater than expected".to_string());
        }

        Ok(Payload::new(
            unpadded_data[0..expected_data_length as usize].to_vec(),
        ))
    }

    /// Converts the encoded payload to an array of field elements.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        to_fr_array(&self.bytes)
    }

    /// Creates an `EncodedPayload` from an array of field elements.
    /// `max_payload_length` is the maximum length in bytes that the contained `Payload` is permitted to be.
    pub fn from_field_elements(
        field_elements: &[Fr],
        max_payload_length: u32,
    ) -> Result<EncodedPayload, String> {
        let serialized_felts = to_byte_array(field_elements, usize::MAX);
        // read payload length from the payload header
        let payload_length = match serialized_felts[2..6].try_into() {
            Ok(arr) => u32::from_be_bytes(arr),
            Err(_) => {
                return Err(
                    "Invalid serialized field elements: couldn't read payload length".to_string(),
                );
            }
        };

        if payload_length > max_payload_length {
            return Err(
                "Invalid serialized field elements: payload length is greater than maximum allowed"
                    .to_string(),
            );
        }

        let padded_length = get_padded_data_length(payload_length);
        // add 32 to take into account the payload header
        let encoded_payload_length = padded_length + 32;

        let serialized_felts_length = serialized_felts.len();
        let mut length_to_copy = encoded_payload_length;

        match encoded_payload_length.cmp(&serialized_felts_length) {
            std::cmp::Ordering::Greater => {
                // serialized_felts is longer than encoded_payload_length, so we need to truncate it
                // to avoid copying more than we need.
                length_to_copy = serialized_felts_length;
            }
            std::cmp::Ordering::Less => {
                // serialized_felts is shorter than encoded_payload_length, 
                // so we need to check that the remaining bytes are all 0.
                let serialized_felts_without_header = serialized_felts
                    .iter()
                    .enumerate()
                    .skip(encoded_payload_length);
                for (index, &byte) in serialized_felts_without_header {
                    if byte != 0 {
                        return Err(format!(
                            "byte at index {} was expected to be 0x00, but instead was 0x{:02x}",
                            index, byte
                        ));
                    }
                }
            }
            std::cmp::Ordering::Equal => {}
        }

        // Create a byte vector of size encoded_payload_length filled with zeros
        let mut encoded_payload_bytes = vec![0u8; encoded_payload_length];

        // Copy data from serialized_felts up to length_to_copy
        encoded_payload_bytes[..length_to_copy]
            .copy_from_slice(&serialized_felts[..length_to_copy]);

        // Return a new EncodedPayload with the byte vector
        Ok(EncodedPayload {
            bytes: encoded_payload_bytes,
        })
    }
}

/// Accepts an array of padded data, and removes the internal padding that was added in PadPayload
///
/// This function assumes that the input aligns to 32 bytes. Since it is removing 1 byte for every 31 bytes kept, the
/// output from this function is not guaranteed to align to 32 bytes.
fn remove_internal_padding(padded_data: &[u8]) -> Result<Vec<u8>, String> {
    if padded_data.len() % (BYTES_PER_SYMBOL as usize) != 0 {
        return Err(format!(
            "padded data (length {}) must be multiple of BYTES_PER_SYMBOL ({})",
            padded_data.len(),
            BYTES_PER_SYMBOL
        ));
    }

    let bytes_per_chunk = (BYTES_PER_SYMBOL - 1) as usize;
    let symbol_count = padded_data.len() / (BYTES_PER_SYMBOL as usize);
    let output_length = symbol_count * bytes_per_chunk;

    let mut output_data = vec![0u8; output_length];

    for i in 0..symbol_count {
        let dst_index = i * bytes_per_chunk;
        let src_index = i * (BYTES_PER_SYMBOL as usize) + 1;

        output_data[dst_index..dst_index + bytes_per_chunk]
            .copy_from_slice(&padded_data[src_index..src_index + bytes_per_chunk]);
    }

    Ok(output_data)
}

/// Accepts the length of a byte array, and returns the length that the array would be after
/// adding internal byte padding.
///
/// The value returned from this function will always be a multiple of `BYTES_PER_SYMBOL`
fn get_padded_data_length(data_length: u32) -> usize {
    let bytes_per_chunk = (BYTES_PER_SYMBOL - 1) as u32;
    let mut chunk_count = (data_length / bytes_per_chunk) as usize;

    if data_length % bytes_per_chunk != 0 {
        chunk_count += 1;
    }

    chunk_count * (BYTES_PER_SYMBOL as usize)
}

/// Accepts an array of data, and returns the array after adding padding to be bn254 friendly.
fn pad_to_bn254(data: &[u8]) -> Vec<u8> {
    let bytes_per_chunk = (BYTES_PER_SYMBOL - 1) as usize;
    let output_length = get_padded_data_length(data.len() as u32);
    let mut padded_output = vec![0u8; output_length];

    // pre-pad the input, so that it aligns to 31 bytes. This means that the internally padded result will automatically
    // align to 32 bytes. Doing this padding in advance simplifies the for loop.
    let required_pad = (bytes_per_chunk - data.len() % bytes_per_chunk) % bytes_per_chunk;
    let pre_padded_payload = [data, &vec![0u8; required_pad]].concat();

    for elem in 0..output_length / 32 {
        let zero_byte_index = elem * bytes_per_chunk;
        padded_output[zero_byte_index] = 0x00;

        let destination_index = zero_byte_index + 1;
        let source_index = elem * bytes_per_chunk;

        let pre_padded_chunk = &pre_padded_payload[source_index..source_index + bytes_per_chunk];
        padded_output[destination_index..destination_index + bytes_per_chunk]
            .copy_from_slice(pre_padded_chunk);
    }

    padded_output
}

#[cfg(test)]
mod tests {
    use crate::core::{EncodedPayload, Payload};
    use rand::{Rng, thread_rng};

    /// Checks that encoding and decoding a payload works correctly.
    #[test]
    fn test_encoding_decoding() {
        let payload = Payload::new("hello world".to_string().into_bytes());
        let encoded_payload = EncodedPayload::new(&payload);
        assert!(encoded_payload.is_ok());

        let decoded_payload = encoded_payload.unwrap().decode();
        assert!(decoded_payload.is_ok());
        assert_eq!(payload, decoded_payload.unwrap());
    }

    /// Checks that an encoded payload with a length less than claimed length fails at decode time
    #[test]
    fn test_decode_short_bytes() {
        let mut rng = thread_rng();
        let random_length = rng.gen_range(33..1057); // 33 + random value up to 1024
        let original_data: Vec<u8> = (0..random_length).map(|_| rng.r#gen()).collect();

        // Create payload and encode it
        let payload = Payload::new(original_data);
        let encoded_payload = EncodedPayload::new(&payload).unwrap();

        // Create a truncated version by removing the last 32 bytes
        let truncated_bytes = encoded_payload.bytes[..encoded_payload.bytes.len() - 32].to_vec();
        let truncated_payload = EncodedPayload {
            bytes: truncated_bytes,
        };

        // Try to decode the truncated payload - should fail
        let decode_result = truncated_payload.decode();
        assert!(decode_result.is_err());
    }

    /// Checks that an encoded payload with length greater than claimed fails at decode
    #[test]
    fn test_decode_long_bytes() {
        use rand::{Rng, thread_rng};

        // Generate random data
        let mut rng = thread_rng();
        let random_length = rng.gen_range(1..1025); // 1 + random value up to 1024
        let original_data: Vec<u8> = (0..random_length).map(|_| rng.r#gen()).collect();

        // Create payload and encode it
        let payload = Payload::new(original_data);
        let encoded_payload = EncodedPayload::new(&payload).unwrap();

        // Create an extended version by appending 33 bytes (zeros)
        let mut extended_bytes = encoded_payload.bytes.clone();
        extended_bytes.extend_from_slice(&vec![0u8; 33]);

        let extended_payload = EncodedPayload {
            bytes: extended_bytes,
        };

        // Try to decode the extended payload - should fail
        let decode_result = extended_payload.decode();
        assert!(decode_result.is_err());
    }

    /// Checks that converting an `EncodedPayload` to an array of field elements and
    /// then back to an `EncodedPayload` results in the same data.
    #[test]
    fn test_from_to_field_elements() {
        let payload = Payload::new("hello world".to_string().into_bytes());
        let encoded_payload = EncodedPayload::new(&payload).unwrap();

        let field_elements = encoded_payload.to_field_elements();
        let max_payload_length = u32::MAX;
        let new_encoded_payload =
            EncodedPayload::from_field_elements(&field_elements, max_payload_length).unwrap();

        assert_eq!(encoded_payload, new_encoded_payload);
    }

    // Checks that an encoded payload with too many elements fails at decode
    // #[test]
    // fn test_encode_too_many_elements() {
    //     todo!()
    // }

    // #[test]
    // fn test_trailing_non_zeros() {
    //     todo!()
    // }
}
