use super::payload::Payload;
use ark_bn254::Fr;
use rust_kzg_bn254_primitives::helpers::to_fr_array;

// TODO: make it an enum
const PAYLOAD_ENCODING_VERSION_0: u8 = 0;

const BYTES_PER_SYMBOL: u8 = 32;

/// `EncodedPayload` represents a payload that has had an encoding applied to it
///
/// Example encoding:
/// ```
///             Encoded Payload header (32 bytes total)                   Encoded Payload Data (len is multiple of 32)
/// [0x00, version byte, big-endian uint32 len of payload, 0x00, ...] + [0x00, 31 bytes of data, 0x00, 31 bytes of data,...]
/// ```
#[derive(Debug, PartialEq)]
pub struct EncodedPayload {
    /// the size of these bytes is guaranteed to be a multiple of 32
    bytes: Vec<u8>,
}

impl EncodedPayload {
    /// Creates a new `EncodedPayload` from a `Payload`, performing the `PayloadEncodingVersion0` encoding
    pub fn new(payload: &Payload) -> Result<EncodedPayload, String> {
        let mut header = [0u8; 32].to_vec();
        header[1] = PAYLOAD_ENCODING_VERSION_0;

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

    /// Decodes the `EncodedPayload` back into a `Payload`. It basically does the inverse of `new`.
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
            todo!()
        }

        if unpadded_data_length > expected_data_length + 31 {
            // TODO: add error handling
            todo!()
        }

        Ok(Payload::new(
            unpadded_data[0..expected_data_length as usize].to_vec(),
        ))
    }

    /// Converts the encoded payload to an array of field elements.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        to_fr_array(&self.bytes)
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
fn get_padded_data_length(data_length: u32) -> u32 {
    let bytes_per_chunk = (BYTES_PER_SYMBOL - 1) as u32;
    let mut chunk_count = data_length / bytes_per_chunk;

    if data_length % bytes_per_chunk != 0 {
        chunk_count += 1;
    }

    chunk_count * (BYTES_PER_SYMBOL as u32)
}

/// Accepts an array of data, and returns the array after adding padding to be bn254 friendly.
fn pad_to_bn254(data: &[u8]) -> Vec<u8> {
    let bytes_per_chunk = (BYTES_PER_SYMBOL - 1) as u32;
    let output_length = get_padded_data_length(data.len() as u32);
    let mut padded_output = vec![0u8; output_length as usize];

    // pre-pad the input, so that it aligns to 31 bytes. This means that the internally padded result will automatically
    // align to 32 bytes. Doing this padding in advance simplifies the for loop.
    let required_pad = (bytes_per_chunk - data.len() as u32 % bytes_per_chunk) % bytes_per_chunk;
    let pre_padded_payload = [data, &vec![0u8; required_pad as usize]].concat();

    for elem in 0..output_length / 32 {
        let zero_byte_index = (elem * bytes_per_chunk) as usize;
        padded_output[zero_byte_index] = 0x00;

        let destination_index = zero_byte_index + 1;
        let source_index = (elem * bytes_per_chunk) as usize;

        let pre_padded_chunk =
            &pre_padded_payload[source_index..source_index + bytes_per_chunk as usize];
        padded_output[destination_index..destination_index + bytes_per_chunk as usize]
            .copy_from_slice(pre_padded_chunk);
    }

    padded_output
}

#[cfg(test)]
mod tests {
    use crate::core::{encoded_payload::EncodedPayload, payload::Payload};


    #[test]
    fn test_encode() {
        let payload = Payload::new("hello world".to_string().into_bytes());
        let encoded_payload = EncodedPayload::new(&payload);
        assert!(encoded_payload.is_ok());
        
        let decoded_payload = encoded_payload.unwrap().decode();
        assert!(decoded_payload.is_ok());
        assert_eq!(payload, decoded_payload.unwrap());
    }

    // checks that an encoded payload with a length less than claimed length fails at decode time
    #[test]
    fn test_decode_short_bytes() {
        todo!()
    }

    // checks that an encoded payload with length too much greater than claimed fails at decode
    #[test]
    fn test_decode_long_bytes() {
        todo!()
    }

    #[test]
    fn test_encode_too_many_elements() {
        todo!()
    }

    #[test]
    fn test_trailing_non_zeros() {
        todo!()
    }
}
