use crate::{errors::ConversionError, generated::common::G1Commitment};
use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ff::{fields::PrimeField, AdditiveGroup, BigInteger, Fp, Fp2};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use rust_kzg_bn254_primitives::helpers::{lexicographically_largest, read_g1_point_from_bytes_be};

/// Converts an eval_poly to a coeff_poly, using the IFFT operation
///
/// blob_length_symbols is required, to be able to choose the correct parameters when performing FFT
pub(crate) fn eval_to_coeff_poly(
    eval_poly: Vec<Fr>,
    blob_length_symbols: usize,
) -> Result<Vec<Fr>, ConversionError> {
    Ok(GeneralEvaluationDomain::<Fr>::new(blob_length_symbols)
        .ok_or(ConversionError::Poly("Failed to create domain".to_string()))?
        .ifft(&eval_poly))
}

/// coeff_to_eval_poly converts a polynomial in coefficient form to one in evaluation form, using the FFT operation.
pub(crate) fn coeff_to_eval_poly(
    coeff_poly: Vec<Fr>,
    blob_length_symbols: usize,
) -> Result<Vec<Fr>, ConversionError> {
    let evals = GeneralEvaluationDomain::<Fr>::new(blob_length_symbols)
        .ok_or(ConversionError::Poly(
            "Failed to construct domain for FFT".to_string(),
        ))?
        .fft(&coeff_poly);
    Ok(evals)
}

/// g1_commitment_from_bytes converts a byte slice to a G1Affine point.
/// The points received are in compressed form.
pub(crate) fn g1_commitment_from_bytes(bytes: &[u8]) -> Result<G1Affine, ConversionError> {
    // See implementation of `read_g1_point_from_bytes_be`
    // to check how flags work (compressed/uncompressed/infinity)
    Ok(read_g1_point_from_bytes_be(bytes).unwrap())
}

pub(crate) fn g1_commitment_to_proto(point: &G1Affine) -> G1Commitment {
    let x = point.x.into_bigint().to_bytes_be();
    let y = point.y.into_bigint().to_bytes_be();
    G1Commitment { x, y }
}

/// Serialize a G1Affine point following applying necessary flags.
/// https://github.com/Consensys/gnark-crypto/blob/5fd6610ac2a1d1b10fae06c5e552550bf43f4d44/ecc/bn254/marshal.go#L790-L801
pub(crate) fn g1_commitment_to_bytes(point: &G1Affine) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];

    // Infinity case
    if point.to_flags().is_infinity() {
        bytes[0] = 0b01 << 6;
        return bytes;
    }

    // Get x-coordinate bytes
    let mut x_bytes = Vec::new();
    point.x.serialize_compressed(&mut x_bytes).unwrap();
    bytes.copy_from_slice(&x_bytes);
    bytes.reverse();

    // Determine y flag
    let y_is_largest = lexicographically_largest(&point.y);
    let m_data = if y_is_largest { 0b11 << 6 } else { 0b10 << 6 };
    bytes[0] |= m_data;

    // As we are returning a compressed point, we need to set the 'compressed' flag
    bytes[0] |= 0b1 << 7;

    // If the point is negative, set the 'negative' flag
    if !point.to_flags().is_positive().unwrap_or(true) {
        bytes[0] |= 0b1 << 6;
    }

    bytes
}

/// g2_commitment_from_bytes converts a byte slice to a G2Affine point.
pub(crate) fn g2_commitment_from_bytes(bytes: &[u8]) -> Result<G2Affine, ConversionError> {
    if bytes[0] == 0b01 << 6 {
        return Ok(G2Affine::identity());
    }

    // Remove smallest/largest mask
    let mut bytes = bytes.to_vec();
    bytes[0] &= 0b0011_1111;

    // smallest (left) and largest (right)
    // let msb_mask = bytes[0] & (0b01 << 6 | 0b11 << 6);

    // Extract X from the compressed representation
    let x1 = Fp::from_be_bytes_mod_order(&bytes[0..32]);
    let x0 = Fp::from_be_bytes_mod_order(&bytes[32..64]);
    let x = Fp2::new(x0, x1);

    let point = G2Affine::get_point_from_x_unchecked(x, true).unwrap();
    // Ensure Y has the correct lexicographic property
    // if (msb_mask == COMPRESSED_LARGEST) != y.is_lexicographically_largest() {
    //     y = -y;
    // }

    Ok(point)
}

pub(crate) fn g2_commitment_to_bytes(point: &G2Affine) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    point.serialize_compressed(&mut bytes).unwrap();

    // Remove leading zeroes
    let mut bytes: Vec<u8> = bytes.into_iter().skip_while(|&x| x == 0).collect();
    bytes.reverse();

    let mut mask = 0b10 << 6; // mCompressedSmallest
                              // if p.Y ">" -p.Y
    if point.y > *point.clone().y.neg_in_place() {
        mask = 0b11 << 6; // mCompressedLargest
    }

    bytes[0] |= mask;
    bytes
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq;

    use super::*;

    #[test]
    fn test_g1_commitment_utils_positive_point() {
        let proto_g1_commitment_bytes =
            hex::decode("8fe9346938e40204330aea61243eb8c4c9b9ea0d41167909e9cae449966229cc")
                .unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g1_commitment = g1_commitment_from_bytes(&proto_g1_commitment_bytes).unwrap();

        // We parse the point into its protobuf counterpart
        let reconstructed_proto_g1_commitment = g1_commitment_to_proto(&g1_commitment);

        let x_from_proto = Fq::from_be_bytes_mod_order(&reconstructed_proto_g1_commitment.x);
        let y_from_proto = Fq::from_be_bytes_mod_order(&reconstructed_proto_g1_commitment.y);

        // g1_commitment and proto x/y should be equal
        assert_eq!(x_from_proto, g1_commitment.x);
        assert_eq!(y_from_proto, g1_commitment.y);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g1_commitment_bytes = g1_commitment_to_bytes(&g1_commitment);
        assert_eq!(g1_commitment_bytes, proto_g1_commitment_bytes);
    }

    #[test]
    fn test_g1_commitment_utils_negative_point() {
        let proto_g1_commitment_bytes =
            hex::decode("d76bb41dda83295b242cf154a682b448504a3874ba4205b58e7a59988d6a85c0")
                .unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g1_commitment = g1_commitment_from_bytes(&proto_g1_commitment_bytes).unwrap();

        // We parse the point into its protobuf counterpart
        let reconstructed_proto_g1_commitment = g1_commitment_to_proto(&g1_commitment);

        let x_from_proto = Fq::from_be_bytes_mod_order(&reconstructed_proto_g1_commitment.x);
        let y_from_proto = Fq::from_be_bytes_mod_order(&reconstructed_proto_g1_commitment.y);

        // g1_commitment and proto x/y should be equal
        assert_eq!(x_from_proto, g1_commitment.x);
        assert_eq!(y_from_proto, g1_commitment.y);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g1_commitment_bytes = g1_commitment_to_bytes(&g1_commitment);
        assert_eq!(g1_commitment_bytes, proto_g1_commitment_bytes);
    }

    #[test]
    fn test_g2_commitment_utils() {
        let proto_g2_commitment_bytes = hex::decode("988473451189058256e788f4e93cb40fc38a9db4549e7b73078a1cc7992d735f2d447efe3e658d556c051fbf3c606f4de0c5d9d609e0170d098337949c2b97e6").unwrap();
        // let proto_g2_commitment_bytes = hex::decode("a6b7905ed5977e1882e0c33319402621ebc2d90fea4f162f926cb6f95180bdde2db3dddcb27fb709924ce96c60b51345ce0760f502d15f3940b7e5f2c95f4c66").unwrap();
        // let proto_g2_commitment_bytes = hex::decode("ea27d2ebb013ec41958e6ea9561dd584807020246b0a16a9a0f5c9ebf32266e72c62b908fbb84107c92ccc04a8120d48715a1e63367534af97f1486ed60ccb5b").unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g2_commitment = g2_commitment_from_bytes(&proto_g2_commitment_bytes).unwrap();

        // There's no proto struct for the G2Commitment, so we don't convert it
        // let reconstructed_proto_g2_commitment = g2_commitment_to_proto(&g2_commitment);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g2_commitment_bytes = g2_commitment_to_bytes(&g2_commitment);
        assert_eq!(g2_commitment_bytes, proto_g2_commitment_bytes);
    }
}
