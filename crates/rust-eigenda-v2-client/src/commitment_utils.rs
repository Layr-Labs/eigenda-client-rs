use ark_bn254::{G1Affine, G1Projective, G2Affine};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Fp, Fp2, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use rust_eigenda_cert::{BlobError, Bn254Error};
use rust_kzg_bn254_primitives::helpers::{lexicographically_largest, read_g1_point_from_bytes_be};

use crate::{errors::ConversionError, utils::fr_array_from_bytes};

const COMPRESSED_SMALLEST: u8 = 0b10 << 6;
const COMPRESSED_LARGEST: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;
const G2_COMPRESSED_SIZE: usize = 64;

fn generate_blob_commitment(
    g1_srs: Vec<G1Affine>,
    blob_bytes: &[u8],
) -> Result<G1Affine, BlobError> {
    let input_fr = fr_array_from_bytes(blob_bytes);

    if g1_srs.len() < input_fr.len() {
        return Err(Bn254Error::InsufficientSrsInMemory(g1_srs.len(), input_fr.len()).into());
    }

    let bases = g1_srs[0..input_fr.len()].to_vec();
    let commitment = G1Projective::msm(&bases, &input_fr)
        .map_err(|_| Bn254Error::FailedComputingMSM(bases, input_fr))?
        .into_affine();
    Ok(commitment)
}

/// Generates the kzg-bn254 commitment of the blob, and compares it with a claimed
/// commitment. An error is returned if there is a problem generating the commitment. True is returned if the commitment
/// is successfully generated, and is equal to the claimed commitment, otherwise false.
pub(crate) fn generate_and_compare_blob_commitment(
    g1_srs: Vec<G1Affine>,
    blob_bytes: Vec<u8>,
    claimed_commitment: G1Affine,
) -> Result<bool, BlobError> {
    let computed_commitment = generate_blob_commitment(g1_srs, &blob_bytes)?;
    Ok(claimed_commitment == computed_commitment)
}

/// Converts a byte slice to a [`G1Affine`] point.
/// The points received are in compressed form.
pub(crate) fn g1_commitment_from_bytes(bytes: &[u8]) -> Result<G1Affine, ConversionError> {
    read_g1_point_from_bytes_be(bytes).map_err(|e| ConversionError::G1Point(e.to_string()))
}

/// Serialize a G1Affine point applying necessary flags.
/// https://github.com/Consensys/gnark-crypto/blob/5fd6610ac2a1d1b10fae06c5e552550bf43f4d44/ecc/bn254/marshal.go#L790-L801
#[cfg(test)]
pub(crate) fn g1_commitment_to_bytes(point: &G1Affine) -> Result<Vec<u8>, ConversionError> {
    let mut bytes = vec![0u8; 32];

    // Infinity case
    if point.to_flags().is_infinity() {
        bytes[0] = COMPRESSED_INFINITY;
        return Ok(bytes);
    }

    // Get X bytes
    let mut x_bytes = Vec::new();
    point.x.serialize_compressed(&mut x_bytes)?;
    bytes.copy_from_slice(&x_bytes);
    bytes.reverse();

    // Determine most significant bits flag
    let mask = match lexicographically_largest(&point.y) {
        true => COMPRESSED_LARGEST,
        false => COMPRESSED_SMALLEST,
    };
    bytes[0] |= mask;

    Ok(bytes)
}

/// Converts a byte slice to a [`G2Affine`] point.
pub(crate) fn g2_commitment_from_bytes(bytes: &[u8]) -> Result<G2Affine, ConversionError> {
    if bytes.len() != 64 {
        return Err(ConversionError::G2Point(
            "Invalid length for G2 Commitment".to_string(),
        ));
    }

    // Get mask from most significant bits
    let msb_mask = bytes[0] & (COMPRESSED_INFINITY | COMPRESSED_SMALLEST | COMPRESSED_LARGEST);

    if msb_mask == COMPRESSED_INFINITY {
        return Ok(G2Affine::identity());
    }

    // Remove most significant bits mask
    let mut bytes = bytes.to_vec();
    bytes[0] &= !(COMPRESSED_INFINITY | COMPRESSED_SMALLEST | COMPRESSED_LARGEST);

    // Extract X from the compressed representation
    let x1 = Fp::from_be_bytes_mod_order(&bytes[0..32]);
    let x0 = Fp::from_be_bytes_mod_order(&bytes[32..64]);
    let x = Fp2::new(x0, x1);

    let mut point = G2Affine::get_point_from_x_unchecked(x, true).ok_or(
        ConversionError::G2Point("Failed to read G2 Commitment from x bytes".to_string()),
    )?;

    // Ensure Y has the correct lexicographic property
    let mut lex_largest = lexicographically_largest(&point.y.c1);
    if !lex_largest && point.y.c1.is_zero() {
        lex_largest = lexicographically_largest(&point.y.c0);
    }
    if (msb_mask == COMPRESSED_LARGEST) != lex_largest {
        point.y.neg_in_place();
    }

    Ok(point)
}

/// Convert bytes from little-endian to big-endian and vice versa.
fn switch_endianess(bytes: &mut Vec<u8>) {
    // Remove leading zeroes
    let mut filtered_bytes: Vec<u8> = bytes.iter().copied().skip_while(|&x| x == 0).collect();

    filtered_bytes.reverse();

    while filtered_bytes.len() != G2_COMPRESSED_SIZE {
        filtered_bytes.push(0);
    }

    *bytes = filtered_bytes;
}

/// Converts a [`G2Affine`] point to a byte slice applying necessary flags.
pub fn g2_commitment_to_bytes(point: &G2Affine) -> Result<Vec<u8>, ConversionError> {
    let mut bytes = vec![0u8; 64];
    if point.to_flags().is_infinity() {
        bytes[0] |= COMPRESSED_INFINITY;
        return Ok(bytes);
    }
    point.serialize_compressed(&mut bytes)?;
    switch_endianess(&mut bytes);

    let mut lex_largest = lexicographically_largest(&point.y.c1);
    if !lex_largest && point.y.c1.is_zero() {
        lex_largest = lexicographically_largest(&point.y.c0);
    }

    let mask = match lex_largest {
        true => COMPRESSED_LARGEST,
        false => COMPRESSED_SMALLEST,
    };

    bytes[0] |= mask;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq;
    use ark_ff::{BigInteger, UniformRand};

    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::generated::common::G1Commitment;

    use super::*;

    pub fn g1_commitment_to_proto(point: &G1Affine) -> G1Commitment {
        let x = point.x.into_bigint().to_bytes_be();
        let y = point.y.into_bigint().to_bytes_be();
        G1Commitment { x, y }
    }

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
        let g1_commitment_bytes = g1_commitment_to_bytes(&g1_commitment).unwrap();
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
        let g1_commitment_bytes = g1_commitment_to_bytes(&g1_commitment).unwrap();
        assert_eq!(g1_commitment_bytes, proto_g1_commitment_bytes);
    }

    #[test]
    fn test_g1_commitment_utils_infinity_point() {
        let proto_g1_commitment_bytes =
            hex::decode("4000000000000000000000000000000000000000000000000000000000000000")
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
        let g1_commitment_bytes = g1_commitment_to_bytes(&g1_commitment).unwrap();
        assert_eq!(g1_commitment_bytes, proto_g1_commitment_bytes);
    }

    #[test]
    fn test_g2_commitment_utils_lexicographically_smallest() {
        let proto_g2_commitment_bytes = hex::decode("a8ebbcc06346864939a08f3a1a87f82b0d8511c406383af82cd0381470bc38eb21481f91983ca56afcd8386b4a835c5bd5629bec45c555dab4c18c9072bc2b61").unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g2_commitment = g2_commitment_from_bytes(&proto_g2_commitment_bytes).unwrap();

        // There's no proto struct for the G2Commitment, so we don't convert it
        // let reconstructed_proto_g2_commitment = g2_commitment_to_proto(&g2_commitment);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g2_commitment_bytes = g2_commitment_to_bytes(&g2_commitment).unwrap();
        assert_eq!(g2_commitment_bytes, proto_g2_commitment_bytes);
    }

    #[test]
    fn test_g2_commitment_utils_lexicographically_largest() {
        let proto_g2_commitment_bytes = hex::decode("d6c493f305050465bbb90a1fccb62f0b6e669c1e83041621b1b1df0ea4f60aab15762d4d538d39357c114426c917d1221de5fe5b276f648e9c650611e09562c0").unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g2_commitment = g2_commitment_from_bytes(&proto_g2_commitment_bytes).unwrap();

        // There's no proto struct for the G2Commitment, so we don't convert it
        // let reconstructed_proto_g2_commitment = g2_commitment_to_proto(&g2_commitment);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g2_commitment_bytes = g2_commitment_to_bytes(&g2_commitment).unwrap();
        assert_eq!(g2_commitment_bytes, proto_g2_commitment_bytes);
    }

    #[test]
    fn test_g2_commitment_utils_infinity_point() {
        let proto_g2_commitment_bytes = hex::decode("40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        // Proto returns a byte array from which we deserialize the point
        let g2_commitment = g2_commitment_from_bytes(&proto_g2_commitment_bytes).unwrap();

        // There's no proto struct for the G2Commitment, so we don't convert it
        // let reconstructed_proto_g2_commitment = g2_commitment_to_proto(&g2_commitment);

        // If we serialize the point to bytes it should be equal to the original hex string
        let g2_commitment_bytes = g2_commitment_to_bytes(&g2_commitment).unwrap();
        assert_eq!(g2_commitment_bytes, proto_g2_commitment_bytes);
    }

    fn test_g1_point_conversion(point: G1Affine) {
        let bytes = g1_commitment_to_bytes(&point).unwrap();
        let reconstructed_point = g1_commitment_from_bytes(&bytes).unwrap();
        assert_eq!(reconstructed_point, point);
    }

    fn g1_affine_strategy() -> impl Strategy<Value = G1Affine> {
        any::<[u8; 32]>().prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            G1Affine::rand(&mut rng)
        })
    }

    fn test_g2_point_conversion(point: G2Affine) {
        let bytes = g2_commitment_to_bytes(&point).unwrap();
        let reconstructed_point = g2_commitment_from_bytes(&bytes).unwrap();
        assert_eq!(reconstructed_point, point);
    }

    fn g2_affine_strategy() -> impl Strategy<Value = G2Affine> {
        any::<[u8; 32]>().prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            G2Affine::rand(&mut rng)
        })
    }

    proptest! {
        #[test]
        fn fuzz_g1_point_conversion(g1_point in g1_affine_strategy()) {
            test_g1_point_conversion(g1_point);
        }

        #[test]
        fn fuzz_g2_point_conversion(g2_point in g2_affine_strategy()) {
            test_g2_point_conversion(g2_point);
        }
    }
}
