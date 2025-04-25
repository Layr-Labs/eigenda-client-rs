use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, Fp, Fp2, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use rust_kzg_bn254_primitives::helpers::{lexicographically_largest, read_g1_point_from_bytes_be};

use crate::ConversionError;

const COMPRESSED_SMALLEST: u8 = 0b10 << 6;
const COMPRESSED_LARGEST: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;
const G2_COMPRESSED_SIZE: usize = 64;

/// g1_commitment_from_bytes converts a byte slice to a G1Affine point.
/// The points received are in compressed form.
pub fn g1_commitment_from_bytes(bytes: &[u8]) -> Result<G1Affine, ConversionError> {
    read_g1_point_from_bytes_be(bytes).map_err(|e| ConversionError::G1Point(e.to_string()))
}

/// Serialize a G1Affine point applying necessary flags.
/// https://github.com/Consensys/gnark-crypto/blob/5fd6610ac2a1d1b10fae06c5e552550bf43f4d44/ecc/bn254/marshal.go#L790-L801
pub fn g1_commitment_to_bytes(point: &G1Affine) -> Result<Vec<u8>, ConversionError> {
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

/// g2_commitment_from_bytes converts a byte slice to a G2Affine point.
pub fn g2_commitment_from_bytes(bytes: &[u8]) -> Result<G2Affine, ConversionError> {
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

    let mut point = G2Affine::get_point_from_x_unchecked(x, true).unwrap();
    // .ok_or(
    //     ConversionError::G2Point("Failed to read G2 Commitment from x bytes".to_string()),
    // )?;

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

/// Serialize a G2Affine point applying necessary flags.
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
