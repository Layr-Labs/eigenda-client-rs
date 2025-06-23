use ark_bn254::{G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};

use crate::{
    errors::{BlobError, Bn254Error},
    utils::fr_array_from_bytes,
};

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

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, G2Affine};
    use ark_ff::{BigInteger, PrimeField, UniformRand};

    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};
    use rust_eigenda_v2_common::{
        g1_commitment_from_bytes, g1_commitment_to_bytes, g2_commitment_from_bytes,
        g2_commitment_to_bytes,
    };

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
