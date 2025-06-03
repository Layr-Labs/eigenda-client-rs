use ark_bn254::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use rust_eigenda_v2_common::BlobCommitments;
use rust_kzg_bn254_primitives::helpers::{pairings_verify, to_byte_array};
use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};

use crate::{
    errors::ValidatorVerifierError,
    eth_client::EthClient,
    validator_encoder::ValidatorEncoder,
    validator_types::{ChunkNumber, EncodingParams, Frame},
};

/// Trait that defines the methods for the verifier used by the validator client
#[async_trait::async_trait]
pub trait ValidatorVerifier: Sync + Send + std::fmt::Debug {
    async fn verify_frames(
        &self,
        chunks: &[Frame],
        indices: &[ChunkNumber],
        commitments: BlobCommitments,
        params: EncodingParams,
        kzg: KZG,
        srs: SRS,
    ) -> Result<(), ValidatorVerifierError>;

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: Vec<BlobCommitments>,
    ) -> Result<(), ValidatorVerifierError>;

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        max_input_size: usize,
    ) -> Result<Vec<u8>, ValidatorVerifierError>;
}

#[async_trait::async_trait]
impl ValidatorVerifier for EthClient {
    async fn verify_frames(
        &self,
        frames: &[Frame],
        indices: &[ChunkNumber],
        commitments: BlobCommitments,
        params: EncodingParams,
        kzg: KZG,
        srs: SRS,
    ) -> Result<(), ValidatorVerifierError> {
        if frames.len() != indices.len() {
            panic!(
                "invalid number of frames and indices: {} != {}",
                frames.len(),
                indices.len()
            );
        }

        for (i, frame) in frames.iter().enumerate() {
            let j = match (indices[i] as u64) < params.num_chunks {
                true => {
                    // Equivalent of: ReverseBitsLimited(uint32(numChunks), uint32(i)) in go
                    let length = params.num_chunks;
                    let value = indices[i];
                    let used_bits = 32 - length.leading_zeros();
                    let unused_bit_len = 32 - used_bits;
                    value.reverse_bits() >> unused_bit_len
                }
                false => panic!("cannot create number of frame higher than possible"),
            };

            let n = frame.coeffs.len();
            if n >= srs.order as usize {
                panic!(
                    "requested power {} is larger than SRSOrder {}",
                    n, srs.order
                );
            }
            // TODO: should be: kzg.get_g2_points()[n];
            // But we don't have access to this method with the new kzg/srs structs
            let g2_at_n = G2Affine::default();

            let commitment = commitments.commitment;

            // TODO: We might not be using the expanded roots of unity here.
            // maybe use directly: `calculate_roots_of_unity` with a correct value
            // for `length_of_data_after_padding`.
            // line bellow might panic due to index out of bounds:
            let x = &kzg.get_roots_of_unities()[j];

            let mut x_pow = Fr::ONE;
            for _ in 0..frame.coeffs.len() {
                x_pow *= x
            }

            // [x^n]_2
            let xn2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y)
                .mul_bigint(x_pow.into_bigint());

            // [s^n - x^n]_2
            let xn_minus_yn = (g2_at_n - xn2).into_affine();

            // [interpolation_polynomial(s)]_1
            let srs_g1 = srs.g1[0..frame.coeffs.len()].to_vec();
            let is1 = G1Projective::msm(&srs_g1, &frame.coeffs)
                .unwrap()
                .into_affine();

            // [commitment - interpolation_polynomial(s)]_1 = [commit]_1 - [interpolation_polynomial(s)]_1
            let commit_minus_interpolation = (commitment - is1).into_affine();

            // Verify the pairing equation
            //
            // e([commitment - interpolation_polynomial(s)], [1]) = e([proof],  [s^n - x^n])
            //    equivalent to
            // e([commitment - interpolation_polynomial]^(-1), [1]) * e([proof],  [s^n - x^n]) = 1_T
            //
            let kzg_gen_g2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y);
            if !pairings_verify(
                commit_minus_interpolation,
                kzg_gen_g2,
                frame.proof,
                xn_minus_yn,
            ) {
                return Err(ValidatorVerifierError::FailedToVerifyCommitEquivalenceBatch);
            };
        }

        Ok(())
    }

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: Vec<BlobCommitments>,
    ) -> Result<(), ValidatorVerifierError> {
        let commitments_amount = commitments.len();
        let mut g1commits = Vec::new();
        let mut g2commits = Vec::new();

        for blob_commitment in commitments {
            g1commits.push(blob_commitment.commitment);
            g2commits.push(blob_commitment.length_commitment);
        }

        let mut random_scalars = Vec::new();
        for _ in 0..commitments_amount {
            random_scalars.push(Fr::rand(&mut rand::thread_rng())); // TODO: USE OTHER RNG!
        }

        let lhs_g1 = G1Projective::msm(&g1commits, &random_scalars)
            .unwrap()
            .into_affine();
        let lhs_g2 = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y);
        let rhs_g1 = G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
        let rhs_g2 = G2Projective::msm(&g2commits, &random_scalars)
            .unwrap()
            .into_affine();

        if !pairings_verify(lhs_g1, lhs_g2, rhs_g1, rhs_g2) {
            return Err(ValidatorVerifierError::FailedToVerifyCommitEquivalenceBatch);
        };
        Ok(())
    }

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        max_input_size: usize,
    ) -> Result<Vec<u8>, ValidatorVerifierError> {
        let encoder = ValidatorEncoder::from_params(params);
        let mut frames = Vec::new();
        for chunk in chunks {
            frames.push(chunk.coeffs);
        }

        let chunk_len = encoder.chunk_len as usize;
        let data_len = (max_input_size + chunk_len - 1) / chunk_len;
        let num_sys = data_len / chunk_len;
        if frames.len() < num_sys {
            panic!("number of frame must be sufficient")
        }

        let mut samples: Vec<Option<Fr>> = vec![None; encoder.num_evaluations() as usize];
        // copy evals based on frame coeffs into samples
        for (i, chunk_number) in indices.iter().enumerate() {
            let frame = frames[i].clone();
            let e = match *chunk_number < encoder.num_chunks as usize {
                true => {
                    let value = *chunk_number;
                    let bit_index = if encoder.num_chunks == 0 {
                        0
                    } else {
                        32 - (encoder.num_chunks - 1).leading_zeros()
                    };
                    let unused_bit_len = 32 - bit_index;
                    value.reverse_bits() >> unused_bit_len
                }
                false => panic!("cannot create number of frame higher than possible"),
            };

            let evals = encoder.get_interpolation_poly_eval(&frame, e);

            // Some pattern i butterfly swap. Find the leading coset, then increment by number of coset
            for j in 0..chunk_len {
                let p = j * encoder.num_chunks as usize + e;
                samples.insert(p, Some(evals[j]));
            }
        }

        // We assume that if any Fr is still default after filling data,
        // then there are missing Frs.
        let reconstructed_data = match samples.iter().any(|sample| sample.is_none()) {
            true => encoder.recover_poly_from_samples(samples),
            false => samples.iter().map(|s| s.unwrap()).collect(), // Safe to unwrap as we check above that all are `Some`
        };

        let reconstructed_poly = encoder.fft(reconstructed_data, true);

        Ok(to_byte_array(&reconstructed_poly, max_input_size))
    }
}
