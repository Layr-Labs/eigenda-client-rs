use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};

use crate::validator_types::EncodingParams;

#[derive(Clone)]
pub struct ValidatorEncoder {
    pub(crate) num_chunks: u64, // number of total chunks that are padded to power of 2
    pub(crate) chunk_len: u64,  // number of Fr symbol stored inside a chunk
}

impl ValidatorEncoder {
    pub(crate) fn from_params(params: EncodingParams) -> Self {
        Self {
            num_chunks: params.num_chunks,
            chunk_len: params.chunk_len,
        }
    }

    pub(crate) fn num_evaluations(&self) -> u64 {
        self.num_chunks * self.chunk_len
    }

    // https://github.com/Layr-Labs/eigenda/blob/57a7b3b20907dfe0f46dc534a0d2673203e69267/encoding/rs/interpolation.go#L19
    pub(crate) fn get_interpolation_poly_eval(
        &self,
        interpolation_poly: &[Fr],
        j: usize,
    ) -> Vec<Fr> {
        unimplemented!()
    }

    fn zero_poly_via_multiplication(
        &self,
        missing_indices: Vec<usize>,
        length: u64,
    ) -> (Vec<Fr>, Vec<Fr>) {
        unimplemented!()
    }

    pub(crate) fn recover_poly_from_samples(&self, samples: Vec<Option<Fr>>) -> Vec<Fr> {
        // TODO: using a single additional temporary array, all the FFTs can run in-place.

        let mut missing_indices = Vec::new();
        for (i, sample) in samples.iter().enumerate() {
            if sample.is_none() {
                missing_indices.push(i);
            }
        }

        let (zero_eval, mut zero_poly) =
            self.zero_poly_via_multiplication(missing_indices, samples.len() as u64);

        for (i, sample) in samples.iter().enumerate() {
            let eval_at_i = zero_eval[i];
            if (sample.is_none()) != (eval_at_i.into_bigint().is_zero()) {
                panic!("bad zero eval")
            }
        }

        let mut poly_evaluations_with_zero = Vec::new();
        for (i, sample) in samples.iter().enumerate() {
            if let Some(sample) = sample {
                poly_evaluations_with_zero.push(*sample * zero_eval[i])
            } else {
                poly_evaluations_with_zero.push(Fr::ZERO);
            }
        }

        let mut poly_with_zero = self.fft(poly_evaluations_with_zero, true);

        // shift in-place
        self.shift_poly(&mut poly_with_zero);
        let shifted_poly_with_zero = poly_with_zero;

        self.shift_poly(&mut zero_poly);
        let shifted_zero_poly = zero_poly;

        let eval_shifted_poly_with_zero = self.fft(shifted_poly_with_zero, false);
        let eval_shifted_zero_poly = self.fft(shifted_zero_poly, false);

        let mut eval_shifted_reconstructed_poly = eval_shifted_poly_with_zero;
        for i in 0..eval_shifted_reconstructed_poly.len() {
            eval_shifted_reconstructed_poly[i] =
                eval_shifted_reconstructed_poly[i] / eval_shifted_zero_poly[i]
        }

        let mut shifted_reconstructed_poly = self.fft(eval_shifted_reconstructed_poly, true);
        self.unshift_poly(&mut shifted_reconstructed_poly);
        let reconstructed_poly = shifted_reconstructed_poly;

        let reconstructed_data = self.fft(reconstructed_poly, false);

        for (i, sample) in samples.iter().enumerate() {
            if let Some(sample) = sample {
                if reconstructed_data[i] != *sample {
                    panic!("failed to reconstruct data correctly, changed value at index {}. Expected: {:?}, got: {:?}", i, sample, reconstructed_data[i])
                }
            }
        }

        reconstructed_data
    }

    pub(crate) fn fft(&self, data: Vec<Fr>, inv: bool) -> Vec<Fr> {
        unimplemented!()
    }

    fn shift_poly(&self, poly: &mut Vec<Fr>) {
        unimplemented!()
    }

    fn unshift_poly(&self, poly: &mut Vec<Fr>) {
        unimplemented!()
    }
}
