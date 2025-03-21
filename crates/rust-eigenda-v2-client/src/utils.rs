use crate::errors::ConversionError;
use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

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

/// computeEvalPoly converts a blob's coeff_poly to an eval_poly, using the FFT operation
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
