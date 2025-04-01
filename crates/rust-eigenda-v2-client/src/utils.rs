use crate::errors::ConversionError;
use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use secrecy::{ExposeSecret,Secret};
use url::Url;

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

#[derive(Debug, Clone)]
/// A URL stored securely using the `Secret` type from the secrecy crate
pub struct SecretUrl {
    // We keep the URL as a String because Secret<T> enforces T: DefaultIsZeroes
    // which is not the case for the type Url
    inner: Secret<String>,
}

impl SecretUrl {
    /// Create a new `SecretUrl` from a `Url`
    pub fn new(url: Url) -> Self {
        Self {
            inner: Secret::new(url.to_string()),
        }
    }
}

impl From<SecretUrl> for Url {
    fn from(secret_url: SecretUrl) -> Self {
        Url::parse(secret_url.inner.expose_secret()).unwrap() // Safe to unwrap, as the `new` fn ensures the URL is valid
    }
}

impl PartialEq for SecretUrl {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret().eq(other.inner.expose_secret())
    }
}
