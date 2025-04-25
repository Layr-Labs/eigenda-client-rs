use std::str::FromStr;

use crate::{
    core::BYTES_PER_SYMBOL,
    errors::{ConversionError, EigenClientError},
};
use ark_bn254::Fr;
use ark_ff::fields::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rust_eigenda_cert::{BlobHeader, BlobKey};
use secrecy::{ExposeSecret, Secret};
use url::Url;

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

impl TryFrom<SecretUrl> for String {
    type Error = ConversionError;

    fn try_from(secret_url: SecretUrl) -> Result<Self, Self::Error> {
        Ok(secret_url.inner.expose_secret().clone())
    }
}

impl PartialEq for SecretUrl {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret().eq(other.inner.expose_secret())
    }
}

/// Secretly enclosed Private Key
#[derive(Debug, Clone)]
pub struct PrivateKey(pub Secret<String>);

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret().eq(other.0.expose_secret())
    }
}

impl FromStr for PrivateKey {
    type Err = EigenClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PrivateKey(
            s.parse().map_err(|_| ConversionError::PrivateKey)?,
        ))
    }
}

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

pub(crate) fn pad_to_bytes_per_symbol(input_bytes: &[u8]) -> Vec<u8> {
    let remainder = input_bytes.len() % BYTES_PER_SYMBOL;
    match remainder == 0 {
        true => {
            // no padding necessary, since bytes are already a multiple of BYTES_PER_SYMBOL
            input_bytes.to_vec()
        }
        false => {
            let necessary_padding = BYTES_PER_SYMBOL - remainder;
            let mut padded_bytes = input_bytes.to_vec();
            padded_bytes.extend(vec![0; necessary_padding]);
            padded_bytes
        }
    }
}

/// fr_array_from_bytes accept a byte array as an input, and converts it to an array of field elements
pub(crate) fn fr_array_from_bytes(input_data: &[u8]) -> Vec<Fr> {
    let bytes = pad_to_bytes_per_symbol(input_data);

    let element_count = bytes.len() / BYTES_PER_SYMBOL;
    let mut output_elements = Vec::new();
    for i in 0..element_count {
        let start_idx = i * BYTES_PER_SYMBOL;
        let end_idx = start_idx + BYTES_PER_SYMBOL;
        output_elements.push(Fr::from_be_bytes_mod_order(&bytes[start_idx..end_idx]))
    }
    output_elements
}

pub(crate) fn get_blob_key(
    blob_header: &BlobHeader,
) -> Result<BlobKey, rust_eigenda_cert::ConversionError> {
    BlobKey::compute_blob_key(blob_header)
}
