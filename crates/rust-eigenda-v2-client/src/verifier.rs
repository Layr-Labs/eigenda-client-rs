use ethabi::{Address, ParamType, Token};

use crate::{core::eigenda_cert::{self, EigenDACert}, errors::EigenClientError, eth_client::EthClient};

/// Trait that defines the methods for the ethclient used by the verifier, needed in order to mock it for tests
#[async_trait::async_trait]
pub(crate) trait CertVerifierClient: Sync + Send + std::fmt::Debug {
    /// Request to the EigenDA service manager contract
    /// the batch metadata hash for a given batch id
    async fn verify_cert_v2(
        &self,
        eigenda_cert: &EigenDACert,
    ) -> Result<(), EigenClientError>;
}

#[async_trait::async_trait]
impl CertVerifierClient for EthClient {
    async fn verify_cert_v2(
        &self,
        eigenda_cert: &EigenDACert,
    ) -> Result<(), EigenClientError> {
        let reference_block_number = eigenda_cert.batch_header.reference_block_number;
        let func_selector =
            ethabi::short_signature("verifyCertV2", &[
                ParamType::Tuple(vec![
                    ParamType::FixedBytes(32),
                    ParamType::Uint(32),
                ]), // batch_header
                ParamType::Tuple(vec![
                    ParamType::Tuple(vec![
                        ParamType::Tuple(vec![
                            ParamType::Uint(16),
                            ParamType::Bytes,
                            ParamType::Tuple(vec![
                                ParamType::Tuple(vec![
                                    ParamType::Uint(256),
                                    ParamType::Uint(256)
                                ]), // commitment
                                ParamType::Tuple(vec![
                                    ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                                ]), // length commitment
                                ParamType::Tuple(vec![
                                    ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                                ]), // length proof
                                ParamType::Uint(32),
                            ]), // blob_commitment
                            ParamType::FixedBytes(32),
                        ]), // blob_header
                        ParamType::Bytes,
                        ParamType::Array(Box::new(ParamType::Uint(32))),
                    ]), // blob_certificate
                    ParamType::Uint(32),
                    ParamType::Bytes,
                ]), // blob_inclusion_info
                ParamType::Tuple(vec![
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]))),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]))),
                    ParamType::Tuple(vec![
                        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                    ]),
                    ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]),
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::Uint(32)),))),
                ]), // non_signer_stakes_and_signature
                ParamType::Bytes,
            ]);
        let mut data = func_selector.to_vec();
        data.append(&mut ethabi::encode(&eigenda_cert.batch_header.to_tokens()));
        data.append(&mut ethabi::encode(&eigenda_cert.blob_inclusion_info.to_tokens()));
        data.append(&mut ethabi::encode(&eigenda_cert.non_signer_stakes_and_signature.to_tokens()));
        data.append(&mut ethabi::encode(&[Token::Bytes(eigenda_cert.signed_quorum_numbers.clone())]));

        self
            .call(
                self.cert_verifier_addr,
                bytes::Bytes::copy_from_slice(&data),
                Some(reference_block_number as u64),
            )
            .await
            .map_err(EigenClientError::EthClient)?;

        Ok(())
    }
}

struct Verifier<T: CertVerifierClient> {
    eth_client: T,
}

impl<T: CertVerifierClient> Verifier<T> {
    pub async fn verify_cert_v2(&self, eigenda_cert: &EigenDACert) -> Result<(), EigenClientError> {
        self.eth_client.verify_cert_v2(eigenda_cert).await
    }
}
