use std::str::FromStr;

use alloy::{network::Ethereum, providers::RootProvider};

use crate::{
    contracts_bindings::IEigenDACertVerifier::{self},
    core::eigenda_cert::{EigenDACert, NonSignerStakesAndSignature, SignedBatch},
    errors::CertVerifierError,
    generated::disperser::v2::SignedBatch as SignedBatchProto,
};

pub type CertVerifierContract =
    IEigenDACertVerifier::IEigenDACertVerifierInstance<RootProvider<Ethereum>>;

pub struct CertVerifier {
    cert_verifier_contract: CertVerifierContract,
}

impl CertVerifier {
    pub fn new(address: String, rpc_url: String) -> Self {
        let url = alloy::transports::http::reqwest::Url::from_str(&rpc_url).unwrap();
        let provider: RootProvider<Ethereum> = RootProvider::new_http(url);

        let cer_verifier_address = alloy::primitives::Address::from_str(&address).unwrap();
        let cert_verifier_contract: IEigenDACertVerifier::IEigenDACertVerifierInstance<
            RootProvider,
        > = IEigenDACertVerifier::new(cer_verifier_address, provider);
        CertVerifier {
            cert_verifier_contract,
        }
    }
    pub async fn get_non_signer_stakes_and_signature(
        &self,
        signed_batch: SignedBatchProto,
    ) -> Result<NonSignerStakesAndSignature, CertVerifierError> {
        let signed_batch: SignedBatch = signed_batch.try_into()?;
        let contract_signed_batch = signed_batch.into();
        let non_signer_stakes_and_signature = self
            .cert_verifier_contract
            .getNonSignerStakesAndSignature(contract_signed_batch)
            .call()
            .await?;

        Ok(non_signer_stakes_and_signature.into())
    }

    pub async fn quorum_numbers_required(&self) -> Result<Vec<u8>, CertVerifierError> {
        let quorums = self
            .cert_verifier_contract
            .quorumNumbersRequired()
            .call()
            .await?;
        Ok(quorums.to_vec())
    }

    pub async fn verify_cert_v2(
        &self,
        eigenda_cert: &EigenDACert,
    ) -> Result<(), CertVerifierError> {
        self.cert_verifier_contract
            .verifyDACertV2(
                eigenda_cert.batch_header.clone().into(),
                eigenda_cert.blob_inclusion_info.clone().into(),
                eigenda_cert.non_signer_stakes_and_signature.clone().into(),
                eigenda_cert.signed_quorum_numbers.clone().into(),
            )
            .call()
            .await?;
        Ok(())
    }
}
