use crate::{
    cert_verifier::CertVerifier,
    core::{eigenda_cert::EigenDACert, BlobKey, Payload, PayloadForm},
    disperser_client::{DisperserClient, DisperserClientConfig},
    errors::{ConversionError, EigenClientError, PayloadDisperserError},
    generated::disperser::v2::{BlobStatus, BlobStatusReply},
};

#[derive(Clone)]
pub struct PayloadDisperserConfig {
    polynomial_form: PayloadForm,
    blob_version: u16,
    cert_verifier_address: String,
    eth_rpc_url: String,
}

/// PayloadDisperser provides the ability to disperse payloads to EigenDA via a Disperser grpc service.
pub struct PayloadDisperser {
    config: PayloadDisperserConfig,
    disperser_client: DisperserClient,
    cert_verifier: CertVerifier,
    required_quorums: Vec<u8>,
}

impl PayloadDisperser {
    /// Creates a PayloadDisperser from the specified configs.
    pub async fn new(
        disperser_config: DisperserClientConfig,
        payload_config: PayloadDisperserConfig,
    ) -> Result<Self, PayloadDisperserError> {
        let disperser_client = DisperserClient::new(disperser_config).await?;
        let cert_verifier = CertVerifier::new(
            payload_config.cert_verifier_address.clone(),
            payload_config.eth_rpc_url.clone(),
        );
        let required_quorums = cert_verifier.quorum_numbers_required().await?;
        Ok(PayloadDisperser {
            disperser_client,
            config: payload_config,
            cert_verifier,
            required_quorums,
        })
    }

    /// Executes the dispersal of a payload, returning the associated blob key
    pub async fn send_payload(
        &mut self,
        payload: Payload,
    ) -> Result<BlobKey, PayloadDisperserError> {
        let blob = payload.to_blob(self.config.polynomial_form)?;

        let (blob_status, blob_key) = self
            .disperser_client
            .disperse_blob(
                &blob.serialize(),
                self.config.blob_version,
                &self.required_quorums,
            )
            .await?;

        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => {
                return Err(PayloadDisperserError::BlobStatus);
            }
            BlobStatus::Complete
            | BlobStatus::Encoded
            | BlobStatus::GatheringSignatures
            | BlobStatus::Queued => {}
        }
        Ok(blob_key)
    }

    /// Retrieves the inclusion data for a given blob key
    /// If the requested blob is still not complete, returns None
    pub async fn get_inclusion_data(
        &mut self,
        blob_key: &BlobKey,
    ) -> Result<Option<EigenDACert>, EigenClientError> {
        let status = self
            .disperser_client
            .blob_status(blob_key)
            .await
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Disperser(e)))?;

        let blob_status = BlobStatus::try_from(status.status)
            .map_err(|e| EigenClientError::PayloadDisperser(PayloadDisperserError::Decode(e)))?;
        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => Err(PayloadDisperserError::BlobStatus)?,
            BlobStatus::Encoded | BlobStatus::GatheringSignatures | BlobStatus::Queued => Ok(None),
            BlobStatus::Complete => {
                let eigenda_cert = self.build_eigenda_cert(&status).await?;
                self.cert_verifier
                    .verify_cert_v2(&eigenda_cert)
                    .await
                    .map_err(|e| {
                        EigenClientError::PayloadDisperser(PayloadDisperserError::CertVerifier(e))
                    })?;
                Ok(Some(eigenda_cert))
            }
        }
    }

    /// Creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub async fn build_eigenda_cert(
        &self,
        status: &BlobStatusReply,
    ) -> Result<EigenDACert, EigenClientError> {
        let signed_batch = match status.clone().signed_batch {
            Some(batch) => batch,
            None => {
                return Err(EigenClientError::PayloadDisperser(
                    PayloadDisperserError::Conversion(ConversionError::SignedBatch(
                        "Not Present".to_string(),
                    )),
                ))
            }
        };
        let non_signer_stakes_and_signature = self
            .cert_verifier
            .get_non_signer_stakes_and_signature(signed_batch)
            .await
            .map_err(|e| {
                EigenClientError::PayloadDisperser(PayloadDisperserError::CertVerifier(e))
            })?;

        let cert = EigenDACert::new(status, non_signer_stakes_and_signature)?;

        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        core::{Payload, PayloadForm},
        disperser_client::DisperserClientConfig,
        payload_disperser::{PayloadDisperser, PayloadDisperserConfig},
    };

    use dotenv::dotenv;
    use std::env;

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_disperse_payload() {
        dotenv().ok();

        let timeout = tokio::time::Duration::from_secs(180);

        // Set your private key in .env file
        let private_key: String =
            env::var("SIGNER_PRIVATE_KEY").expect("SIGNER_PRIVATE_KEY must be set");

        let disperser_config = DisperserClientConfig {
            disperser_rpc: "https://disperser-testnet-holesky.eigenda.xyz".to_string(),
            private_key,
            use_secure_grpc_flag: false,
        };

        let payload_config = PayloadDisperserConfig {
            polynomial_form: PayloadForm::Coeff,
            blob_version: 0,
            cert_verifier_address: "0xFe52fE1940858DCb6e12153E2104aD0fDFbE1162".to_string(),
            eth_rpc_url: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
        };

        let mut payload_disperser = PayloadDisperser::new(disperser_config, payload_config)
            .await
            .unwrap();

        let payload = Payload::new(vec![1, 2, 3, 4, 5]);
        let blob_key = payload_disperser.send_payload(payload).await.unwrap();

        let mut finished = false;
        let start_time = tokio::time::Instant::now();
        while !finished {
            let inclusion_data = payload_disperser
                .get_inclusion_data(&blob_key)
                .await
                .unwrap();
            match inclusion_data {
                Some(cert) => {
                    println!("Inclusion data: {:?}", cert);
                    finished = true;
                }
                None => {
                    let elapsed = start_time.elapsed();
                    assert!(elapsed < timeout, "Timeout waiting for inclusion data");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}
