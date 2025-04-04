use std::time::Duration;

use ark_ff::Zero;

use crate::accountant::Accountant;
use crate::core::{BlobKey, BlobRequestSigner, LocalBlobRequestSigner};
use crate::generated::disperser::v2::{
    disperser_client, BlobCommitmentReply, BlobCommitmentRequest, BlobStatusReply,
    BlobStatusRequest, GetPaymentStateReply, GetPaymentStateRequest,
};
use crate::prover::Prover;

#[derive(Debug)]
pub struct DisperserClientConfig {
    host: String,
    port: u16,
    timeout: Duration,
    use_secure_grpc_flag: bool,
    max_retrieve_blob_size_bytes: u64,
}

impl DisperserClientConfig {
    pub fn new(
        host: String,
        port: u16,
        use_secure_grpc_flag: bool,
        timeout: Duration,
        max_retrieve_blob_size_bytes: u64,
    ) -> Result<Self, String> {
        if host.is_empty() {
            return Err("host cannot be empty".to_string());
        }

        if timeout.is_zero() {
            return Err("timeout cannot be zero".to_string());
        }

        if max_retrieve_blob_size_bytes.is_zero() {
            return Err("max_retrieve_blob_size_bytes cannot be zero".to_string());
        }

        Ok(Self {
            host,
            port,
            use_secure_grpc_flag,
            timeout,
            max_retrieve_blob_size_bytes,
        })
    }
}

pub struct DisperserClient {
    config: DisperserClientConfig,
    signer: LocalBlobRequestSigner,
    rpc_client: disperser_client::DisperserClient<tonic::transport::Channel>,
    prover: Prover,
    accountant: Accountant,
}

impl DisperserClient {
    pub fn new(
        config: DisperserClientConfig,
        signer: LocalBlobRequestSigner,
        rpc_client: disperser_client::DisperserClient<tonic::transport::Channel>,
        prover: Prover,
        accountant: Accountant,
    ) -> Self {
        Self {
            config,
            signer,
            rpc_client,
            prover,
            accountant,
        }
    }

    pub fn disperse_blob(data: &[u8], quorums: &[u8]) {
        todo!()
    }

    /// Populates the accountant with the payment state from the disperser.
    async fn populate_accountant(&mut self) -> Result<(), String> {
        let payment_state = self.payment_state().await?;
        self.accountant.set_payment_state(&payment_state)?;
        Ok(())
    }

    /// Returns the status of a blob with the given blob key.
    pub async fn blob_status(&mut self, blob_key: BlobKey) -> Result<BlobStatusReply, String> {
        let request = BlobStatusRequest {
            blob_key: blob_key.to_bytes().to_vec(),
        };

        self.rpc_client
            .get_blob_status(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }

    /// Returns the payment state of the disperser client
    pub async fn payment_state(&mut self) -> Result<GetPaymentStateReply, String> {
        let account_id = self.signer.account_id()?.to_string();
        let signature = self.signer.sign_payment_state_request()?;
        let request = GetPaymentStateRequest {
            account_id,
            signature,
        };

        self.rpc_client
            .get_payment_state(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }

    pub async fn blob_commitment(&mut self, data: &[u8]) -> Result<BlobCommitmentReply, String> {
        let request = BlobCommitmentRequest {
            blob: data.to_vec(),
        };

        self.rpc_client
            .get_blob_commitment(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }
}
