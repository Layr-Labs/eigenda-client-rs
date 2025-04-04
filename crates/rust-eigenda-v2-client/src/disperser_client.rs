use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_ff::Zero;
use rust_kzg_bn254_primitives::helpers::to_fr_array;

use crate::accountant::Accountant;
use crate::core::eigenda_cert::{BlobCommitment, BlobHeader};
use crate::core::{BlobKey, BlobRequestSigner, LocalBlobRequestSigner};
use crate::generated::common::v2::{BlobHeader as BlobHeaderProto, PaymentHeader};
use crate::generated::common::BlobCommitment as BlobCommitmentProto;
use crate::generated::disperser::v2::{
    disperser_client, BlobCommitmentReply, BlobCommitmentRequest, BlobStatus, BlobStatusReply, BlobStatusRequest, DisperseBlobRequest, GetPaymentStateReply, GetPaymentStateRequest
};
use crate::prover::Prover;

const MAX_QUORUM_ID: u8 = 255;
const BYTES_PER_SYMBOL: usize = 32;

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

// todo: add locks
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

    //todo: error handling
    pub async fn disperse_blob(&mut self, data: &[u8], blob_version: u16, quorums: &[u8]) -> Result<(BlobStatus,BlobKey), String> {
        if quorums.is_empty() {
            return Err("quorum numbers must be provided".to_string());
        }

        for quorum in quorums {
            if *quorum > MAX_QUORUM_ID {
                return Err("quorum number must be less than 256".to_string());
            }
        }
        
        let symbol_length = ((data.len() + BYTES_PER_SYMBOL - 1)/ BYTES_PER_SYMBOL).next_power_of_two();
        let payment = self.accountant.account_blob(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64, symbol_length as u64, quorums).unwrap();
        //to_fr_array(data); //doesn't return error so no need to do the check

        // if prover is null: //todo: prover not null
        let blob_commitment_reply = self.blob_commitment(data).await?;
        let Some(blob_commitment) = blob_commitment_reply.blob_commitment else {
            return Err("blob commitment is empty".to_string());
        };
        let core_blob_commitment: BlobCommitment = blob_commitment.try_into().unwrap();
        if core_blob_commitment.length != symbol_length as u32 {
            return Err(format!(
                "blob commitment length {} does not match symbol length {}",
                core_blob_commitment.length, symbol_length
            ));
        }

        let blob_header = BlobHeader {
            version: blob_version,
            commitment: core_blob_commitment,
            quorum_numbers: quorums.to_vec(),
            payment_header_hash: todo!(),
        };
        let signature = self.signer.sign(blob_header)?;
        let disperse_request = DisperseBlobRequest{
            blob: data.to_vec(),
            blob_header: Some(BlobHeaderProto{
                version: blob_header.version as u32,
                commitment: Some(blob_commitment),
                quorum_numbers: quorums.to_vec().iter().map(|&x| x as u32).collect(),
                payment_header: Some(PaymentHeader{
                    account_id: payment.account_id.to_string(),
                    timestamp: payment.timestamp,
                    cumulative_payment: payment.cumulative_payment.to_signed_bytes_be(),
                }),
            }),
            signature
        };

        let reply = self.rpc_client.disperse_blob(disperse_request).await
        .map(|response| response.into_inner())
        .map_err(|status| format!("Failed RPC call: {}", status))?;

        

        if blob_header.blob_key().unwrap().to_bytes().to_vec() != reply.blob_key {
            return Err("blob key mismatch".to_string());
        }
        
        Ok((BlobStatus::try_from(reply.result).unwrap(), blob_header.blob_key().unwrap()))
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
