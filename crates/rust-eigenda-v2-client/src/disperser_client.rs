use std::time::Duration;

use ark_ff::Zero;

use crate::accountant::Accountant;
use crate::core::{BlobKey, LocalBlobRequestSigner};
use crate::generated::disperser::v2::{disperser_client, BlobCommitmentReply, BlobStatusReply, GetPaymentStateReply};
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
        accountant: Accountant
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

    pub fn blob_status(&self, blob_key: BlobKey) -> Result<BlobStatusReply, String> {
        todo!()
    }

    pub fn payment_state(&self) -> Result<GetPaymentStateReply, String> {
        todo!()
    }

    pub fn blob_commitment(&self, data: &[u8]) -> Result<BlobCommitmentReply, String> {
        todo!()
    }

    
}
