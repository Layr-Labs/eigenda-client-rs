use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hex::ToHex;
use rust_eigenda_signers::secp256k1::Message;
use rust_eigenda_signers::Sign;
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::accountant::Accountant;
use crate::core::eigenda_cert::{BlobCommitments, BlobHeader, PaymentHeader};
use crate::core::{
    BlobKey, OnDemandPayment, PaymentStateRequest, PrivateKeySigner, ReservedPayment,
};
use crate::errors::DisperseError;
use crate::generated::common::v2::{
    BlobHeader as BlobHeaderProto, PaymentHeader as PaymentHeaderProto,
};
use crate::generated::disperser::v2::{
    disperser_client, BlobCommitmentReply, BlobCommitmentRequest, BlobStatus, BlobStatusReply,
    BlobStatusRequest, DisperseBlobRequest, GetPaymentStateReply, GetPaymentStateRequest,
};

const BYTES_PER_SYMBOL: usize = 32;

#[derive(Debug)]
pub struct DisperserClientConfig<S = PrivateKeySigner> {
    pub disperser_rpc: String,
    pub signer: S,
    pub use_secure_grpc_flag: bool,
}

impl<S> DisperserClientConfig<S> {
    pub fn new(
        disperser_rpc: String,
        signer: S,
        use_secure_grpc_flag: bool,
    ) -> Result<Self, DisperseError> {
        if disperser_rpc.is_empty() {
            return Err(DisperseError::ConfigInitialization(
                "disperser_rpc cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            disperser_rpc,
            signer,
            use_secure_grpc_flag,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DisperserClient<S = PrivateKeySigner> {
    signer: S,
    rpc_client: Arc<Mutex<disperser_client::DisperserClient<tonic::transport::Channel>>>,
    accountant: Arc<Mutex<Accountant>>,
}

// todo: add locks
impl<S> DisperserClient<S> {
    pub async fn new(config: DisperserClientConfig<S>) -> Result<Self, DisperseError>
    where
        S: Sign,
    {
        let mut endpoint = Channel::from_shared(config.disperser_rpc.clone())
            .map_err(|_| DisperseError::InvalidURI(config.disperser_rpc.clone()))?;
        if config.use_secure_grpc_flag {
            let tls: ClientTlsConfig = ClientTlsConfig::new();
            endpoint = endpoint.tls_config(tls)?;
        }
        let channel = endpoint.connect().await?;
        let rpc_client = disperser_client::DisperserClient::new(channel);
        let signer = config.signer;
        let accountant = Accountant::new(
            signer.public_key().address(),
            ReservedPayment::default(),
            OnDemandPayment::default(),
            0,
            0,
            0,
            0,
        );
        let mut disperser = Self {
            signer,
            rpc_client: Arc::new(Mutex::new(rpc_client)),
            accountant: Arc::new(Mutex::new(accountant)),
        };
        disperser.populate_accountant().await?;
        Ok(disperser)
    }

    pub(crate) async fn disperse_blob(
        &self,
        data: &[u8],
        blob_version: u16,
        quorums: &[u8],
    ) -> Result<(BlobStatus, BlobKey), DisperseError>
    where
        S: Sign,
    {
        if quorums.is_empty() {
            return Err(DisperseError::EmptyQuorums);
        }

        let symbol_length = data.len().div_ceil(BYTES_PER_SYMBOL).next_power_of_two();
        let payment = self
            .accountant
            .lock()
            .await
            .account_blob(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as i64,
                symbol_length as u64,
                quorums,
            )
            .map_err(DisperseError::Accountant)?;

        let blob_commitment_reply = self.blob_commitment(data).await?;
        let Some(blob_commitments) = blob_commitment_reply.blob_commitment else {
            return Err(DisperseError::EmptyBlobCommitment);
        };
        let core_blob_commitments: BlobCommitments = blob_commitments.clone().try_into()?;
        if core_blob_commitments.length != symbol_length as u32 {
            return Err(DisperseError::CommitmentLengthMismatch(
                core_blob_commitments.length,
                symbol_length,
            ));
        }
        let account_id: String = payment.account_id.encode_hex();

        let account_id: String = alloy_primitives::Address::from_str(&account_id)
            .map_err(|_| DisperseError::AccountID)?
            .to_checksum(None);

        let blob_header = BlobHeader {
            version: blob_version,
            commitment: core_blob_commitments.clone(),
            quorum_numbers: quorums.to_vec(),
            payment_header_hash: PaymentHeader {
                account_id: account_id.clone(),
                timestamp: payment.timestamp,
                cumulative_payment: payment.cumulative_payment.to_signed_bytes_be(),
            }
            .hash()?,
        };

        let digest = Message::from_slice(&blob_header.blob_key()?.to_bytes())
            .map_err(|e| DisperseError::Signer(Box::new(e)))?;
        let signature = self
            .signer
            .sign_digest(&digest)
            .await
            .map_err(|e| DisperseError::Signer(Box::new(e)))?
            .encode_as_rsv();

        let disperse_request = DisperseBlobRequest {
            blob: data.to_vec(),
            blob_header: Some(BlobHeaderProto {
                version: blob_header.version as u32,
                commitment: Some(blob_commitments),
                quorum_numbers: quorums.to_vec().iter().map(|&x| x as u32).collect(),
                payment_header: Some(PaymentHeaderProto {
                    account_id,
                    timestamp: payment.timestamp,
                    cumulative_payment: payment.cumulative_payment.to_signed_bytes_be(),
                }),
            }),
            signature,
        };

        let reply = self
            .rpc_client
            .lock()
            .await
            .disperse_blob(disperse_request)
            .await
            .map(|response| response.into_inner())
            .map_err(DisperseError::FailedRPC)?;

        if blob_header.blob_key()?.to_bytes().to_vec() != reply.blob_key {
            return Err(DisperseError::BlobKeyMismatch);
        }

        Ok((BlobStatus::try_from(reply.result)?, blob_header.blob_key()?))
    }

    /// Populates the accountant with the payment state from the disperser.
    async fn populate_accountant(&mut self) -> Result<(), DisperseError>
    where
        S: Sign,
    {
        let payment_state = self.payment_state().await?;
        self.accountant
            .lock()
            .await
            .set_payment_state(&payment_state)
            .map_err(DisperseError::Accountant)?;
        Ok(())
    }

    /// Returns the status of a blob with the given blob key.
    pub(crate) async fn blob_status(
        &self,
        blob_key: &BlobKey,
    ) -> Result<BlobStatusReply, DisperseError> {
        let request = BlobStatusRequest {
            blob_key: blob_key.to_bytes().to_vec(),
        };

        self.rpc_client
            .lock()
            .await
            .get_blob_status(request)
            .await
            .map(|response| response.into_inner())
            .map_err(DisperseError::FailedRPC)
    }

    /// Returns the payment state of the disperser client
    pub(crate) async fn payment_state(&mut self) -> Result<GetPaymentStateReply, DisperseError>
    where
        S: Sign,
    {
        let account_id = self.signer.public_key().address().encode_hex();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let digest = PaymentStateRequest::new(timestamp as u64)
            .prepare_for_signing_by(&self.signer.public_key().address())
            .map_err(|e| DisperseError::Signer(Box::new(e)))?;

        let signature = self
            .signer
            .sign_digest(&digest)
            .await
            .map_err(|e| DisperseError::Signer(Box::new(e)))?
            .encode_as_rsv();
        let request = GetPaymentStateRequest {
            account_id,
            signature,
            timestamp: timestamp as u64,
        };

        self.rpc_client
            .lock()
            .await
            .get_payment_state(request)
            .await
            .map(|response: tonic::Response<GetPaymentStateReply>| response.into_inner())
            .map_err(DisperseError::FailedRPC)
    }

    pub(crate) async fn blob_commitment(
        &self,
        data: &[u8],
    ) -> Result<BlobCommitmentReply, DisperseError> {
        let request = BlobCommitmentRequest {
            blob: data.to_vec(),
        };

        self.rpc_client
            .lock()
            .await
            .get_blob_commitment(request)
            .await
            .map(|response| response.into_inner())
            .map_err(DisperseError::FailedRPC)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        disperser_client::DisperserClient,
        tests::{get_test_private_key_signer, HOLESKY_DISPERSER_RPC_URL},
    };

    use super::DisperserClientConfig;

    use serial_test::serial;

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_disperse_non_secure() {
        let config = DisperserClientConfig {
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            signer: get_test_private_key_signer(),
            use_secure_grpc_flag: false,
        };
        let client = DisperserClient::new(config).await.unwrap();
        let data = vec![1, 2, 3, 4, 5];
        let blob_version = 0;
        let quorums = vec![0, 1];

        let result = client.disperse_blob(&data, blob_version, &quorums).await;
        assert!(result.is_ok());
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_disperse_secure() {
        let config = DisperserClientConfig {
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            signer: get_test_private_key_signer(),
            use_secure_grpc_flag: true,
        };
        let client = DisperserClient::new(config).await.unwrap();
        let data = vec![1, 2, 3, 4, 5];
        let blob_version = 0;
        let quorums = vec![0, 1];
        let result = client.disperse_blob(&data, blob_version, &quorums).await;
        assert!(result.is_ok());
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_double_disperse_secure() {
        let config = DisperserClientConfig {
            disperser_rpc: HOLESKY_DISPERSER_RPC_URL.to_string(),
            signer: get_test_private_key_signer(),
            use_secure_grpc_flag: true,
        };
        let client = DisperserClient::new(config).await.unwrap();
        let data = vec![1, 2, 3, 4, 5];
        let blob_version = 0;
        let quorums = vec![0, 1];

        let result = client.disperse_blob(&data, blob_version, &quorums).await;
        assert!(result.is_ok());
        let result = client.disperse_blob(&data, blob_version, &quorums).await;
        assert!(result.is_ok());
    }
}
