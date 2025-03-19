use std::{str::FromStr, sync::Arc};

use super::{
    blob_info::BlobInfo, config::EigenConfig, eth_client,
    generated::disperser::BlobInfo as DisperserBlobInfo, verifier::Verifier,
};
use crate::{
    blob_info,
    client::BlobProvider,
    errors::{
        BlobStatusError, CommunicationError, ConfigError, EigenClientError, VerificationError,
    },
    generated::disperser::{
        self,
        authenticated_request::Payload::{AuthenticationData, DisperseRequest},
        disperser_client::DisperserClient,
        AuthenticatedReply, BlobAuthHeader,
    },
};
use byteorder::{BigEndian, ByteOrder};
use secp256k1::{ecdsa::RecoverableSignature, SecretKey};
use tiny_keccak::{Hasher, Keccak};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};
use tonic::{
    transport::{Channel, ClientTlsConfig, Endpoint},
    Streaming,
};

/// Raw Client that comunicates with the disperser
#[derive(Debug)]
pub(crate) struct RawEigenClient {
    client: Arc<Mutex<DisperserClient<Channel>>>,
    private_key: SecretKey,
    pub config: EigenConfig,
    verifier: Verifier<eth_client::EthClient>,
    blob_provider: Arc<dyn BlobProvider>,
}

pub(crate) const FIELD_ELEMENT_SIZE_BYTES: usize = 32;

impl RawEigenClient {
    const BLOB_SIZE_LIMIT: usize = 1024 * 1024 * 2; // 2 MB
    /// Creates a new RawEigenClient
    pub(crate) async fn new(
        private_key: SecretKey,
        config: EigenConfig,
        blob_provider: Arc<dyn BlobProvider>,
    ) -> Result<Self, EigenClientError> {
        let endpoint = Endpoint::from_str(config.disperser_rpc.as_str())
            .map_err(ConfigError::Tonic)?
            .tls_config(ClientTlsConfig::new())
            .map_err(ConfigError::Tonic)?;
        let client = Arc::new(Mutex::new(
            DisperserClient::connect(endpoint)
                .await
                .map_err(ConfigError::Tonic)?,
        ));

        let url = config.eth_rpc_url.clone();
        let eth_client = eth_client::EthClient::new(url, config.eigenda_svc_manager_address);

        let verifier = Verifier::new(config.clone(), eth_client).await?;
        Ok(RawEigenClient {
            client,
            private_key,
            config,
            verifier,
            blob_provider,
        })
    }

    /// Returns the blob size limit
    pub(crate) fn blob_size_limit() -> usize {
        Self::BLOB_SIZE_LIMIT
    }

    /// Dispatches a blob to the disperser without authentication
    async fn dispatch_blob_non_authenticated(
        &self,
        data: Vec<u8>,
    ) -> Result<String, EigenClientError> {
        let padded_data = convert_by_padding_empty_byte(&data);

        let custom_quorum_numbers: Vec<u32> = self
            .config
            .custom_quorum_numbers
            .iter()
            .map(|&x| x as u32)
            .collect();
        let request = disperser::DisperseBlobRequest {
            data: padded_data,
            custom_quorum_numbers,
            account_id: String::default(), // Account Id is not used in non-authenticated mode
        };

        let disperse_reply = self
            .client
            .lock()
            .await
            .disperse_blob(request)
            .await
            .map_err(BlobStatusError::Status)?
            .into_inner();

        match disperser::BlobStatus::try_from(disperse_reply.result)
            .map_err(BlobStatusError::Prost)?
        {
            disperser::BlobStatus::Failed
            | disperser::BlobStatus::InsufficientSignatures
            | disperser::BlobStatus::Unknown => Err(BlobStatusError::BlobDispatchedFailed)?,

            disperser::BlobStatus::Dispersing
            | disperser::BlobStatus::Processing
            | disperser::BlobStatus::Finalized
            | disperser::BlobStatus::Confirmed => Ok(hex::encode(disperse_reply.request_id)),
        }
    }

    /// Dispatches a blob to the disperser with authentication
    async fn dispatch_blob_authenticated(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        let (tx, rx) = mpsc::unbounded_channel();

        // 1. send DisperseBlobRequest
        let padded_data = convert_by_padding_empty_byte(&data);
        self.disperse_data(padded_data, &tx)?;

        // this await is blocked until the first response on the stream, so we only await after sending the `DisperseBlobRequest`
        let mut response_stream = self
            .client
            .clone()
            .lock()
            .await
            .disperse_blob_authenticated(UnboundedReceiverStream::new(rx))
            .await
            .map_err(BlobStatusError::Status)?;
        let response_stream = response_stream.get_mut();

        // 2. receive BlobAuthHeader
        let blob_auth_header = self.receive_blob_auth_header(response_stream).await?;

        // 3. sign and send BlobAuthHeader
        self.submit_authentication_data(blob_auth_header.clone(), &tx)?;

        // 4. receive DisperseBlobReply
        let reply = response_stream
            .next()
            .await
            .ok_or(CommunicationError::NoResponseFromServer)?
            .map_err(BlobStatusError::Status)?
            .payload
            .ok_or(CommunicationError::NoPayloadInResponse)?;

        let disperser::authenticated_reply::Payload::DisperseReply(disperse_reply) = reply else {
            return Err(CommunicationError::ErrorFromServer(
                "Unexpected response".to_string(),
            ))?;
        };

        match disperser::BlobStatus::try_from(disperse_reply.result)
            .map_err(BlobStatusError::Prost)?
        {
            disperser::BlobStatus::Failed
            | disperser::BlobStatus::InsufficientSignatures
            | disperser::BlobStatus::Unknown => Err(BlobStatusError::BlobDispatchedFailed)?,

            disperser::BlobStatus::Dispersing
            | disperser::BlobStatus::Processing
            | disperser::BlobStatus::Finalized
            | disperser::BlobStatus::Confirmed => Ok(hex::encode(disperse_reply.request_id)),
        }
    }

    /// Gets the blob info for a given request id
    pub(crate) async fn get_commitment(
        &self,
        request_id: &str,
    ) -> Result<Option<BlobInfo>, EigenClientError> {
        let blob_info = self.try_get_inclusion_data(request_id.to_string()).await?;

        let Some(blob_info) = blob_info else {
            return Ok(None);
        };
        let blob_info = blob_info::BlobInfo::try_from(blob_info)?;
        let Some(data) = self.get_blob(blob_info.clone()).await? else {
            return Err(CommunicationError::FailedToGetBlob)?;
        };

        let data_db = self
            .blob_provider
            .get_blob(request_id)
            .await
            .map_err(CommunicationError::BlobProvider)?;
        if let Some(data_db) = data_db {
            if data_db != data {
                return Err(VerificationError::DataMismatch)?;
            }
        }
        self.verifier
            .verify_commitment(blob_info.blob_header.commitment.clone(), data)?;

        let result = self
            .verifier
            .verify_inclusion_data_against_settlement_layer(blob_info.clone())
            .await;
        if let Err(e) = result {
            match e {
                // in case of an error, the dispatcher will retry, so the need to return None
                VerificationError::EmptyHash => return Ok(None),
                _ => Err(EigenClientError::Verification(e))?,
            }
        }
        Ok(Some(blob_info))
    }

    /// Returns the inclusion data for a given request id
    pub(crate) async fn get_inclusion_data(
        &self,
        request_id: &str,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        let blob_info = self.get_commitment(request_id).await?;
        if let Some(blob_info) = blob_info {
            Ok(Some(ethabi::encode(&blob_info.to_tokens())))
        } else {
            Ok(None)
        }
    }

    /// Dispatches a blob to the disperser
    pub(crate) async fn dispatch_blob(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        if self.config.authenticated {
            self.dispatch_blob_authenticated(data).await
        } else {
            self.dispatch_blob_non_authenticated(data).await
        }
    }

    fn disperse_data(
        &self,
        data: Vec<u8>,
        tx: &mpsc::UnboundedSender<disperser::AuthenticatedRequest>,
    ) -> Result<(), EigenClientError> {
        let custom_quorum_numbers: Vec<u32> = self
            .config
            .custom_quorum_numbers
            .iter()
            .map(|&x| x as u32)
            .collect();
        let req = disperser::AuthenticatedRequest {
            payload: Some(DisperseRequest(disperser::DisperseBlobRequest {
                data,
                custom_quorum_numbers,
                account_id: get_account_id(&self.private_key),
            })),
        };

        tx.send(req).map_err(CommunicationError::DisperseBlob)?;
        Ok(())
    }

    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }

    fn submit_authentication_data(
        &self,
        blob_auth_header: BlobAuthHeader,
        tx: &mpsc::UnboundedSender<disperser::AuthenticatedRequest>,
    ) -> Result<(), EigenClientError> {
        // TODO: replace challenge_parameter with actual auth header when it is available
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, blob_auth_header.challenge_parameter);
        let digest = self.keccak256(&buf);
        let signature: RecoverableSignature = secp256k1::Secp256k1::signing_only()
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(&digest[..]).map_err(CommunicationError::Secp)?,
                &self.private_key,
            );
        let (recovery_id, sig) = signature.serialize_compact();

        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&sig);
        signature.push(recovery_id.to_i32() as u8);

        let req = disperser::AuthenticatedRequest {
            payload: Some(AuthenticationData(disperser::AuthenticationData {
                authentication_data: signature,
            })),
        };

        tx.send(req)
            .map_err(CommunicationError::AuthenticationData)?;
        Ok(())
    }

    async fn receive_blob_auth_header(
        &self,
        response_stream: &mut Streaming<AuthenticatedReply>,
    ) -> Result<disperser::BlobAuthHeader, EigenClientError> {
        let reply = response_stream
            .next()
            .await
            .ok_or(CommunicationError::NoResponseFromServer)?;

        let Ok(reply) = reply else {
            return Err(CommunicationError::ErrorFromServer(format!("{:?}", reply)))?;
        };

        let reply = reply
            .payload
            .ok_or(CommunicationError::NoPayloadInResponse)?;

        if let disperser::authenticated_reply::Payload::BlobAuthHeader(blob_auth_header) = reply {
            Ok(blob_auth_header)
        } else {
            Err(CommunicationError::ErrorFromServer(
                "Unexpected Response".to_string(),
            ))?
        }
    }

    async fn try_get_inclusion_data(
        &self,
        request_id: String,
    ) -> Result<Option<DisperserBlobInfo>, EigenClientError> {
        let polling_request = disperser::BlobStatusRequest {
            request_id: hex::decode(request_id).map_err(CommunicationError::Hex)?,
        };

        let resp = self
            .client
            .lock()
            .await
            .get_blob_status(polling_request.clone())
            .await
            .map_err(BlobStatusError::Status)?
            .into_inner();

        match disperser::BlobStatus::try_from(resp.status).map_err(BlobStatusError::Prost)? {
            disperser::BlobStatus::Processing | disperser::BlobStatus::Dispersing => Ok(None),
            disperser::BlobStatus::Failed => Err(BlobStatusError::BlobDispatchedFailed)?,
            disperser::BlobStatus::InsufficientSignatures => {
                Err(BlobStatusError::InsufficientSignatures)?
            }
            disperser::BlobStatus::Confirmed => {
                if !self.config.wait_for_finalization {
                    let blob_info = resp
                        .info
                        .ok_or_else(|| BlobStatusError::NoBlobHeaderInResponse)?;
                    return Ok(Some(blob_info));
                }
                Ok(None)
            }
            disperser::BlobStatus::Finalized => {
                let blob_info = resp
                    .info
                    .ok_or_else(|| BlobStatusError::NoBlobHeaderInResponse)?;
                Ok(Some(blob_info))
            }

            _ => Err(BlobStatusError::ReceivedUnknownBlobStatus)?,
        }
    }

    /// Returns the blob data
    pub(crate) async fn get_blob(
        &self,
        blob_info: BlobInfo,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        let blob_index = blob_info.blob_verification_proof.blob_index;
        let batch_header_hash = blob_info
            .blob_verification_proof
            .batch_medatada
            .batch_header_hash;
        let get_response = self
            .client
            .lock()
            .await
            .retrieve_blob(disperser::RetrieveBlobRequest {
                batch_header_hash,
                blob_index,
            })
            .await
            .map_err(BlobStatusError::Status)?
            .into_inner();

        if get_response.data.is_empty() {
            return Err(CommunicationError::FailedToGetBlob)?;
        }

        let data = remove_empty_byte_from_padded_bytes(&get_response.data);
        Ok(Some(data))
    }
}

fn get_account_id(secret_key: &SecretKey) -> String {
    let public_key =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), secret_key);
    let hex = hex::encode(public_key.serialize_uncompressed());

    format!("0x{}", hex)
}

fn convert_by_padding_empty_byte(data: &[u8]) -> Vec<u8> {
    let parse_size = FIELD_ELEMENT_SIZE_BYTES - 1;

    let chunk_count = data.len().div_ceil(parse_size);
    let mut valid_data = Vec::with_capacity(data.len() + chunk_count);

    for chunk in data.chunks(parse_size) {
        valid_data.push(0x00); // Add the padding byte (0x00)
        valid_data.extend_from_slice(chunk);
    }
    valid_data
}

fn remove_empty_byte_from_padded_bytes(data: &[u8]) -> Vec<u8> {
    let parse_size = FIELD_ELEMENT_SIZE_BYTES;

    let chunk_count = data.len().div_ceil(parse_size);
    // Safe subtraction, as we know chunk_count is always less than the length of the data
    let mut valid_data = Vec::with_capacity(data.len() - chunk_count);

    for chunk in data.chunks(parse_size) {
        valid_data.extend_from_slice(&chunk[1..]);
    }
    valid_data
}

#[cfg(test)]
mod test {
    #[test]
    fn test_pad_and_unpad() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }

    #[test]
    fn test_pad_and_unpad_large() {
        let data = vec![1; 1000];
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }

    #[test]
    fn test_pad_and_unpad_empty() {
        let data = Vec::new();
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }
}
