// This file is @generated by prost-build.
/// A request to disperse a blob.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DisperseBlobRequest {
    /// The blob to be dispersed.
    ///
    /// The size of this byte array may be any size as long as it does not exceed the maximum length of 16MiB.
    /// While the data being dispersed is only required to be greater than 0 bytes, the blob size charged against the
    /// payment method will be rounded up to the nearest multiple of `minNumSymbols` defined by the payment vault contract
    /// (<https://github.com/Layr-Labs/eigenda/blob/1430d56258b4e814b388e497320fd76354bfb478/contracts/src/payments/PaymentVaultStorage.sol#L9>).
    ///
    /// Every 32 bytes of data is interpreted as an integer in big endian format where the lower address has more
    /// significant bits. The integer must stay in the valid range to be interpreted as a field element on the bn254 curve.
    /// The valid range is 0 <= x < 21888242871839275222246405745257275088548364400416034343698204186575808495617.
    /// If any one of the 32 bytes elements is outside the range, the whole request is deemed as invalid, and rejected.
    #[prost(bytes = "vec", tag = "1")]
    pub blob: ::prost::alloc::vec::Vec<u8>,
    /// The header contains metadata about the blob.
    ///
    /// This header can be thought of as an "eigenDA tx", in that it plays a purpose similar to an eth_tx to disperse a
    /// 4844 blob. Note that a call to DisperseBlob requires the blob and the blobHeader, which is similar to how
    /// dispersing a blob to ethereum requires sending a tx whose data contains the hash of the kzg commit of the blob,
    /// which is dispersed separately.
    #[prost(message, optional, tag = "2")]
    pub blob_header: ::core::option::Option<super::super::common::v2::BlobHeader>,
    /// signature over keccak hash of the blob_header that can be verified by blob_header.payment_header.account_id
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
/// A reply to a DisperseBlob request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DisperseBlobReply {
    /// The status of the blob associated with the blob key.
    #[prost(enumeration = "BlobStatus", tag = "1")]
    pub result: i32,
    /// The unique 32 byte identifier for the blob.
    ///
    /// The blob_key is the keccak hash of the rlp serialization of the BlobHeader, as computed here:
    /// <https://github.com/Layr-Labs/eigenda/blob/0f14d1c90b86d29c30ff7e92cbadf2762c47f402/core/v2/serialization.go#L30>
    /// The blob_key must thus be unique for every request, even if the same blob is being dispersed.
    /// Meaning the blob_header must be different for each request.
    ///
    /// Note that attempting to disperse a blob with the same blob key as a previously dispersed blob may cause
    /// the disperser to reject the blob (DisperseBlob() RPC will return an error).
    #[prost(bytes = "vec", tag = "2")]
    pub blob_key: ::prost::alloc::vec::Vec<u8>,
}
/// BlobStatusRequest is used to query the status of a blob.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobStatusRequest {
    /// The unique identifier for the blob.
    #[prost(bytes = "vec", tag = "1")]
    pub blob_key: ::prost::alloc::vec::Vec<u8>,
}
/// BlobStatusReply is the reply to a BlobStatusRequest.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobStatusReply {
    /// The status of the blob.
    #[prost(enumeration = "BlobStatus", tag = "1")]
    pub status: i32,
    /// The signed batch. Only set if the blob status is GATHERING_SIGNATURES or COMPLETE.
    /// signed_batch and blob_inclusion_info are only set if the blob status is GATHERING_SIGNATURES or COMPLETE.
    /// When blob is in GATHERING_SIGNATURES status, the attestation object in signed_batch contains attestation information
    /// at the point in time. As it gathers more signatures, attestation object will be updated according to the latest attestation status.
    /// The client can use this intermediate attestation to verify a blob if it has gathered enough signatures.
    /// Otherwise, it should should poll the GetBlobStatus API until the desired level of attestation has been gathered or status is COMPLETE.
    /// When blob is in COMPLETE status, the attestation object in signed_batch contains the final attestation information.
    /// If the final attestation does not meet the client's requirement, the client should try a new dispersal.
    #[prost(message, optional, tag = "2")]
    pub signed_batch: ::core::option::Option<SignedBatch>,
    /// BlobInclusionInfo is the information needed to verify the inclusion of a blob in a batch.
    /// Only set if the blob status is GATHERING_SIGNATURES or COMPLETE.
    #[prost(message, optional, tag = "3")]
    pub blob_inclusion_info: ::core::option::Option<BlobInclusionInfo>,
}
/// The input for a BlobCommitmentRequest().
/// This can be used to construct a BlobHeader.commitment.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobCommitmentRequest {
    /// The blob data to compute the commitment for.
    #[prost(bytes = "vec", tag = "1")]
    pub blob: ::prost::alloc::vec::Vec<u8>,
}
/// The result of a BlobCommitmentRequest().
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobCommitmentReply {
    /// The commitment of the blob.
    #[prost(message, optional, tag = "1")]
    pub blob_commitment: ::core::option::Option<super::super::common::BlobCommitment>,
}
/// GetPaymentStateRequest contains parameters to query the payment state of an account.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPaymentStateRequest {
    /// The ID of the account being queried. This account ID is an eth wallet address of the user.
    #[prost(string, tag = "1")]
    pub account_id: ::prost::alloc::string::String,
    /// Signature over the account ID
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
/// GetPaymentStateReply contains the payment state of an account.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPaymentStateReply {
    /// global payment vault parameters
    #[prost(message, optional, tag = "1")]
    pub payment_global_params: ::core::option::Option<PaymentGlobalParams>,
    /// off-chain account reservation usage records
    #[prost(message, repeated, tag = "2")]
    pub period_records: ::prost::alloc::vec::Vec<PeriodRecord>,
    /// on-chain account reservation setting
    #[prost(message, optional, tag = "3")]
    pub reservation: ::core::option::Option<Reservation>,
    /// off-chain on-demand payment usage
    #[prost(bytes = "vec", tag = "4")]
    pub cumulative_payment: ::prost::alloc::vec::Vec<u8>,
    /// on-chain on-demand payment deposited
    #[prost(bytes = "vec", tag = "5")]
    pub onchain_cumulative_payment: ::prost::alloc::vec::Vec<u8>,
}
/// SignedBatch is a batch of blobs with a signature.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedBatch {
    /// header contains metadata about the batch
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::super::common::v2::BatchHeader>,
    /// attestation on the batch
    #[prost(message, optional, tag = "2")]
    pub attestation: ::core::option::Option<Attestation>,
}
/// BlobInclusionInfo is the information needed to verify the inclusion of a blob in a batch.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobInclusionInfo {
    #[prost(message, optional, tag = "1")]
    pub blob_certificate: ::core::option::Option<
        super::super::common::v2::BlobCertificate,
    >,
    /// blob_index is the index of the blob in the batch
    #[prost(uint32, tag = "2")]
    pub blob_index: u32,
    /// inclusion_proof is the inclusion proof of the blob in the batch
    #[prost(bytes = "vec", tag = "3")]
    pub inclusion_proof: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Attestation {
    /// Serialized bytes of non signer public keys (G1 points)
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub non_signer_pubkeys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Serialized bytes of G2 point that represents aggregate public key of all signers
    #[prost(bytes = "vec", tag = "2")]
    pub apk_g2: ::prost::alloc::vec::Vec<u8>,
    /// Serialized bytes of aggregate public keys (G1 points) from all nodes for each quorum
    /// The order of the quorum_apks should match the order of the quorum_numbers
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub quorum_apks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Serialized bytes of aggregate signature
    #[prost(bytes = "vec", tag = "4")]
    pub sigma: ::prost::alloc::vec::Vec<u8>,
    /// Relevant quorum numbers for the attestation
    #[prost(uint32, repeated, tag = "5")]
    pub quorum_numbers: ::prost::alloc::vec::Vec<u32>,
    /// The attestation rate for each quorum. Each quorum's signing percentage is represented by
    /// an 8 bit unsigned integer. The integer is the fraction of the quorum that has signed, with
    /// 100 representing 100% of the quorum signing, and 0 representing 0% of the quorum signing. The first
    /// byte in the byte array corresponds to the first quorum in the quorum_numbers array, the second byte
    /// corresponds to the second quorum, and so on.
    #[prost(bytes = "vec", tag = "6")]
    pub quorum_signed_percentages: ::prost::alloc::vec::Vec<u8>,
}
/// Global constant parameters defined by the payment vault.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PaymentGlobalParams {
    /// Global ratelimit for on-demand dispersals
    #[prost(uint64, tag = "1")]
    pub global_symbols_per_second: u64,
    /// Minimum number of symbols accounted for all dispersals
    #[prost(uint64, tag = "2")]
    pub min_num_symbols: u64,
    /// Price charged per symbol for on-demand dispersals
    #[prost(uint64, tag = "3")]
    pub price_per_symbol: u64,
    /// Reservation window for all reservations
    #[prost(uint64, tag = "4")]
    pub reservation_window: u64,
    /// quorums allowed to make on-demand dispersals
    #[prost(uint32, repeated, tag = "5")]
    pub on_demand_quorum_numbers: ::prost::alloc::vec::Vec<u32>,
}
/// Reservation parameters of an account, used to determine the rate limit for the account.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reservation {
    /// rate limit for the account
    #[prost(uint64, tag = "1")]
    pub symbols_per_second: u64,
    /// start timestamp of the reservation
    #[prost(uint32, tag = "2")]
    pub start_timestamp: u32,
    /// end timestamp of the reservation
    #[prost(uint32, tag = "3")]
    pub end_timestamp: u32,
    /// quorums allowed to make reserved dispersals
    #[prost(uint32, repeated, tag = "4")]
    pub quorum_numbers: ::prost::alloc::vec::Vec<u32>,
    /// quorum splits describes how the payment is split among the quorums
    #[prost(uint32, repeated, tag = "5")]
    pub quorum_splits: ::prost::alloc::vec::Vec<u32>,
}
/// PeriodRecord is the usage record of an account in a bin. The API should return the active bin
/// record and the subsequent two records that contains potential overflows.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct PeriodRecord {
    /// Period index of the reservation
    #[prost(uint32, tag = "1")]
    pub index: u32,
    /// symbol usage recorded
    #[prost(uint64, tag = "2")]
    pub usage: u64,
}
/// BlobStatus represents the status of a blob.
/// The status of a blob is updated as the blob is processed by the disperser.
/// The status of a blob can be queried by the client using the GetBlobStatus API.
/// Intermediate states are states that the blob can be in while being processed, and it can be updated to a different state:
/// - QUEUED
/// - ENCODED
/// - GATHERING_SIGNATURES
/// Terminal states are states that will not be updated to a different state:
/// - UNKNOWN
/// - COMPLETE
/// - FAILED
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BlobStatus {
    /// UNKNOWN means that the status of the blob is unknown.
    /// This is a catch all and should not be encountered absent a bug.
    ///
    /// This status is functionally equivalent to FAILED, but is used to indicate that the failure is due to an
    /// unanticipated bug.
    Unknown = 0,
    /// QUEUED means that the blob has been queued by the disperser for processing.
    /// The DisperseBlob API is asynchronous, meaning that after request validation, but before any processing,
    /// the blob is stored in a queue of some sort, and a response immediately returned to the client.
    Queued = 1,
    /// ENCODED means that the blob has been Reed-Solomon encoded into chunks and is ready to be dispersed to DA Nodes.
    Encoded = 2,
    /// GATHERING_SIGNATURES means that the blob chunks are currently actively being transmitted to validators,
    /// and in doing so requesting that the validators sign to acknowledge receipt of the blob.
    /// Requests that timeout or receive errors are resubmitted to DA nodes for some period of time set by the disperser,
    /// after which the BlobStatus becomes COMPLETE.
    GatheringSignatures = 3,
    /// COMPLETE means the blob has been dispersed to DA nodes, and the GATHERING_SIGNATURES period of time has completed.
    /// This status does not guarantee any signer percentage, so a client should check that the signature has met
    /// its required threshold, and resubmit a new blob dispersal request if not.
    Complete = 4,
    /// FAILED means that the blob has failed permanently. Note that this is a terminal state, and in order to
    /// retry the blob, the client must submit the blob again (blob key is required to be unique).
    Failed = 5,
}
impl BlobStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Queued => "QUEUED",
            Self::Encoded => "ENCODED",
            Self::GatheringSignatures => "GATHERING_SIGNATURES",
            Self::Complete => "COMPLETE",
            Self::Failed => "FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "QUEUED" => Some(Self::Queued),
            "ENCODED" => Some(Self::Encoded),
            "GATHERING_SIGNATURES" => Some(Self::GatheringSignatures),
            "COMPLETE" => Some(Self::Complete),
            "FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}
