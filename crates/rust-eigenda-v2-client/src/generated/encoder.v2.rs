// This file is @generated by prost-build.
/// EncodeBlobRequest contains the reference to the blob to be encoded and the encoding parameters
/// determined by the control plane.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncodeBlobRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub blob_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub encoding_params: ::core::option::Option<EncodingParams>,
    #[prost(uint64, tag = "3")]
    pub blob_size: u64,
}
/// EncodingParams specifies how the blob should be encoded into chunks
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct EncodingParams {
    #[prost(uint64, tag = "1")]
    pub chunk_length: u64,
    #[prost(uint64, tag = "2")]
    pub num_chunks: u64,
}
/// FragmentInfo contains metadata about the encoded fragments
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct FragmentInfo {
    #[prost(uint32, tag = "1")]
    pub total_chunk_size_bytes: u32,
    #[prost(uint32, tag = "2")]
    pub fragment_size_bytes: u32,
}
/// EncodeBlobReply contains metadata about the encoded chunks
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct EncodeBlobReply {
    #[prost(message, optional, tag = "1")]
    pub fragment_info: ::core::option::Option<FragmentInfo>,
}
