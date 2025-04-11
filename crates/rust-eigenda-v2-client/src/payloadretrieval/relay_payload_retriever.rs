// RelayPayloadRetriever provides the ability to get payloads from the relay subsystem.
pub(crate) struct RelayPayloadRetriever {

}

impl RelayPayloadRetriever {
    pub fn new() -> Self {
        RelayPayloadRetriever {}
    }

    // get_payload iteratively attempts to fetch a given blob with key blobKey from relays that have it, as claimed by the
    // blob certificate. The relays are attempted in random order.
    //
    // If the blob is successfully retrieved, then the blob is verified against the certificate. If the verification
    // succeeds, the blob is decoded to yield the payload (the original user data, with no padding or any modification),
    // and the payload is returned.
    //
    // This method does NOT verify the eigenDACert on chain: it is assumed that the input eigenDACert has already been
    // verified prior to calling this method.
    pub fn get_payload(&self) -> () {

    }
}
