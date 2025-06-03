use crate::validator_types::{BlobVersionParameters, OperatorState};

/// Calculates chunk assignments for the validators in a set of quorums based on their stake.
/// The quorums passed should be the full set of quorums contained in the blob header.
/// Moreover, the OperatorState must include the operator state maps for each of the quorums specified.
/// This function will attempt to construct maximally overlapping assignments for each quorum, and then merge them together.
/// The number of chunks assigned to each operator is capped at the maximum number of chunks needed to construct a blob.
pub(crate) fn get_assigment_for_blob(
    operator_state: OperatorState,
    blob_params: &BlobVersionParameters,
    quorum_numbers: Vec<u8>,
) -> Vec<Vec<u8>> {
    unimplemented!()
}
