use alloy_sol_types::sol;

// todo: add eigenda-rs bindings

// Export the ABI for the IEigenDACertVerifier contract.
// We export from json abis (https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#json-abi)
// even though its not recommended because our contracts have external dependencies which
// the sol! macro doesn't support right now (it's not a full fledged solidity compiler so doesn't find dependencies).
// See https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity for more details.
sol! {
    #[sol(rpc)]
    IEigenDACertVerifier, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDACertVerifier.json"),
}
