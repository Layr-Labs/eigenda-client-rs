use ethers::contract::abigen;

// todo: add eigenda-rs bindings

// Export the ABI for the IEigenDACertVerifier contract.
// We export from json abis (https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#json-abi)
// even though its not recommended because our contracts have external dependencies which
// the sol! macro doesn't support right now (it's not a full fledged solidity compiler so doesn't find dependencies).
// See https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity for more details.
abigen!(
    IEigenDACertVerifier,
    "crates/rust-eigenda-v2-client/src/generated/abi/IEigenDACertVerifier.json",
);

abigen!(
    IRelayRegistry,
    "crates/rust-eigenda-v2-client/src/generated/abi/IRelayRegistry.json",
);

// Export the ABI for the IRelayRegistry contract.
// We export from json abis (https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#json-abi)
// even though its not recommended because our contracts have external dependencies which
// the sol! macro doesn't support right now (it's not a full fledged solidity compiler so doesn't find dependencies).
// See https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity for more details.
