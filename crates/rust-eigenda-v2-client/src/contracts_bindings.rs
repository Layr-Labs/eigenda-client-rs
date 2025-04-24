use ethers::contract::abigen;

// todo: add eigenda-rs bindings

// Export the ABI for the IEigenDACertVerifier contract.
abigen!(
    IEigenDACertVerifier,
    "./crates/rust-eigenda-v2-client/src/generated/abi/IEigenDACertVerifier.json",
);

// Export the ABI for the IRelayRegistry contract.
abigen!(
    IRelayRegistry,
    "./crates/rust-eigenda-v2-client/src/generated/abi/IRelayRegistry.json",
);
