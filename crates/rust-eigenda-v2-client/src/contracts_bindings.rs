alloy::sol! {
    #[sol(rpc)]
    IEigenDACertVerifier, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IEigenDACertVerifier.json"),
}

alloy::sol! {
    #[sol(rpc)]
    IRelayRegistry, concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/abi/IRelayRegistry.json"),
}
