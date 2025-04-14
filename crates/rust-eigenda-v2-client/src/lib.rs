pub mod accountant;
pub mod core;
pub mod disperser_client;
pub mod errors;
pub mod eth_client;
pub mod relay_client;
pub mod prover;
pub mod retrieval_client;
pub mod utils;
pub mod verifier;

#[allow(clippy::all)]
pub(crate) mod generated {
    pub mod common {
        include!("generated/common.rs");

        pub mod v2 {
            include!("generated/common.v2.rs");
        }
    }

    pub mod disperser {
        pub mod v2 {
            include!("generated/disperser.v2.rs");
        }
    }

    pub mod encoder {
        pub mod v2 {
            include!("generated/encoder.v2.rs");
        }
    }

    pub mod retriever {
        pub mod v2 {
            include!("generated/retriever.v2.rs");
        }
    }

    pub mod validator {
        include!("generated/validator.rs");
    }

    pub mod relay {
        include!("generated/relay.rs");
    }
}
