mod commitment_utils;
pub mod core;
pub mod eigenda_cert;
pub mod errors;

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
}
