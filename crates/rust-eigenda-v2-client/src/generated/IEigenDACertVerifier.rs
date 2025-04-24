pub use i_eigen_da_cert_verifier::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    dead_code,
    non_camel_case_types,
)]
pub mod i_eigen_da_cert_verifier {
    const _: () = {
        ::core::include_bytes!(
            "/Users/gianlucabelinche/Desktop/verifier_test/IEigenDACertVerifier.json",
        );
    };
    #[allow(deprecated)]
    fn __abi() -> ::ethers::core::abi::Abi {
        ::ethers::core::abi::ethabi::Contract {
            constructor: ::core::option::Option::None,
            functions: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("getBlobParams"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("getBlobParams"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("version"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint16"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct VersionedBlobParams",
                                        ),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("getIsQuorumRequired"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "getIsQuorumRequired",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("quorumNumber"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bool,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bool"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("getNonSignerStakesAndSignature"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "getNonSignerStakesAndSignature",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("signedBatch"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ],
                                                            ),
                                                        ),
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ],
                                                            ),
                                                        ),
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                ::std::boxed::Box::new(
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ),
                                                                2usize,
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                ::std::boxed::Box::new(
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ),
                                                                2usize,
                                                            ),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct SignedBatch"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct NonSignerStakesAndSignature",
                                        ),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "getQuorumAdversaryThresholdPercentage",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "getQuorumAdversaryThresholdPercentage",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("quorumNumber"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "getQuorumConfirmationThresholdPercentage",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "getQuorumConfirmationThresholdPercentage",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("quorumNumber"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint8"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "quorumAdversaryThresholdPercentages",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "quorumAdversaryThresholdPercentages",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "quorumConfirmationThresholdPercentages",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "quorumConfirmationThresholdPercentages",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("quorumNumbersRequired"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "quorumNumbersRequired",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertSecurityParams"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "verifyDACertSecurityParams",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobParams"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct VersionedBlobParams",
                                        ),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "securityThresholds",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct SecurityThresholds",
                                        ),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "verifyDACertSecurityParams",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("version"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint16"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "securityThresholds",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct SecurityThresholds",
                                        ),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertV1"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("verifyDACertV1"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobHeader"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BlobHeader"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "blobVerificationProof",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct BlobVerificationProof",
                                        ),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertV2"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("verifyDACertV2"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("batchHeader"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BatchHeaderV2"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobInclusionInfo"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                                ],
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BlobInclusionInfo"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "nonSignerStakesAndSignature",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct NonSignerStakesAndSignature",
                                        ),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "signedQuorumNumbers",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertV2ForZKProof"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "verifyDACertV2ForZKProof",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("batchHeader"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BatchHeaderV2"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobInclusionInfo"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                                ],
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BlobInclusionInfo"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "nonSignerStakesAndSignature",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ),
                                                        2usize,
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct NonSignerStakesAndSignature",
                                        ),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "signedQuorumNumbers",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bool,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bool"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertV2FromSignedBatch"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "verifyDACertV2FromSignedBatch",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("signedBatch"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ],
                                                            ),
                                                        ),
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ],
                                                            ),
                                                        ),
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                ::std::boxed::Box::new(
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ),
                                                                2usize,
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                ::std::boxed::Box::new(
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                ),
                                                                2usize,
                                                            ),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct SignedBatch"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobInclusionInfo"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                        ::std::vec![
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                            ::ethers::core::abi::ethabi::ParamType::FixedArray(
                                                                                ::std::boxed::Box::new(
                                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                                                ),
                                                                                2usize,
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                                ],
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Bytes,
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BlobInclusionInfo"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyDACertsV1"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("verifyDACertsV1"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("blobHeaders"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Array(
                                        ::std::boxed::Box::new(
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Array(
                                                        ::std::boxed::Box::new(
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                                ],
                                                            ),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                        ),
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BlobHeader[]"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "blobVerificationProofs",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Array(
                                        ::std::boxed::Box::new(
                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                ::std::vec![
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                    ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                        ::std::vec![
                                                            ::ethers::core::abi::ethabi::ParamType::Tuple(
                                                                ::std::vec![
                                                                    ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                                    ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                                ],
                                                            ),
                                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                                        ],
                                                    ),
                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                    ::ethers::core::abi::ethabi::ParamType::Bytes,
                                                ],
                                            ),
                                        ),
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct BlobVerificationProof[]",
                                        ),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
            ]),
            events: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned(
                        "DefaultSecurityThresholdsV2Updated",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "DefaultSecurityThresholdsV2Updated",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "previousDefaultSecurityThresholdsV2",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "newDefaultSecurityThresholdsV2",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "QuorumAdversaryThresholdPercentagesUpdated",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "QuorumAdversaryThresholdPercentagesUpdated",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "previousQuorumAdversaryThresholdPercentages",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "newQuorumAdversaryThresholdPercentages",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned(
                        "QuorumConfirmationThresholdPercentagesUpdated",
                    ),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "QuorumConfirmationThresholdPercentagesUpdated",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "previousQuorumConfirmationThresholdPercentages",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "newQuorumConfirmationThresholdPercentages",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("QuorumNumbersRequiredUpdated"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "QuorumNumbersRequiredUpdated",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "previousQuorumNumbersRequired",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "newQuorumNumbersRequired",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("VersionedBlobParamsAdded"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "VersionedBlobParamsAdded",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("version"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(16usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned(
                                        "versionedBlobParams",
                                    ),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(32usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
            ]),
            errors: ::std::collections::BTreeMap::new(),
            receive: false,
            fallback: false,
        }
    }
    ///The parsed JSON ABI of the contract.
    pub static IEIGENDACERTVERIFIER_ABI: ::ethers::contract::Lazy<
        ::ethers::core::abi::Abi,
    > = ::ethers::contract::Lazy::new(__abi);
    pub struct IEigenDACertVerifier<M>(::ethers::contract::Contract<M>);
    impl<M> ::core::clone::Clone for IEigenDACertVerifier<M> {
        fn clone(&self) -> Self {
            Self(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<M> ::core::ops::Deref for IEigenDACertVerifier<M> {
        type Target = ::ethers::contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M> ::core::ops::DerefMut for IEigenDACertVerifier<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<M> ::core::fmt::Debug for IEigenDACertVerifier<M> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            f.debug_tuple(::core::stringify!(IEigenDACertVerifier))
                .field(&self.address())
                .finish()
        }
    }
    impl<M: ::ethers::providers::Middleware> IEigenDACertVerifier<M> {
        /// Creates a new contract instance with the specified `ethers` client at
        /// `address`. The contract derefs to a `ethers::Contract` object.
        pub fn new<T: Into<::ethers::core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            Self(
                ::ethers::contract::Contract::new(
                    address.into(),
                    IEIGENDACERTVERIFIER_ABI.clone(),
                    client,
                ),
            )
        }
        ///Calls the contract's `getBlobParams` (0x2ecfe72b) function
        pub fn get_blob_params(
            &self,
            version: u16,
        ) -> ::ethers::contract::builders::ContractCall<M, VersionedBlobParams> {
            self.0
                .method_hash([46, 207, 231, 43], version)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getIsQuorumRequired` (0x048886d2) function
        pub fn get_is_quorum_required(
            &self,
            quorum_number: u8,
        ) -> ::ethers::contract::builders::ContractCall<M, bool> {
            self.0
                .method_hash([4, 136, 134, 210], quorum_number)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getNonSignerStakesAndSignature` (0xf25de3f8) function
        pub fn get_non_signer_stakes_and_signature(
            &self,
            signed_batch: SignedBatch,
        ) -> ::ethers::contract::builders::ContractCall<M, NonSignerStakesAndSignature> {
            self.0
                .method_hash([242, 93, 227, 248], (signed_batch,))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getQuorumAdversaryThresholdPercentage` (0xee6c3bcf) function
        pub fn get_quorum_adversary_threshold_percentage(
            &self,
            quorum_number: u8,
        ) -> ::ethers::contract::builders::ContractCall<M, u8> {
            self.0
                .method_hash([238, 108, 59, 207], quorum_number)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getQuorumConfirmationThresholdPercentage` (0x1429c7c2) function
        pub fn get_quorum_confirmation_threshold_percentage(
            &self,
            quorum_number: u8,
        ) -> ::ethers::contract::builders::ContractCall<M, u8> {
            self.0
                .method_hash([20, 41, 199, 194], quorum_number)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `quorumAdversaryThresholdPercentages` (0x8687feae) function
        pub fn quorum_adversary_threshold_percentages(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Bytes,
        > {
            self.0
                .method_hash([134, 135, 254, 174], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `quorumConfirmationThresholdPercentages` (0xbafa9107) function
        pub fn quorum_confirmation_threshold_percentages(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Bytes,
        > {
            self.0
                .method_hash([186, 250, 145, 7], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `quorumNumbersRequired` (0xe15234ff) function
        pub fn quorum_numbers_required(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Bytes,
        > {
            self.0
                .method_hash([225, 82, 52, 255], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertSecurityParams` (0x143eb4d9) function
        pub fn verify_da_cert_security_params(
            &self,
            blob_params: VersionedBlobParams,
            security_thresholds: SecurityThresholds,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([20, 62, 180, 217], (blob_params, security_thresholds))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertSecurityParams` (0xccb7cd0d) function
        pub fn verify_da_cert_security_params_with_version(
            &self,
            version: u16,
            security_thresholds: SecurityThresholds,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([204, 183, 205, 13], (version, security_thresholds))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertV1` (0x7d644cad) function
        pub fn verify_da_cert_v1(
            &self,
            blob_header: BlobHeader,
            blob_verification_proof: BlobVerificationProof,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([125, 100, 76, 173], (blob_header, blob_verification_proof))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertV2` (0x813c2eb0) function
        pub fn verify_da_cert_v2(
            &self,
            batch_header: BatchHeaderV2,
            blob_inclusion_info: BlobInclusionInfo,
            non_signer_stakes_and_signature: NonSignerStakesAndSignature,
            signed_quorum_numbers: ::ethers::core::types::Bytes,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash(
                    [129, 60, 46, 176],
                    (
                        batch_header,
                        blob_inclusion_info,
                        non_signer_stakes_and_signature,
                        signed_quorum_numbers,
                    ),
                )
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertV2ForZKProof` (0x415ef614) function
        pub fn verify_da_cert_v2_for_zk_proof(
            &self,
            batch_header: BatchHeaderV2,
            blob_inclusion_info: BlobInclusionInfo,
            non_signer_stakes_and_signature: NonSignerStakesAndSignature,
            signed_quorum_numbers: ::ethers::core::types::Bytes,
        ) -> ::ethers::contract::builders::ContractCall<M, bool> {
            self.0
                .method_hash(
                    [65, 94, 246, 20],
                    (
                        batch_header,
                        blob_inclusion_info,
                        non_signer_stakes_and_signature,
                        signed_quorum_numbers,
                    ),
                )
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertV2FromSignedBatch` (0x421c0222) function
        pub fn verify_da_cert_v2_from_signed_batch(
            &self,
            signed_batch: SignedBatch,
            blob_inclusion_info: BlobInclusionInfo,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([66, 28, 2, 34], (signed_batch, blob_inclusion_info))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyDACertsV1` (0x31a3479a) function
        pub fn verify_da_certs_v1(
            &self,
            blob_headers: ::std::vec::Vec<BlobHeader>,
            blob_verification_proofs: ::std::vec::Vec<BlobVerificationProof>,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash(
                    [49, 163, 71, 154],
                    (blob_headers, blob_verification_proofs),
                )
                .expect("method not found (this should never happen)")
        }
        ///Gets the contract's `DefaultSecurityThresholdsV2Updated` event
        pub fn default_security_thresholds_v2_updated_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            DefaultSecurityThresholdsV2UpdatedFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `QuorumAdversaryThresholdPercentagesUpdated` event
        pub fn quorum_adversary_threshold_percentages_updated_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            QuorumAdversaryThresholdPercentagesUpdatedFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `QuorumConfirmationThresholdPercentagesUpdated` event
        pub fn quorum_confirmation_threshold_percentages_updated_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            QuorumConfirmationThresholdPercentagesUpdatedFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `QuorumNumbersRequiredUpdated` event
        pub fn quorum_numbers_required_updated_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            QuorumNumbersRequiredUpdatedFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `VersionedBlobParamsAdded` event
        pub fn versioned_blob_params_added_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            VersionedBlobParamsAddedFilter,
        > {
            self.0.event()
        }
        /// Returns an `Event` builder for all the events of this contract.
        pub fn events(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            IEigenDACertVerifierEvents,
        > {
            self.0.event_with_filter(::core::default::Default::default())
        }
    }
    impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
    for IEigenDACertVerifier<M> {
        fn from(contract: ::ethers::contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "DefaultSecurityThresholdsV2Updated",
        abi = "DefaultSecurityThresholdsV2Updated((uint8,uint8),(uint8,uint8))"
    )]
    pub struct DefaultSecurityThresholdsV2UpdatedFilter {
        pub previous_default_security_thresholds_v2: SecurityThresholds,
        pub new_default_security_thresholds_v2: SecurityThresholds,
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "QuorumAdversaryThresholdPercentagesUpdated",
        abi = "QuorumAdversaryThresholdPercentagesUpdated(bytes,bytes)"
    )]
    pub struct QuorumAdversaryThresholdPercentagesUpdatedFilter {
        pub previous_quorum_adversary_threshold_percentages: ::ethers::core::types::Bytes,
        pub new_quorum_adversary_threshold_percentages: ::ethers::core::types::Bytes,
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "QuorumConfirmationThresholdPercentagesUpdated",
        abi = "QuorumConfirmationThresholdPercentagesUpdated(bytes,bytes)"
    )]
    pub struct QuorumConfirmationThresholdPercentagesUpdatedFilter {
        pub previous_quorum_confirmation_threshold_percentages: ::ethers::core::types::Bytes,
        pub new_quorum_confirmation_threshold_percentages: ::ethers::core::types::Bytes,
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "QuorumNumbersRequiredUpdated",
        abi = "QuorumNumbersRequiredUpdated(bytes,bytes)"
    )]
    pub struct QuorumNumbersRequiredUpdatedFilter {
        pub previous_quorum_numbers_required: ::ethers::core::types::Bytes,
        pub new_quorum_numbers_required: ::ethers::core::types::Bytes,
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "VersionedBlobParamsAdded",
        abi = "VersionedBlobParamsAdded(uint16,(uint32,uint32,uint8))"
    )]
    pub struct VersionedBlobParamsAddedFilter {
        #[ethevent(indexed)]
        pub version: u16,
        pub versioned_blob_params: VersionedBlobParams,
    }
    ///Container type for all of the contract's events
    #[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum IEigenDACertVerifierEvents {
        DefaultSecurityThresholdsV2UpdatedFilter(
            DefaultSecurityThresholdsV2UpdatedFilter,
        ),
        QuorumAdversaryThresholdPercentagesUpdatedFilter(
            QuorumAdversaryThresholdPercentagesUpdatedFilter,
        ),
        QuorumConfirmationThresholdPercentagesUpdatedFilter(
            QuorumConfirmationThresholdPercentagesUpdatedFilter,
        ),
        QuorumNumbersRequiredUpdatedFilter(QuorumNumbersRequiredUpdatedFilter),
        VersionedBlobParamsAddedFilter(VersionedBlobParamsAddedFilter),
    }
    impl ::ethers::contract::EthLogDecode for IEigenDACertVerifierEvents {
        fn decode_log(
            log: &::ethers::core::abi::RawLog,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::Error> {
            if let Ok(decoded) = DefaultSecurityThresholdsV2UpdatedFilter::decode_log(
                log,
            ) {
                return Ok(
                    IEigenDACertVerifierEvents::DefaultSecurityThresholdsV2UpdatedFilter(
                        decoded,
                    ),
                );
            }
            if let Ok(decoded) = QuorumAdversaryThresholdPercentagesUpdatedFilter::decode_log(
                log,
            ) {
                return Ok(
                    IEigenDACertVerifierEvents::QuorumAdversaryThresholdPercentagesUpdatedFilter(
                        decoded,
                    ),
                );
            }
            if let Ok(decoded) = QuorumConfirmationThresholdPercentagesUpdatedFilter::decode_log(
                log,
            ) {
                return Ok(
                    IEigenDACertVerifierEvents::QuorumConfirmationThresholdPercentagesUpdatedFilter(
                        decoded,
                    ),
                );
            }
            if let Ok(decoded) = QuorumNumbersRequiredUpdatedFilter::decode_log(log) {
                return Ok(
                    IEigenDACertVerifierEvents::QuorumNumbersRequiredUpdatedFilter(
                        decoded,
                    ),
                );
            }
            if let Ok(decoded) = VersionedBlobParamsAddedFilter::decode_log(log) {
                return Ok(
                    IEigenDACertVerifierEvents::VersionedBlobParamsAddedFilter(decoded),
                );
            }
            Err(::ethers::core::abi::Error::InvalidData)
        }
    }
    impl ::core::fmt::Display for IEigenDACertVerifierEvents {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::DefaultSecurityThresholdsV2UpdatedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumAdversaryThresholdPercentagesUpdatedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumConfirmationThresholdPercentagesUpdatedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumNumbersRequiredUpdatedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VersionedBlobParamsAddedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
            }
        }
    }
    impl ::core::convert::From<DefaultSecurityThresholdsV2UpdatedFilter>
    for IEigenDACertVerifierEvents {
        fn from(value: DefaultSecurityThresholdsV2UpdatedFilter) -> Self {
            Self::DefaultSecurityThresholdsV2UpdatedFilter(value)
        }
    }
    impl ::core::convert::From<QuorumAdversaryThresholdPercentagesUpdatedFilter>
    for IEigenDACertVerifierEvents {
        fn from(value: QuorumAdversaryThresholdPercentagesUpdatedFilter) -> Self {
            Self::QuorumAdversaryThresholdPercentagesUpdatedFilter(value)
        }
    }
    impl ::core::convert::From<QuorumConfirmationThresholdPercentagesUpdatedFilter>
    for IEigenDACertVerifierEvents {
        fn from(value: QuorumConfirmationThresholdPercentagesUpdatedFilter) -> Self {
            Self::QuorumConfirmationThresholdPercentagesUpdatedFilter(value)
        }
    }
    impl ::core::convert::From<QuorumNumbersRequiredUpdatedFilter>
    for IEigenDACertVerifierEvents {
        fn from(value: QuorumNumbersRequiredUpdatedFilter) -> Self {
            Self::QuorumNumbersRequiredUpdatedFilter(value)
        }
    }
    impl ::core::convert::From<VersionedBlobParamsAddedFilter>
    for IEigenDACertVerifierEvents {
        fn from(value: VersionedBlobParamsAddedFilter) -> Self {
            Self::VersionedBlobParamsAddedFilter(value)
        }
    }
    ///Container type for all input parameters for the `getBlobParams` function with signature `getBlobParams(uint16)` and selector `0x2ecfe72b`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getBlobParams", abi = "getBlobParams(uint16)")]
    pub struct GetBlobParamsCall {
        pub version: u16,
    }
    ///Container type for all input parameters for the `getIsQuorumRequired` function with signature `getIsQuorumRequired(uint8)` and selector `0x048886d2`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getIsQuorumRequired", abi = "getIsQuorumRequired(uint8)")]
    pub struct GetIsQuorumRequiredCall {
        pub quorum_number: u8,
    }
    ///Container type for all input parameters for the `getNonSignerStakesAndSignature` function with signature `getNonSignerStakesAndSignature(((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])))` and selector `0xf25de3f8`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "getNonSignerStakesAndSignature",
        abi = "getNonSignerStakesAndSignature(((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])))"
    )]
    pub struct GetNonSignerStakesAndSignatureCall {
        pub signed_batch: SignedBatch,
    }
    ///Container type for all input parameters for the `getQuorumAdversaryThresholdPercentage` function with signature `getQuorumAdversaryThresholdPercentage(uint8)` and selector `0xee6c3bcf`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "getQuorumAdversaryThresholdPercentage",
        abi = "getQuorumAdversaryThresholdPercentage(uint8)"
    )]
    pub struct GetQuorumAdversaryThresholdPercentageCall {
        pub quorum_number: u8,
    }
    ///Container type for all input parameters for the `getQuorumConfirmationThresholdPercentage` function with signature `getQuorumConfirmationThresholdPercentage(uint8)` and selector `0x1429c7c2`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "getQuorumConfirmationThresholdPercentage",
        abi = "getQuorumConfirmationThresholdPercentage(uint8)"
    )]
    pub struct GetQuorumConfirmationThresholdPercentageCall {
        pub quorum_number: u8,
    }
    ///Container type for all input parameters for the `quorumAdversaryThresholdPercentages` function with signature `quorumAdversaryThresholdPercentages()` and selector `0x8687feae`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "quorumAdversaryThresholdPercentages",
        abi = "quorumAdversaryThresholdPercentages()"
    )]
    pub struct QuorumAdversaryThresholdPercentagesCall;
    ///Container type for all input parameters for the `quorumConfirmationThresholdPercentages` function with signature `quorumConfirmationThresholdPercentages()` and selector `0xbafa9107`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "quorumConfirmationThresholdPercentages",
        abi = "quorumConfirmationThresholdPercentages()"
    )]
    pub struct QuorumConfirmationThresholdPercentagesCall;
    ///Container type for all input parameters for the `quorumNumbersRequired` function with signature `quorumNumbersRequired()` and selector `0xe15234ff`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "quorumNumbersRequired", abi = "quorumNumbersRequired()")]
    pub struct QuorumNumbersRequiredCall;
    ///Container type for all input parameters for the `verifyDACertSecurityParams` function with signature `verifyDACertSecurityParams((uint32,uint32,uint8),(uint8,uint8))` and selector `0x143eb4d9`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertSecurityParams",
        abi = "verifyDACertSecurityParams((uint32,uint32,uint8),(uint8,uint8))"
    )]
    pub struct VerifyDACertSecurityParamsCall {
        pub blob_params: VersionedBlobParams,
        pub security_thresholds: SecurityThresholds,
    }
    ///Container type for all input parameters for the `verifyDACertSecurityParams` function with signature `verifyDACertSecurityParams(uint16,(uint8,uint8))` and selector `0xccb7cd0d`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertSecurityParams",
        abi = "verifyDACertSecurityParams(uint16,(uint8,uint8))"
    )]
    pub struct VerifyDaCertSecurityParamsWithVersionCall {
        pub version: u16,
        pub security_thresholds: SecurityThresholds,
    }
    ///Container type for all input parameters for the `verifyDACertV1` function with signature `verifyDACertV1(((uint256,uint256),uint32,(uint8,uint8,uint8,uint32)[]),(uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes))` and selector `0x7d644cad`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertV1",
        abi = "verifyDACertV1(((uint256,uint256),uint32,(uint8,uint8,uint8,uint32)[]),(uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes))"
    )]
    pub struct VerifyDACertV1Call {
        pub blob_header: BlobHeader,
        pub blob_verification_proof: BlobVerificationProof,
    }
    ///Container type for all input parameters for the `verifyDACertV2` function with signature `verifyDACertV2((bytes32,uint32),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes),(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][]),bytes)` and selector `0x813c2eb0`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertV2",
        abi = "verifyDACertV2((bytes32,uint32),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes),(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][]),bytes)"
    )]
    pub struct VerifyDACertV2Call {
        pub batch_header: BatchHeaderV2,
        pub blob_inclusion_info: BlobInclusionInfo,
        pub non_signer_stakes_and_signature: NonSignerStakesAndSignature,
        pub signed_quorum_numbers: ::ethers::core::types::Bytes,
    }
    ///Container type for all input parameters for the `verifyDACertV2ForZKProof` function with signature `verifyDACertV2ForZKProof((bytes32,uint32),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes),(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][]),bytes)` and selector `0x415ef614`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertV2ForZKProof",
        abi = "verifyDACertV2ForZKProof((bytes32,uint32),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes),(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][]),bytes)"
    )]
    pub struct VerifyDACertV2ForZKProofCall {
        pub batch_header: BatchHeaderV2,
        pub blob_inclusion_info: BlobInclusionInfo,
        pub non_signer_stakes_and_signature: NonSignerStakesAndSignature,
        pub signed_quorum_numbers: ::ethers::core::types::Bytes,
    }
    ///Container type for all input parameters for the `verifyDACertV2FromSignedBatch` function with signature `verifyDACertV2FromSignedBatch(((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes))` and selector `0x421c0222`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertV2FromSignedBatch",
        abi = "verifyDACertV2FromSignedBatch(((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes))"
    )]
    pub struct VerifyDACertV2FromSignedBatchCall {
        pub signed_batch: SignedBatch,
        pub blob_inclusion_info: BlobInclusionInfo,
    }
    ///Container type for all input parameters for the `verifyDACertsV1` function with signature `verifyDACertsV1(((uint256,uint256),uint32,(uint8,uint8,uint8,uint32)[])[],(uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes)[])` and selector `0x31a3479a`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyDACertsV1",
        abi = "verifyDACertsV1(((uint256,uint256),uint32,(uint8,uint8,uint8,uint32)[])[],(uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes)[])"
    )]
    pub struct VerifyDACertsV1Call {
        pub blob_headers: ::std::vec::Vec<BlobHeader>,
        pub blob_verification_proofs: ::std::vec::Vec<BlobVerificationProof>,
    }
    ///Container type for all of the contract's call
    #[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum IEigenDACertVerifierCalls {
        GetBlobParams(GetBlobParamsCall),
        GetIsQuorumRequired(GetIsQuorumRequiredCall),
        GetNonSignerStakesAndSignature(GetNonSignerStakesAndSignatureCall),
        GetQuorumAdversaryThresholdPercentage(GetQuorumAdversaryThresholdPercentageCall),
        GetQuorumConfirmationThresholdPercentage(
            GetQuorumConfirmationThresholdPercentageCall,
        ),
        QuorumAdversaryThresholdPercentages(QuorumAdversaryThresholdPercentagesCall),
        QuorumConfirmationThresholdPercentages(
            QuorumConfirmationThresholdPercentagesCall,
        ),
        QuorumNumbersRequired(QuorumNumbersRequiredCall),
        VerifyDACertSecurityParams(VerifyDACertSecurityParamsCall),
        VerifyDaCertSecurityParamsWithVersion(VerifyDaCertSecurityParamsWithVersionCall),
        VerifyDACertV1(VerifyDACertV1Call),
        VerifyDACertV2(VerifyDACertV2Call),
        VerifyDACertV2ForZKProof(VerifyDACertV2ForZKProofCall),
        VerifyDACertV2FromSignedBatch(VerifyDACertV2FromSignedBatchCall),
        VerifyDACertsV1(VerifyDACertsV1Call),
    }
    impl ::ethers::core::abi::AbiDecode for IEigenDACertVerifierCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <GetBlobParamsCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetBlobParams(decoded));
            }
            if let Ok(decoded) = <GetIsQuorumRequiredCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetIsQuorumRequired(decoded));
            }
            if let Ok(decoded) = <GetNonSignerStakesAndSignatureCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetNonSignerStakesAndSignature(decoded));
            }
            if let Ok(decoded) = <GetQuorumAdversaryThresholdPercentageCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetQuorumAdversaryThresholdPercentage(decoded));
            }
            if let Ok(decoded) = <GetQuorumConfirmationThresholdPercentageCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetQuorumConfirmationThresholdPercentage(decoded));
            }
            if let Ok(decoded) = <QuorumAdversaryThresholdPercentagesCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::QuorumAdversaryThresholdPercentages(decoded));
            }
            if let Ok(decoded) = <QuorumConfirmationThresholdPercentagesCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::QuorumConfirmationThresholdPercentages(decoded));
            }
            if let Ok(decoded) = <QuorumNumbersRequiredCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::QuorumNumbersRequired(decoded));
            }
            if let Ok(decoded) = <VerifyDACertSecurityParamsCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertSecurityParams(decoded));
            }
            if let Ok(decoded) = <VerifyDaCertSecurityParamsWithVersionCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDaCertSecurityParamsWithVersion(decoded));
            }
            if let Ok(decoded) = <VerifyDACertV1Call as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertV1(decoded));
            }
            if let Ok(decoded) = <VerifyDACertV2Call as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertV2(decoded));
            }
            if let Ok(decoded) = <VerifyDACertV2ForZKProofCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertV2ForZKProof(decoded));
            }
            if let Ok(decoded) = <VerifyDACertV2FromSignedBatchCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertV2FromSignedBatch(decoded));
            }
            if let Ok(decoded) = <VerifyDACertsV1Call as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyDACertsV1(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for IEigenDACertVerifierCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::GetBlobParams(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetIsQuorumRequired(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetNonSignerStakesAndSignature(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetQuorumAdversaryThresholdPercentage(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetQuorumConfirmationThresholdPercentage(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::QuorumAdversaryThresholdPercentages(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::QuorumConfirmationThresholdPercentages(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::QuorumNumbersRequired(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertSecurityParams(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDaCertSecurityParamsWithVersion(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertV1(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertV2(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertV2ForZKProof(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertV2FromSignedBatch(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyDACertsV1(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
            }
        }
    }
    impl ::core::fmt::Display for IEigenDACertVerifierCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::GetBlobParams(element) => ::core::fmt::Display::fmt(element, f),
                Self::GetIsQuorumRequired(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::GetNonSignerStakesAndSignature(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::GetQuorumAdversaryThresholdPercentage(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::GetQuorumConfirmationThresholdPercentage(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumAdversaryThresholdPercentages(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumConfirmationThresholdPercentages(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumNumbersRequired(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VerifyDACertSecurityParams(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VerifyDaCertSecurityParamsWithVersion(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VerifyDACertV1(element) => ::core::fmt::Display::fmt(element, f),
                Self::VerifyDACertV2(element) => ::core::fmt::Display::fmt(element, f),
                Self::VerifyDACertV2ForZKProof(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VerifyDACertV2FromSignedBatch(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::VerifyDACertsV1(element) => ::core::fmt::Display::fmt(element, f),
            }
        }
    }
    impl ::core::convert::From<GetBlobParamsCall> for IEigenDACertVerifierCalls {
        fn from(value: GetBlobParamsCall) -> Self {
            Self::GetBlobParams(value)
        }
    }
    impl ::core::convert::From<GetIsQuorumRequiredCall> for IEigenDACertVerifierCalls {
        fn from(value: GetIsQuorumRequiredCall) -> Self {
            Self::GetIsQuorumRequired(value)
        }
    }
    impl ::core::convert::From<GetNonSignerStakesAndSignatureCall>
    for IEigenDACertVerifierCalls {
        fn from(value: GetNonSignerStakesAndSignatureCall) -> Self {
            Self::GetNonSignerStakesAndSignature(value)
        }
    }
    impl ::core::convert::From<GetQuorumAdversaryThresholdPercentageCall>
    for IEigenDACertVerifierCalls {
        fn from(value: GetQuorumAdversaryThresholdPercentageCall) -> Self {
            Self::GetQuorumAdversaryThresholdPercentage(value)
        }
    }
    impl ::core::convert::From<GetQuorumConfirmationThresholdPercentageCall>
    for IEigenDACertVerifierCalls {
        fn from(value: GetQuorumConfirmationThresholdPercentageCall) -> Self {
            Self::GetQuorumConfirmationThresholdPercentage(value)
        }
    }
    impl ::core::convert::From<QuorumAdversaryThresholdPercentagesCall>
    for IEigenDACertVerifierCalls {
        fn from(value: QuorumAdversaryThresholdPercentagesCall) -> Self {
            Self::QuorumAdversaryThresholdPercentages(value)
        }
    }
    impl ::core::convert::From<QuorumConfirmationThresholdPercentagesCall>
    for IEigenDACertVerifierCalls {
        fn from(value: QuorumConfirmationThresholdPercentagesCall) -> Self {
            Self::QuorumConfirmationThresholdPercentages(value)
        }
    }
    impl ::core::convert::From<QuorumNumbersRequiredCall> for IEigenDACertVerifierCalls {
        fn from(value: QuorumNumbersRequiredCall) -> Self {
            Self::QuorumNumbersRequired(value)
        }
    }
    impl ::core::convert::From<VerifyDACertSecurityParamsCall>
    for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertSecurityParamsCall) -> Self {
            Self::VerifyDACertSecurityParams(value)
        }
    }
    impl ::core::convert::From<VerifyDaCertSecurityParamsWithVersionCall>
    for IEigenDACertVerifierCalls {
        fn from(value: VerifyDaCertSecurityParamsWithVersionCall) -> Self {
            Self::VerifyDaCertSecurityParamsWithVersion(value)
        }
    }
    impl ::core::convert::From<VerifyDACertV1Call> for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertV1Call) -> Self {
            Self::VerifyDACertV1(value)
        }
    }
    impl ::core::convert::From<VerifyDACertV2Call> for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertV2Call) -> Self {
            Self::VerifyDACertV2(value)
        }
    }
    impl ::core::convert::From<VerifyDACertV2ForZKProofCall>
    for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertV2ForZKProofCall) -> Self {
            Self::VerifyDACertV2ForZKProof(value)
        }
    }
    impl ::core::convert::From<VerifyDACertV2FromSignedBatchCall>
    for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertV2FromSignedBatchCall) -> Self {
            Self::VerifyDACertV2FromSignedBatch(value)
        }
    }
    impl ::core::convert::From<VerifyDACertsV1Call> for IEigenDACertVerifierCalls {
        fn from(value: VerifyDACertsV1Call) -> Self {
            Self::VerifyDACertsV1(value)
        }
    }
    ///Container type for all return fields from the `getBlobParams` function with signature `getBlobParams(uint16)` and selector `0x2ecfe72b`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetBlobParamsReturn(pub VersionedBlobParams);
    ///Container type for all return fields from the `getIsQuorumRequired` function with signature `getIsQuorumRequired(uint8)` and selector `0x048886d2`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetIsQuorumRequiredReturn(pub bool);
    ///Container type for all return fields from the `getNonSignerStakesAndSignature` function with signature `getNonSignerStakesAndSignature(((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])))` and selector `0xf25de3f8`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetNonSignerStakesAndSignatureReturn(pub NonSignerStakesAndSignature);
    ///Container type for all return fields from the `getQuorumAdversaryThresholdPercentage` function with signature `getQuorumAdversaryThresholdPercentage(uint8)` and selector `0xee6c3bcf`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetQuorumAdversaryThresholdPercentageReturn(pub u8);
    ///Container type for all return fields from the `getQuorumConfirmationThresholdPercentage` function with signature `getQuorumConfirmationThresholdPercentage(uint8)` and selector `0x1429c7c2`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetQuorumConfirmationThresholdPercentageReturn(pub u8);
    ///Container type for all return fields from the `quorumAdversaryThresholdPercentages` function with signature `quorumAdversaryThresholdPercentages()` and selector `0x8687feae`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct QuorumAdversaryThresholdPercentagesReturn(
        pub ::ethers::core::types::Bytes,
    );
    ///Container type for all return fields from the `quorumConfirmationThresholdPercentages` function with signature `quorumConfirmationThresholdPercentages()` and selector `0xbafa9107`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct QuorumConfirmationThresholdPercentagesReturn(
        pub ::ethers::core::types::Bytes,
    );
    ///Container type for all return fields from the `quorumNumbersRequired` function with signature `quorumNumbersRequired()` and selector `0xe15234ff`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct QuorumNumbersRequiredReturn(pub ::ethers::core::types::Bytes);
    ///Container type for all return fields from the `verifyDACertV2ForZKProof` function with signature `verifyDACertV2ForZKProof((bytes32,uint32),(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes),(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][]),bytes)` and selector `0x415ef614`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct VerifyDACertV2ForZKProofReturn(pub bool);
    ///`Attestation((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[])`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct Attestation {
        pub non_signer_pubkeys: ::std::vec::Vec<G1Point>,
        pub quorum_apks: ::std::vec::Vec<G1Point>,
        pub sigma: G1Point,
        pub apk_g2: G2Point,
        pub quorum_numbers: ::std::vec::Vec<u32>,
    }
    ///`G1Point(uint256,uint256)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct G1Point {
        pub x: ::ethers::core::types::U256,
        pub y: ::ethers::core::types::U256,
    }
    ///`G2Point(uint256[2],uint256[2])`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct G2Point {
        pub x: [::ethers::core::types::U256; 2],
        pub y: [::ethers::core::types::U256; 2],
    }
    ///`BatchHeader(bytes32,bytes,bytes,uint32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BatchHeader {
        pub blob_headers_root: [u8; 32],
        pub quorum_numbers: ::ethers::core::types::Bytes,
        pub signed_stake_for_quorums: ::ethers::core::types::Bytes,
        pub reference_block_number: u32,
    }
    ///`BatchHeaderV2(bytes32,uint32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BatchHeaderV2 {
        pub batch_root: [u8; 32],
        pub reference_block_number: u32,
    }
    ///`BatchMetadata((bytes32,bytes,bytes,uint32),bytes32,uint32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BatchMetadata {
        pub batch_header: BatchHeader,
        pub signatory_record_hash: [u8; 32],
        pub confirmation_block_number: u32,
    }
    ///`BlobCertificate((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[])`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobCertificate {
        pub blob_header: BlobHeaderV2,
        pub signature: ::ethers::core::types::Bytes,
        pub relay_keys: ::std::vec::Vec<u32>,
    }
    ///`BlobCommitment((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobCommitment {
        pub commitment: G1Point,
        pub length_commitment: G2Point,
        pub length_proof: G2Point,
        pub length: u32,
    }
    ///`BlobHeader((uint256,uint256),uint32,(uint8,uint8,uint8,uint32)[])`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobHeader {
        pub commitment: G1Point,
        pub data_length: u32,
        pub quorum_blob_params: ::std::vec::Vec<QuorumBlobParam>,
    }
    ///`BlobHeaderV2(uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobHeaderV2 {
        pub version: u16,
        pub quorum_numbers: ::ethers::core::types::Bytes,
        pub commitment: BlobCommitment,
        pub payment_header_hash: [u8; 32],
    }
    ///`BlobInclusionInfo(((uint16,bytes,((uint256,uint256),(uint256[2],uint256[2]),(uint256[2],uint256[2]),uint32),bytes32),bytes,uint32[]),uint32,bytes)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobInclusionInfo {
        pub blob_certificate: BlobCertificate,
        pub blob_index: u32,
        pub inclusion_proof: ::ethers::core::types::Bytes,
    }
    ///`BlobVerificationProof(uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlobVerificationProof {
        pub batch_id: u32,
        pub blob_index: u32,
        pub batch_metadata: BatchMetadata,
        pub inclusion_proof: ::ethers::core::types::Bytes,
        pub quorum_indices: ::ethers::core::types::Bytes,
    }
    ///`NonSignerStakesAndSignature(uint32[],(uint256,uint256)[],(uint256,uint256)[],(uint256[2],uint256[2]),(uint256,uint256),uint32[],uint32[],uint32[][])`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct NonSignerStakesAndSignature {
        pub non_signer_quorum_bitmap_indices: ::std::vec::Vec<u32>,
        pub non_signer_pubkeys: ::std::vec::Vec<G1Point>,
        pub quorum_apks: ::std::vec::Vec<G1Point>,
        pub apk_g2: G2Point,
        pub sigma: G1Point,
        pub quorum_apk_indices: ::std::vec::Vec<u32>,
        pub total_stake_indices: ::std::vec::Vec<u32>,
        pub non_signer_stake_indices: ::std::vec::Vec<::std::vec::Vec<u32>>,
    }
    ///`QuorumBlobParam(uint8,uint8,uint8,uint32)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct QuorumBlobParam {
        pub quorum_number: u8,
        pub adversary_threshold_percentage: u8,
        pub confirmation_threshold_percentage: u8,
        pub chunk_length: u32,
    }
    ///`SecurityThresholds(uint8,uint8)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct SecurityThresholds {
        pub confirmation_threshold: u8,
        pub adversary_threshold: u8,
    }
    ///`SignedBatch((bytes32,uint32),((uint256,uint256)[],(uint256,uint256)[],(uint256,uint256),(uint256[2],uint256[2]),uint32[]))`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct SignedBatch {
        pub batch_header: BatchHeaderV2,
        pub attestation: Attestation,
    }
    ///`VersionedBlobParams(uint32,uint32,uint8)`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct VersionedBlobParams {
        pub max_num_operators: u32,
        pub num_chunks: u32,
        pub coding_rate: u8,
    }
}
