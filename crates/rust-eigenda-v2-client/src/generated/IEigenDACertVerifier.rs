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
    #[allow(deprecated)]
    fn __abi() -> ::ethers::core::abi::Abi {
        ::ethers::core::abi::ethabi::Contract {
            constructor: ::core::option::Option::None,
            functions: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("eigenDASignatureVerifier"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "eigenDASignatureVerifier",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Address,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "contract IEigenDASignatureVerifier",
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
                    ::std::borrow::ToOwned::to_owned("eigenDAThresholdRegistry"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "eigenDAThresholdRegistry",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Address,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "contract IEigenDAThresholdRegistry",
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
                    ::std::borrow::ToOwned::to_owned("securityThresholds"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("securityThresholds"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(8usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned(
                                            "struct EigenDATypesV1.SecurityThresholds",
                                        ),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
            ]),
            events: ::std::collections::BTreeMap::new(),
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
        ///Calls the contract's `eigenDASignatureVerifier` (0xefd4532b) function
        pub fn eigen_da_signature_verifier(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Address,
        > {
            self.0
                .method_hash([239, 212, 83, 43], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `eigenDAThresholdRegistry` (0xf8c66814) function
        pub fn eigen_da_threshold_registry(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Address,
        > {
            self.0
                .method_hash([248, 198, 104, 20], ())
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
        ///Calls the contract's `securityThresholds` (0x21b9b2fb) function
        pub fn security_thresholds(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<M, SecurityThresholds> {
            self.0
                .method_hash([33, 185, 178, 251], ())
                .expect("method not found (this should never happen)")
        }
    }
    impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
    for IEigenDACertVerifier<M> {
        fn from(contract: ::ethers::contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    ///Container type for all input parameters for the `eigenDASignatureVerifier` function with signature `eigenDASignatureVerifier()` and selector `0xefd4532b`
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
    #[ethcall(name = "eigenDASignatureVerifier", abi = "eigenDASignatureVerifier()")]
    pub struct EigenDASignatureVerifierCall;
    ///Container type for all input parameters for the `eigenDAThresholdRegistry` function with signature `eigenDAThresholdRegistry()` and selector `0xf8c66814`
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
    #[ethcall(name = "eigenDAThresholdRegistry", abi = "eigenDAThresholdRegistry()")]
    pub struct EigenDAThresholdRegistryCall;
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
    ///Container type for all input parameters for the `securityThresholds` function with signature `securityThresholds()` and selector `0x21b9b2fb`
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
    #[ethcall(name = "securityThresholds", abi = "securityThresholds()")]
    pub struct SecurityThresholdsCall;
    ///Container type for all of the contract's call
    #[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum IEigenDACertVerifierCalls {
        EigenDASignatureVerifier(EigenDASignatureVerifierCall),
        EigenDAThresholdRegistry(EigenDAThresholdRegistryCall),
        QuorumNumbersRequired(QuorumNumbersRequiredCall),
        SecurityThresholds(SecurityThresholdsCall),
    }
    impl ::ethers::core::abi::AbiDecode for IEigenDACertVerifierCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <EigenDASignatureVerifierCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::EigenDASignatureVerifier(decoded));
            }
            if let Ok(decoded) = <EigenDAThresholdRegistryCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::EigenDAThresholdRegistry(decoded));
            }
            if let Ok(decoded) = <QuorumNumbersRequiredCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::QuorumNumbersRequired(decoded));
            }
            if let Ok(decoded) = <SecurityThresholdsCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::SecurityThresholds(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for IEigenDACertVerifierCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::EigenDASignatureVerifier(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::EigenDAThresholdRegistry(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::QuorumNumbersRequired(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::SecurityThresholds(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
            }
        }
    }
    impl ::core::fmt::Display for IEigenDACertVerifierCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::EigenDASignatureVerifier(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::EigenDAThresholdRegistry(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::QuorumNumbersRequired(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::SecurityThresholds(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
            }
        }
    }
    impl ::core::convert::From<EigenDASignatureVerifierCall>
    for IEigenDACertVerifierCalls {
        fn from(value: EigenDASignatureVerifierCall) -> Self {
            Self::EigenDASignatureVerifier(value)
        }
    }
    impl ::core::convert::From<EigenDAThresholdRegistryCall>
    for IEigenDACertVerifierCalls {
        fn from(value: EigenDAThresholdRegistryCall) -> Self {
            Self::EigenDAThresholdRegistry(value)
        }
    }
    impl ::core::convert::From<QuorumNumbersRequiredCall> for IEigenDACertVerifierCalls {
        fn from(value: QuorumNumbersRequiredCall) -> Self {
            Self::QuorumNumbersRequired(value)
        }
    }
    impl ::core::convert::From<SecurityThresholdsCall> for IEigenDACertVerifierCalls {
        fn from(value: SecurityThresholdsCall) -> Self {
            Self::SecurityThresholds(value)
        }
    }
    ///Container type for all return fields from the `eigenDASignatureVerifier` function with signature `eigenDASignatureVerifier()` and selector `0xefd4532b`
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
    pub struct EigenDASignatureVerifierReturn(pub ::ethers::core::types::Address);
    ///Container type for all return fields from the `eigenDAThresholdRegistry` function with signature `eigenDAThresholdRegistry()` and selector `0xf8c66814`
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
    pub struct EigenDAThresholdRegistryReturn(pub ::ethers::core::types::Address);
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
    ///Container type for all return fields from the `securityThresholds` function with signature `securityThresholds()` and selector `0x21b9b2fb`
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
    pub struct SecurityThresholdsReturn(pub SecurityThresholds);
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
}
