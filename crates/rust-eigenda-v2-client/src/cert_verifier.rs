use ethers::prelude::*;
use rust_eigenda_signers::signers::ethers::Signer as EthersSigner;
use rust_eigenda_v2_common::{EigenDACert};
use std::sync::Arc;

use ethereum_types::H160;

use crate::{
    core::eigenda_cert::eigenda_cert_to_abi_encoded, errors::{CertVerifierError, ConversionError}, generated::{
        i_cert_verifier::{
            IEigenDACertVerifier,
            SecurityThresholds,
        }, i_eigen_da_cert_verifier_base::IEigenDACertVerifierBase,
    }, utils::SecretUrl
};

#[derive(Debug, Clone)]
/// Provides methods for interacting with the EigenDA CertVerifier contract.
pub struct CertVerifier<S> {
    cert_verifier_contract: IEigenDACertVerifier<SignerMiddleware<Provider<Http>, EthersSigner<S>>>,
    cert_verifier_contract_base: IEigenDACertVerifierBase<SignerMiddleware<Provider<Http>, EthersSigner<S>>>,
}

impl<S> CertVerifier<S> {
    /// Creates a new instance of [`CertVerifier`], receiving the address of the contract and the ETH RPC url.
    pub fn new(address: H160, rpc_url: SecretUrl, signer: S) -> Result<Self, CertVerifierError>
    where
        EthersSigner<S>: Signer,
    {
        let url: String = rpc_url.try_into()?;

        let provider = Provider::<Http>::try_from(url).map_err(ConversionError::UrlParse)?;
        // ethers hard codes 1 when constructing wallets
        let chain_id = 1;
        let signer = EthersSigner::new(signer, chain_id);
        let client = SignerMiddleware::new(provider, signer);
        let client = Arc::new(client);
        let cert_verifier_contract = IEigenDACertVerifier::new(address, client.clone());

        let cert_verifier_contract_base = IEigenDACertVerifierBase::new(address, client);
        Ok(CertVerifier {
            cert_verifier_contract,
            cert_verifier_contract_base
        })
    }

    /// Queries the cert verifier contract for the configured set of quorum numbers that must
    /// be set in the BlobHeader, and verified in VerifyDACertV2 and verifyDACertV2FromSignedBatch
    pub async fn quorum_numbers_required(&self) -> Result<Vec<u8>, CertVerifierError>
    where
        EthersSigner<S>: Signer,
    {
        let quorums: Bytes = self
            .cert_verifier_contract
            .quorum_numbers_required()
            .call()
            .await
            .map_err(|_| CertVerifierError::Contract("quorum_numbers_required".to_string()))?;
        Ok(quorums.to_vec())
    }

    /// Calls the VerifyCertV2 view function on the EigenDACertVerifier contract.
    ///
    /// This method returns an empty Result if the cert is successfully verified. Otherwise, it returns a [`CertVerifierError`].
    pub async fn verify_cert_v2(&self, eigenda_cert: &EigenDACert) -> Result<(), CertVerifierError>
    where
        EthersSigner<S>: Signer,
    {
        let abi_encoded_cert: Vec<u8>  = eigenda_cert_to_abi_encoded(eigenda_cert).unwrap();
        self.cert_verifier_contract_base.check_da_cert(Bytes::from(abi_encoded_cert))
            .call()
            .await
            .map_err(|_| CertVerifierError::Contract("check_da_cert".to_string()))?;
        Ok(())
    }

    pub async fn get_confirmation_threshold(&self) -> Result<u8, CertVerifierError>
    where
        EthersSigner<S>: Signer,
    {
        let result: SecurityThresholds = self.cert_verifier_contract
            .security_thresholds()
            .call()
            .await
            .map_err(|_| {
                CertVerifierError::Contract("security_thresholds".to_string())
            })?;

        Ok(result.confirmation_threshold)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_bn254::{G1Affine, G2Affine};
    use ark_ff::{BigInt, Fp2};
    use rust_eigenda_v2_common::{
        BatchHeaderV2, BlobCertificate, BlobCommitments, BlobHeader, BlobInclusionInfo,
        EigenDACert, NonSignerStakesAndSignature,
    };
    use url::Url;

    use crate::{
        cert_verifier::CertVerifier,
        tests::{get_test_private_key_signer, CERT_VERIFIER_ADDRESS, HOLESKY_ETH_RPC_URL},
        utils::SecretUrl,
    };

    fn get_test_eigenda_cert() -> EigenDACert {
        let commitment = G1Affine::new(
            BigInt::from_str(
                "12333798181301323475650542858494027157894807436765791161947036530299714261436",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "11128044787060091585348350525532886346962300834309368301486420106780036224253",
            )
            .unwrap()
            .into(),
        );

        let length_commitment = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "5716322077716147030690054711846283217996964008853823145286748982289839497743",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "3650156319996016584559584710300275244609429854872136622487563168287789777654",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "10974685880072588044730534361232244968799811245270164514077786783897822758261",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "11553532820257652978387180802956870865647930659194545412810154067266016884124",
                )
                .unwrap()
                .into(),
            ),
        );

        let length_proof = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "4643675515760837928167599812909403821109601017344830791188028375822253168965",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "8734750208192122540025124188153917163322702241123731120591607917408915752445",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "17072133967246531985744349781442497791252914903907036772805819247780542991745",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "20294276478832695059547819261651444779625884263296109788369710672065573438470",
                )
                .unwrap()
                .into(),
            ),
        );

        let quorum_apks = vec![
            G1Affine::new(
                BigInt::from_str(
                    "20707377398918879861052200395641848564754169290994507074171703031964381240954",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "19818270338060648434242060737031700807791827974882969750823362309435401682703",
                )
                .unwrap()
                .into(),
            ),
            G1Affine::new(
                BigInt::from_str(
                    "9817020594633164190020731292959226780976321240116097510692294534725289247448",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "6543934278976149913385688504460018919257753414424306454948368312689483583934",
                )
                .unwrap()
                .into(),
            ),
        ];

        let apk_g2 = G2Affine::new(
            Fp2::new(
                BigInt::from_str(
                    "14965994889071619819446937262508283023425732847803582775082308126897001858385",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "424511265199836222171189838201654012504607225718840732994210815543791072723",
                )
                .unwrap()
                .into(),
            ),
            Fp2::new(
                BigInt::from_str(
                    "10334432992602034872979025009842481721144509800260495829990482515621755075795",
                )
                .unwrap()
                .into(),
                BigInt::from_str(
                    "9841818323264649074514261459775280044000073958159617760595021082785845935923",
                )
                .unwrap()
                .into(),
            ),
        );

        let sigma = G1Affine::new(
            BigInt::from_str(
                "5283565740702483325309310716144955944667412378052706390324593310913313977527",
            )
            .unwrap()
            .into(),
            BigInt::from_str(
                "6773449901572267613561034602952802067869620344494017242807811863225363932048",
            )
            .unwrap()
            .into(),
        );

        EigenDACert {
            blob_inclusion_info: BlobInclusionInfo {
                blob_certificate: BlobCertificate {
                    blob_header: BlobHeader {
                        version: 0,
                        quorum_numbers: vec![0, 1], // breaks when changes
                        commitment: BlobCommitments {
                            commitment,
                            length_commitment,
                            length_proof,
                            length: 64,
                        },
                        payment_header_hash: [
                            29, 146, 146, 30, 199, 36, 31, 25, 135, 92, 123, 219, 227, 120, 149,
                            42, 90, 132, 47, 17, 6, 243, 38, 190, 6, 161, 62, 59, 163, 217, 173,
                            131,
                        ],
                    },
                    signature: vec![
                        92, 83, 82, 196, 28, 254, 190, 62, 52, 229, 80, 45, 61, 171, 85, 81, 181,
                        12, 175, 28, 208, 16, 84, 89, 8, 216, 93, 17, 233, 157, 220, 238, 91, 218,
                        254, 142, 201, 178, 65, 198, 103, 157, 13, 105, 11, 39, 141, 231, 36, 67,
                        58, 22, 227, 215, 132, 147, 146, 75, 172, 140, 72, 119, 222, 170, 0,
                    ],
                    relay_keys: vec![1, 0], // breaks when changes
                },
                blob_index: 0, // does not break when changes
                inclusion_proof: vec![],
            },
            batch_header: BatchHeaderV2 {
                batch_root: [
                    179, 157, 140, 16, 70, 67, 200, 196, 172, 175, 23, 7, 232, 98, 121, 153, 195,
                    200, 53, 38, 173, 110, 102, 121, 6, 124, 187, 124, 64, 41, 132, 28,
                ], // breaks when changed
                reference_block_number: 3672938, // breaks when changed
            },
            non_signer_stakes_and_signature: NonSignerStakesAndSignature {
                non_signer_quorum_bitmap_indices: vec![],
                non_signer_pubkeys: vec![],
                quorum_apks,
                apk_g2,
                sigma,
                quorum_apk_indices: vec![1745, 2176], // breaks when changed
                total_stake_indices: vec![2309, 2442], // breaks when changed
                non_signer_stake_indices: vec![vec![], vec![]], // does not break when changed
            },
            signed_quorum_numbers: vec![0, 1], // breaks when changed
        }
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    async fn test_verify_cert() {
        let cert_verifier = CertVerifier::new(
            CERT_VERIFIER_ADDRESS,
            SecretUrl::new(Url::from_str(HOLESKY_ETH_RPC_URL).unwrap()),
            get_test_private_key_signer(),
        )
        .unwrap();
        let res = cert_verifier.verify_cert_v2(&get_test_eigenda_cert()).await;
        assert!(res.is_ok())
    }
}
