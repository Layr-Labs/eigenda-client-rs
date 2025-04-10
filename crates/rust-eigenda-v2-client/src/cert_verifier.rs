use std::str::FromStr;

use alloy_primitives::{Address, Uint};
use alloy::{	
    network::Ethereum,	
    providers::{Provider, RootProvider},
};
use alloy_sol_types::sol_data::FixedArray;
use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger, Fp2, PrimeField};

use crate::{contracts_bindings::{IEigenDACertVerifier::{self, getNonSignerStakesAndSignatureCall, Attestation as AttestationContract, BatchHeaderV2, IEigenDACertVerifierCalls, NonSignerStakesAndSignature as NonSignerStakesAndSignatureContract, SignedBatch as ContractSignedBatch}, BN254::{G1Point, G2Point}}, core::eigenda_cert::NonSignerStakesAndSignature, generated::{common::v2::BatchHeader, disperser::v2::{Attestation, SignedBatch}}, utils::{g1_commitment_from_bytes, g2_commitment_from_bytes}};

type CertVerifierContract = IEigenDACertVerifier::IEigenDACertVerifierInstance<RootProvider<Ethereum>>;

pub(crate) struct CertVerifier {
    cert_verifier_contract: CertVerifierContract
}

impl CertVerifier {
    pub fn new(address: String, rpc_url: String) -> Self {
        let url = alloy::transports::http::reqwest::Url::from_str(&rpc_url).unwrap();
        let provider: RootProvider<
            Ethereum
        > = RootProvider::new_http(url);	

        let cer_verifier_address = alloy::primitives::Address::from_str(&address).unwrap();
        let cert_verifier_contract: IEigenDACertVerifier::IEigenDACertVerifierInstance<RootProvider>= IEigenDACertVerifier::new(cer_verifier_address, provider);
        CertVerifier {
            cert_verifier_contract,
        }
    }
    pub async fn get_non_signer_stakes_and_signature(&self, signed_batch: SignedBatch) -> NonSignerStakesAndSignature{
        let contract_signed_batch = self.signed_batch_proto_to_contract(signed_batch);
        let non_signer_stakes_and_signature = self.cert_verifier_contract.getNonSignerStakesAndSignature(contract_signed_batch).call().await?;

        self.non_signer_stakes_and_signature_contract_to_core(non_signer_stakes_and_signature)
    }

    pub async fn quorum_numbers_required(&self) -> Vec<u8> {
        let quorums = self.cert_verifier_contract.quorumNumbersRequired().call().await.unwrap();
        quorums.iter().map(|q| *q as u8).collect()
    }

    fn signed_batch_proto_to_contract(&self, signed_batch: SignedBatch) -> ContractSignedBatch {
        let batch_header = self.batch_header_proto_to_contract(signed_batch.header.unwrap());
        let attestation = self.attestation_proto_to_contract(signed_batch.attestation.unwrap());
        ContractSignedBatch {
            batchHeader: batch_header,
            attestation,
        }
    }

    fn batch_header_proto_to_contract(&self, batch_header: BatchHeader) -> BatchHeaderV2 {
        BatchHeaderV2 {
            batchRoot: alloy_primitives::FixedBytes(batch_header.batch_root.try_into().unwrap()),
            referenceBlockNumber: batch_header.reference_block_number as u32,
        }
    }

    fn attestation_proto_to_contract(&self, attestation: Attestation) -> AttestationContract {
        AttestationContract {
            nonSignerPubkeys: attestation.non_signer_pubkeys.iter().map(|p| self.g1_point_from_bytes(p)).collect(),
            quorumApks: attestation.quorum_apks.iter().map(|p| self.g1_point_from_bytes(p)).collect(),
            sigma: self.g1_point_from_bytes(&attestation.sigma),
            apkG2: self.g2_point_from_bytes(&attestation.apk_g2),
            quorumNumbers: attestation.quorum_numbers,
        }
    }

    fn non_signer_stakes_and_signature_contract_to_core(&self, non_signer_stakes_and_signature: NonSignerStakesAndSignatureContract) -> NonSignerStakesAndSignature {
        NonSignerStakesAndSignature {
            non_signer_quorum_bitmap_indices: non_signer_stakes_and_signature.nonSignerQuorumBitmapIndices,
            non_signer_pubkeys: non_signer_stakes_and_signature.nonSignerPubkeys.iter().map(|p| self.g1_affine_from_g1_point(p)).collect(),
            quorum_apks: non_signer_stakes_and_signature.quorumApks.iter().map(|p| self.g1_affine_from_g1_point(p)).collect(),
            apk_g2: self.g2_affine_from_g2_point(&non_signer_stakes_and_signature.apkG2),
            sigma: self.g1_affine_from_g1_point(&non_signer_stakes_and_signature.sigma),
            quorum_apk_indices: non_signer_stakes_and_signature.quorumApkIndices,
            total_stake_indices: non_signer_stakes_and_signature.totalStakeIndices,
            non_signer_stake_indices: non_signer_stakes_and_signature.nonSignerStakeIndices,
        }
    }

    fn g1_point_from_bytes(&self, bytes: &[u8]) -> G1Point {
        let g1_affine = g1_commitment_from_bytes(bytes).unwrap();
        G1Point {
            X: Uint::from_be_bytes::<32>(g1_affine.x.into_bigint().to_bytes_be().try_into().unwrap()),
            Y: Uint::from_be_bytes::<32>(g1_affine.y.into_bigint().to_bytes_be().try_into().unwrap())
        }
    }

    fn g2_point_from_bytes(&self, bytes: &[u8]) -> G2Point {
        let g2_affine = g2_commitment_from_bytes(bytes).unwrap();
        G2Point {
            X: [Uint::from_be_bytes::<32>(g2_affine.x.c0.into_bigint().to_bytes_be().try_into().unwrap()),
                Uint::from_be_bytes::<32>(g2_affine.x.c1.into_bigint().to_bytes_be().try_into().unwrap())],
            Y: [Uint::from_be_bytes::<32>(g2_affine.y.c0.into_bigint().to_bytes_be().try_into().unwrap()),
                Uint::from_be_bytes::<32>(g2_affine.y.c1.into_bigint().to_bytes_be().try_into().unwrap())]
        }
    }

    fn g1_affine_from_g1_point(&self, g1_point: &G1Point) -> G1Affine {
        let x = Fq::from_be_bytes_mod_order(&g1_point.X.to_be_bytes::<32>());
        let y = Fq::from_be_bytes_mod_order(&g1_point.Y.to_be_bytes::<32>());
        G1Affine::new(x, y)
    }

    fn g2_affine_from_g2_point(&self, g2_point: &G2Point) -> G2Affine {
        let x = Fp2::new(
            Fq::from_be_bytes_mod_order(&g2_point.X[0].to_be_bytes::<32>()),
            Fq::from_be_bytes_mod_order(&g2_point.X[1].to_be_bytes::<32>()),
        );
        let y = Fp2::new(
            Fq::from_be_bytes_mod_order(&g2_point.Y[0].to_be_bytes::<32>()),
            Fq::from_be_bytes_mod_order(&g2_point.Y[1].to_be_bytes::<32>()),
        );
        G2Affine::new(x, y)
    }
}
