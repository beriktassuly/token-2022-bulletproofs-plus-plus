//! Verify zk-sdk 8.1 proofs and extract their context with the standard extractor 0.7.0.

use {
    super::fixtures::{FeeFixture, PlainFixture},
    solana_zk_sdk::zk_elgamal_proof_program::VerifyZkProof,
    t22x::{
        errors::TokenProofExtractionError, transfer::TransferProofContext,
        transfer_with_fee::TransferWithFeeProofContext,
    },
    t22zk::proof_data::ZkProofData,
};

pub fn verify_sigma_fee(fx: &FeeFixture) -> Result<(), String> {
    fx.equality
        .verify_proof()
        .map_err(|e| format!("equality: {e:?}"))?;
    fx.validity3
        .verify_proof()
        .map_err(|e| format!("validity3: {e:?}"))?;
    fx.percentage
        .verify_proof()
        .map_err(|e| format!("percentage_with_cap: {e:?}"))?;
    fx.validity2
        .verify_proof()
        .map_err(|e| format!("validity2: {e:?}"))
}

pub fn verify_range_zk_fee(fx: &FeeFixture) -> Result<(), String> {
    fx.range
        .verify_proof()
        .map_err(|e| format!("range u256: {e:?}"))
}

pub fn extract_fee(
    fx: &FeeFixture,
    bps: u16,
    max_fee: u64,
) -> Result<TransferWithFeeProofContext, TokenProofExtractionError> {
    TransferWithFeeProofContext::verify_and_extract(
        fx.equality.context_data(),
        fx.validity3.context_data(),
        fx.percentage.context_data(),
        fx.validity2.context_data(),
        fx.range.context_data(),
        bps,
        max_fee,
    )
}

pub fn verify_sigma_plain(fx: &PlainFixture) -> Result<(), String> {
    fx.equality
        .verify_proof()
        .map_err(|e| format!("equality: {e:?}"))?;
    fx.validity3
        .verify_proof()
        .map_err(|e| format!("validity3: {e:?}"))
}

pub fn verify_range_zk_plain(fx: &PlainFixture) -> Result<(), String> {
    fx.range
        .verify_proof()
        .map_err(|e| format!("range u128: {e:?}"))
}

pub fn extract_plain(fx: &PlainFixture) -> Result<TransferProofContext, TokenProofExtractionError> {
    TransferProofContext::verify_and_extract(
        fx.equality.context_data(),
        fx.validity3.context_data(),
        fx.range.context_data(),
    )
}
