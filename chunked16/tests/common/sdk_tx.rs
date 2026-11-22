//! TX v1 size using real SDK instructions: spl-token-2022-interface 4.0.0,
//! solana-zk-elgamal-proof-interface 1.x, solana-system-interface, solana-message v1.
//! `hyp` substitutes only the range-instruction data for hypothetical BP++.

use {
    super::fixtures::{FeeFixture, PlainFixture},
    std::{mem::size_of, num::NonZeroI8},
    t22addr::Address,
    t22iface::extension::confidential_transfer::instruction as ct,
    t22msg::v1,
    t22sys::instruction as sys,
    t22x::instruction::ProofLocation,
    t22zk::{
        instruction::{close_context_state, ContextStateInfo, ProofInstruction},
        proof_data::{
            BatchedGroupedCiphertext2HandlesValidityProofContext,
            BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
            CiphertextCommitmentEqualityProofContext, PercentageWithCapProofContext,
        },
        state::ProofContextState,
    },
};

pub const PACKET_LEGACY: usize = 1_232;
pub const PACKET_V1: usize = 4_096;
const RENT_LAMPORTS: u64 = 10_000_000; // Does not affect size: this is a u64 field.

#[derive(Debug, Clone)]
pub struct TxSize {
    pub layout: &'static str,
    pub instructions: usize,
    pub signatures: usize,
    pub message: usize,
    pub transaction: usize,
    pub range_ix_data: usize,
}

struct Keys {
    payer: Address,
    source: Address,
    mint: Address,
    destination: Address,
    ctx: [Address; 5],
}

fn keys() -> Keys {
    let k = |b: u8| Address::from([b; 32]);
    Keys {
        payer: k(1),
        source: k(2),
        mint: k(3),
        destination: k(4),
        ctx: [k(10), k(11), k(12), k(13), k(14)],
    }
}

fn at(n: i8) -> NonZeroI8 {
    NonZeroI8::new(n).expect("offset != 0")
}

// Leave the Instruction type inferred from the SDK builders.
// TX size = message.size() + 64 bytes for the signature (SIMD-0385, without the length prefix).
macro_rules! measure {
    ($layout:expr, $payer:expr, $ixs:expr, $range_idx:expr, $range_data:expr, $hyp:expr) => {{
        let mut ixs = $ixs;
        assert_eq!(
            &ixs[$range_idx].data[1..],
            bytemuck::bytes_of($range_data),
            "range instruction index"
        );
        if let Some(data) = $hyp {
            ixs[$range_idx].data = data;
        }
        let range_ix_data = ixs[$range_idx].data.len();
        let config = v1::TransactionConfig::empty().with_compute_unit_limit(1_000_000);
        let msg = v1::Message::try_compile_with_config($payer, &ixs, Default::default(), config)
            .expect("v1 compile");
        let signatures = usize::from(msg.header.num_required_signatures);
        let message = msg.size();
        TxSize {
            layout: $layout,
            instructions: ixs.len(),
            signatures,
            message,
            transaction: message + 64 * signatures,
            range_ix_data,
        }
    }};
}

/// All five proofs in the same transaction (InstructionOffset 1..5).
pub fn fee_inline(fx: &FeeFixture, hyp: Option<Vec<u8>>) -> TxSize {
    let k = keys();
    let ixs = ct::transfer_with_fee(
        &t22iface::id(),
        &k.source,
        &k.mint,
        &k.destination,
        &fx.new_decryptable,
        &fx.auditor_lo,
        &fx.auditor_hi,
        &k.payer,
        &[],
        ProofLocation::InstructionOffset(at(1), &fx.equality),
        ProofLocation::InstructionOffset(at(2), &fx.validity3),
        ProofLocation::InstructionOffset(at(3), &fx.percentage),
        ProofLocation::InstructionOffset(at(4), &fx.validity2),
        ProofLocation::InstructionOffset(at(5), &fx.range),
    )
    .expect("transfer_with_fee");
    measure!("fee/inline", &k.payer, ixs, 5, &fx.range, hyp)
}

/// All in one v1 transaction: create x5, verify-to-context x5, transfer, close x5.
pub fn fee_context_state(fx: &FeeFixture, hyp: Option<Vec<u8>>) -> TxSize {
    let k = keys();
    let zk = t22zk::id();
    let info = |i: usize| ContextStateInfo {
        context_state_account: &k.ctx[i],
        context_state_authority: &k.payer,
    };
    let spaces = [
        size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>(),
        size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>(),
        size_of::<ProofContextState<PercentageWithCapProofContext>>(),
        size_of::<ProofContextState<BatchedGroupedCiphertext2HandlesValidityProofContext>>(),
        size_of::<ProofContextState<BatchedRangeProofContext>>(),
    ];
    let mut ixs = Vec::new();
    for (i, space) in spaces.iter().enumerate() {
        ixs.push(sys::create_account(
            &k.payer,
            &k.ctx[i],
            RENT_LAMPORTS,
            *space as u64,
            &zk,
        ));
    }
    ixs.push(
        ProofInstruction::VerifyCiphertextCommitmentEquality
            .encode_verify_proof(Some(info(0)), &fx.equality),
    );
    ixs.push(
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
            .encode_verify_proof(Some(info(1)), &fx.validity3),
    );
    ixs.push(
        ProofInstruction::VerifyPercentageWithCap
            .encode_verify_proof(Some(info(2)), &fx.percentage),
    );
    ixs.push(
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
            .encode_verify_proof(Some(info(3)), &fx.validity2),
    );
    let range_idx = ixs.len();
    ixs.push(
        ProofInstruction::VerifyBatchedRangeProofU256.encode_verify_proof(Some(info(4)), &fx.range),
    );
    ixs.push(
        ct::inner_transfer_with_fee(
            &t22iface::id(),
            &k.source,
            &k.mint,
            &k.destination,
            &fx.new_decryptable,
            &fx.auditor_lo,
            &fx.auditor_hi,
            &k.payer,
            &[],
            ProofLocation::ContextStateAccount(&k.ctx[0]),
            ProofLocation::ContextStateAccount(&k.ctx[1]),
            ProofLocation::ContextStateAccount(&k.ctx[2]),
            ProofLocation::ContextStateAccount(&k.ctx[3]),
            ProofLocation::ContextStateAccount(&k.ctx[4]),
        )
        .expect("inner_transfer_with_fee"),
    );
    for i in 0..5 {
        ixs.push(close_context_state(info(i), &k.payer));
    }
    measure!(
        "fee/context-state",
        &k.payer,
        ixs,
        range_idx,
        &fx.range,
        hyp
    )
}

pub fn plain_inline(fx: &PlainFixture, hyp: Option<Vec<u8>>) -> TxSize {
    let k = keys();
    let ixs = ct::transfer(
        &t22iface::id(),
        &k.source,
        &k.mint,
        &k.destination,
        &fx.new_decryptable,
        &fx.auditor_lo,
        &fx.auditor_hi,
        &k.payer,
        &[],
        ProofLocation::InstructionOffset(at(1), &fx.equality),
        ProofLocation::InstructionOffset(at(2), &fx.validity3),
        ProofLocation::InstructionOffset(at(3), &fx.range),
    )
    .expect("transfer");
    measure!("plain/inline", &k.payer, ixs, 3, &fx.range, hyp)
}

pub fn plain_context_state(fx: &PlainFixture, hyp: Option<Vec<u8>>) -> TxSize {
    let k = keys();
    let zk = t22zk::id();
    let info = |i: usize| ContextStateInfo {
        context_state_account: &k.ctx[i],
        context_state_authority: &k.payer,
    };
    let spaces = [
        size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>(),
        size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>(),
        size_of::<ProofContextState<BatchedRangeProofContext>>(),
    ];
    let mut ixs = Vec::new();
    for (i, space) in spaces.iter().enumerate() {
        ixs.push(sys::create_account(
            &k.payer,
            &k.ctx[i],
            RENT_LAMPORTS,
            *space as u64,
            &zk,
        ));
    }
    ixs.push(
        ProofInstruction::VerifyCiphertextCommitmentEquality
            .encode_verify_proof(Some(info(0)), &fx.equality),
    );
    ixs.push(
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
            .encode_verify_proof(Some(info(1)), &fx.validity3),
    );
    let range_idx = ixs.len();
    ixs.push(
        ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof(Some(info(2)), &fx.range),
    );
    ixs.push(
        ct::inner_transfer(
            &t22iface::id(),
            &k.source,
            &k.mint,
            &k.destination,
            &fx.new_decryptable,
            &fx.auditor_lo,
            &fx.auditor_hi,
            &k.payer,
            &[],
            ProofLocation::ContextStateAccount(&k.ctx[0]),
            ProofLocation::ContextStateAccount(&k.ctx[1]),
            ProofLocation::ContextStateAccount(&k.ctx[2]),
        )
        .expect("inner_transfer"),
    );
    for i in 0..3 {
        ixs.push(close_context_state(info(i), &k.payer));
    }
    measure!(
        "plain/context-state",
        &k.payer,
        ixs,
        range_idx,
        &fx.range,
        hyp
    )
}
