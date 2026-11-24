//! Token-2022 fixtures with range openings (needed for BP++).
//!
//! Mirrors spl-token-confidential-transfer-proof-generation 0.7.0
//! (transfer.rs, transfer_with_fee.rs). The only difference is that it exposes
//! range-commitment values and openings. TransferAmountCiphertext/FeeCiphertext
//! are replaced by their inner values (new_rand + encrypt_with), since their .0 fields are private.

use {
    bytemuck::{bytes_of, Pod},
    curve25519_dalek::scalar::Scalar,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::{ElGamalCiphertext, ElGamalKeypair},
            grouped_elgamal::{GroupedElGamal, GroupedElGamalCiphertext},
            pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
        },
        zk_elgamal_proof_program::{
            build_batched_grouped_ciphertext_2_handles_validity_proof_data,
            build_batched_grouped_ciphertext_3_handles_validity_proof_data,
            build_batched_range_proof_u128_data, build_batched_range_proof_u256_data,
            build_ciphertext_commitment_equality_proof_data, build_percentage_with_cap_proof_data,
        },
    },
    t22gen::{
        try_combine_lo_hi_ciphertexts, try_combine_lo_hi_commitments, try_combine_lo_hi_openings,
        try_split_u64, TRANSFER_AMOUNT_HI_BITS, TRANSFER_AMOUNT_LO_BITS,
    },
    t22pod::encryption::{auth_encryption::PodAeCiphertext, elgamal::PodElGamalCiphertext},
    t22zk::proof_data::{
        BatchedGroupedCiphertext2HandlesValidityProofData,
        BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofU128Data,
        BatchedRangeProofU256Data, CiphertextCommitmentEqualityProofData,
        PercentageWithCapProofData, ZkProofData,
    },
};

pub const MAX_FEE_BASIS_POINTS: u64 = 10_000;
const MAX_FEE_BASIS_POINTS_SUB_ONE: u64 = 9_999;
const ONE_IN_BASIS_POINTS: u128 = MAX_FEE_BASIS_POINTS as u128;
const FEE_AMOUNT_LO_BITS: usize = 16;
const FEE_AMOUNT_HI_BITS: usize = 32;
const REMAINING_BALANCE_BIT_LENGTH: usize = 64;
const DELTA_BIT_LENGTH: usize = 16;
const NET_TRANSFER_AMOUNT_BIT_LENGTH: usize = 64;
const PADDING_BIT_LENGTH: usize = 16;

/// Order and widths match extractor 0.7.0 (transfer_with_fee.rs).
pub const FEE_WIDTHS: [usize; 8] = [
    REMAINING_BALANCE_BIT_LENGTH,
    TRANSFER_AMOUNT_LO_BITS,
    TRANSFER_AMOUNT_HI_BITS,
    DELTA_BIT_LENGTH,
    DELTA_BIT_LENGTH,
    FEE_AMOUNT_LO_BITS,
    FEE_AMOUNT_HI_BITS,
    NET_TRANSFER_AMOUNT_BIT_LENGTH,
];

/// Every active slot of the U128 context, padding included. Extractor 0.7.0
/// (transfer.rs) checks only the first three commitments but all four bit lengths,
/// and the context written to a context-state account attests to all four.
pub const PLAIN_WIDTHS: [usize; 4] = [
    REMAINING_BALANCE_BIT_LENGTH,
    TRANSFER_AMOUNT_LO_BITS,
    TRANSFER_AMOUNT_HI_BITS,
    PADDING_BIT_LENGTH,
];

pub struct Parties {
    pub source: ElGamalKeypair,
    pub aes: AeKey,
    pub destination: ElGamalKeypair,
    pub auditor: ElGamalKeypair,
    pub withdraw_withheld: ElGamalKeypair,
}

impl Parties {
    pub fn new() -> Self {
        Self {
            source: ElGamalKeypair::new_rand(),
            aes: AeKey::new_rand(),
            destination: ElGamalKeypair::new_rand(),
            auditor: ElGamalKeypair::new_rand(),
            withdraw_withheld: ElGamalKeypair::new_rand(),
        }
    }
}

pub struct SourceAccount {
    pub balance: u64,
    pub available: ElGamalCiphertext,
    pub decryptable: AeCiphertext,
}

impl SourceAccount {
    pub fn new(p: &Parties, balance: u64) -> Self {
        Self {
            balance,
            available: p.source.pubkey().encrypt(balance),
            decryptable: p.aes.encrypt(balance),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FeeCase {
    pub name: &'static str,
    pub amount: u64,
    pub bps: u16,
    pub max_fee: u64,
}

/// Select the generator for claimed Δ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeBranch {
    Percentage,
    Cap,
}

/// Branch inside PercentageWithCap: fee < max proves equality of Δ;
/// otherwise fee == max (as selected by zk-sdk; here only to cover the branch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmaBranch {
    BelowMax,
    AtMax,
}

#[derive(Clone, Copy, Debug)]
pub struct FeeParams {
    pub raw_fee: u64,
    pub raw_delta: u64,
    pub fee: u64,
    pub claimed_delta: u64,
    pub net: u64,
    pub branch: FeeBranch,
    pub sigma: SigmaBranch,
}

/// proof-generation 0.7.0 rule: apply the cap only when `maximum_fee < raw_fee`,
/// in which case claimed Δ = 0; when raw == max, use the percentage branch and Δ = raw Δ.
pub fn fee_params(amount: u64, bps: u16, max_fee: u64) -> Option<FeeParams> {
    let (raw_fee, raw_delta) = calculate_fee(amount, bps)?;
    let (fee, claimed_delta, branch) = if max_fee < raw_fee {
        (max_fee, 0, FeeBranch::Cap)
    } else {
        (raw_fee, raw_delta, FeeBranch::Percentage)
    };
    let sigma = if fee < max_fee {
        SigmaBranch::BelowMax
    } else {
        SigmaBranch::AtMax
    };
    Some(FeeParams {
        raw_fee,
        raw_delta,
        fee,
        claimed_delta,
        net: amount.checked_sub(fee)?,
        branch,
        sigma,
    })
}

/// Copy of calculate_fee from proof-generation 0.7.0 (u128 division is variable-time,
/// as in the generator).
pub fn calculate_fee(amount: u64, bps: u16) -> Option<(u64, u64)> {
    let numerator = (amount as u128).checked_mul(bps as u128)?;
    let fee = numerator
        .checked_add(ONE_IN_BASIS_POINTS)?
        .checked_sub(1)?
        .checked_div(ONE_IN_BASIS_POINTS)?;
    let delta = fee
        .checked_mul(ONE_IN_BASIS_POINTS)?
        .checked_sub(numerator)?;
    Some((fee as u64, delta as u64))
}

/// Raw fee at 25 bps for 1,234,567 is 3,087; raw Δ is 5,825.
pub fn fee_cases() -> Vec<FeeCase> {
    const A: u64 = 1_234_567;
    vec![
        FeeCase {
            name: "percentage",
            amount: A,
            bps: 25,
            max_fee: 10_000,
        },
        FeeCase {
            name: "raw_eq_max",
            amount: A,
            bps: 25,
            max_fee: 3_087,
        },
        FeeCase {
            name: "cap",
            amount: A,
            bps: 25,
            max_fee: 3_086,
        },
        FeeCase {
            name: "cap_max_zero",
            amount: A,
            bps: 25,
            max_fee: 0,
        },
        FeeCase {
            name: "zero_rate",
            amount: A,
            bps: 0,
            max_fee: 10_000,
        },
        FeeCase {
            name: "zero_rate_max_zero",
            amount: A,
            bps: 0,
            max_fee: 0,
        },
        FeeCase {
            name: "full_rate",
            amount: A,
            bps: 10_000,
            max_fee: u64::MAX,
        },
        FeeCase {
            name: "max_amount",
            amount: (1 << 48) - 1,
            bps: 25,
            max_fee: u64::MAX,
        },
    ]
}

/// BP++ witness: commitment bytes copied directly from BatchedRangeProofContext,
/// which are the bytes checked by the extractor.
#[derive(Clone)]
pub struct RangeWitness {
    pub commitments: Vec<[u8; 32]>,
    pub values: Vec<u64>,
    pub openings: Vec<Scalar>,
    pub widths: Vec<usize>,
}

impl RangeWitness {
    fn from_context<C: Pod>(
        ctx_commitments: &[C],
        values: &[u64],
        openings: &[&PedersenOpening],
        widths: &[usize],
    ) -> Self {
        let n = widths.len();
        assert!(values.len() == n && openings.len() == n && ctx_commitments.len() >= n);
        Self {
            commitments: ctx_commitments[..n]
                .iter()
                .map(|c| bytes_of(c).try_into().expect("32 bytes"))
                .collect(),
            values: values.to_vec(),
            openings: openings.iter().map(|o| *o.get_scalar()).collect(),
            widths: widths.to_vec(),
        }
    }
}

pub struct PlainFixture {
    pub amount: u64,
    pub equality: CiphertextCommitmentEqualityProofData,
    pub validity3: BatchedGroupedCiphertext3HandlesValidityProofData,
    pub range: BatchedRangeProofU128Data,
    pub auditor_lo: PodElGamalCiphertext,
    pub auditor_hi: PodElGamalCiphertext,
    pub new_decryptable: PodAeCiphertext,
    pub witness: RangeWitness,
}

pub struct FeeFixture {
    pub case: FeeCase,
    pub params: FeeParams,
    pub equality: CiphertextCommitmentEqualityProofData,
    pub validity3: BatchedGroupedCiphertext3HandlesValidityProofData,
    pub percentage: PercentageWithCapProofData,
    pub validity2: BatchedGroupedCiphertext2HandlesValidityProofData,
    pub range: BatchedRangeProofU256Data,
    pub auditor_lo: PodElGamalCiphertext,
    pub auditor_hi: PodElGamalCiphertext,
    pub new_decryptable: PodAeCiphertext,
    pub claimed_commitment: PedersenCommitment,
    pub claimed_opening: PedersenOpening,
    pub witness: RangeWitness,
}

struct Common {
    lo: u64,
    hi: u64,
    ct_lo: GroupedElGamalCiphertext<3>,
    ct_hi: GroupedElGamalCiphertext<3>,
    op_lo: PedersenOpening,
    op_hi: PedersenOpening,
    new_balance: u64,
    new_commitment: PedersenCommitment,
    new_opening: PedersenOpening,
    equality: CiphertextCommitmentEqualityProofData,
    validity3: BatchedGroupedCiphertext3HandlesValidityProofData,
    auditor_lo: PodElGamalCiphertext,
    auditor_hi: PodElGamalCiphertext,
    new_decryptable: PodAeCiphertext,
}

fn common(p: &Parties, src: &SourceAccount, amount: u64) -> Common {
    let (lo, hi) = try_split_u64(amount, TRANSFER_AMOUNT_LO_BITS).expect("amount < 2^48");
    let keys = [
        p.source.pubkey(),
        p.destination.pubkey(),
        p.auditor.pubkey(),
    ];
    let op_lo = PedersenOpening::new_rand();
    let op_hi = PedersenOpening::new_rand();
    let ct_lo = GroupedElGamal::encrypt_with(keys, lo, &op_lo);
    let ct_hi = GroupedElGamal::encrypt_with(keys, hi, &op_hi);

    let new_balance = src.balance.checked_sub(amount).expect("not enough funds");
    let (new_commitment, new_opening) = Pedersen::new(new_balance);
    let source_lo = ct_lo.to_elgamal_ciphertext(0).expect("handle 0");
    let source_hi = ct_hi.to_elgamal_ciphertext(0).expect("handle 0");
    let transferred =
        try_combine_lo_hi_ciphertexts(&source_lo, &source_hi, TRANSFER_AMOUNT_LO_BITS)
            .expect("combine");
    let new_ciphertext = &src.available - &transferred;

    let equality = build_ciphertext_commitment_equality_proof_data(
        &p.source,
        &new_ciphertext,
        &new_commitment,
        &new_opening,
        new_balance,
    )
    .expect("equality proof");
    let validity3 = build_batched_grouped_ciphertext_3_handles_validity_proof_data(
        p.source.pubkey(),
        p.destination.pubkey(),
        p.auditor.pubkey(),
        &ct_lo,
        &ct_hi,
        lo,
        hi,
        &op_lo,
        &op_hi,
    )
    .expect("validity3 proof");
    let auditor_lo = validity3
        .context_data()
        .grouped_ciphertext_lo
        .try_extract_ciphertext(2)
        .expect("auditor lo");
    let auditor_hi = validity3
        .context_data()
        .grouped_ciphertext_hi
        .try_extract_ciphertext(2)
        .expect("auditor hi");
    let new_decryptable: PodAeCiphertext = p.aes.encrypt(new_balance).into();

    Common {
        lo,
        hi,
        ct_lo,
        ct_hi,
        op_lo,
        op_hi,
        new_balance,
        new_commitment,
        new_opening,
        equality,
        validity3,
        auditor_lo,
        auditor_hi,
        new_decryptable,
    }
}

pub fn plain(p: &Parties, src: &SourceAccount, amount: u64) -> PlainFixture {
    let c = common(p, src, amount);
    let (pad_commitment, pad_opening) = Pedersen::new(0_u64);
    let range = build_batched_range_proof_u128_data(
        vec![
            &c.new_commitment,
            &c.ct_lo.commitment,
            &c.ct_hi.commitment,
            &pad_commitment,
        ],
        vec![c.new_balance, c.lo, c.hi, 0],
        vec![
            REMAINING_BALANCE_BIT_LENGTH,
            TRANSFER_AMOUNT_LO_BITS,
            TRANSFER_AMOUNT_HI_BITS,
            PADDING_BIT_LENGTH,
        ],
        vec![&c.new_opening, &c.op_lo, &c.op_hi, &pad_opening],
    )
    .expect("range u128 proof");
    let witness = RangeWitness::from_context(
        &range.context_data().commitments,
        &[c.new_balance, c.lo, c.hi, 0],
        &[&c.new_opening, &c.op_lo, &c.op_hi, &pad_opening],
        &PLAIN_WIDTHS,
    );
    PlainFixture {
        amount,
        equality: c.equality,
        validity3: c.validity3,
        range,
        auditor_lo: c.auditor_lo,
        auditor_hi: c.auditor_hi,
        new_decryptable: c.new_decryptable,
        witness,
    }
}

pub fn with_fee(p: &Parties, src: &SourceAccount, case: FeeCase) -> FeeFixture {
    let c = common(p, src, case.amount);
    let params = fee_params(case.amount, case.bps, case.max_fee).expect("fee params");

    let (fee_lo, fee_hi) = try_split_u64(params.fee, FEE_AMOUNT_LO_BITS).expect("fee < 2^48");
    let fee_keys = [p.destination.pubkey(), p.withdraw_withheld.pubkey()];
    let fee_op_lo = PedersenOpening::new_rand();
    let fee_op_hi = PedersenOpening::new_rand();
    let fee_ct_lo = GroupedElGamal::encrypt_with(fee_keys, fee_lo, &fee_op_lo);
    let fee_ct_hi = GroupedElGamal::encrypt_with(fee_keys, fee_hi, &fee_op_hi);

    let amount_commitment = try_combine_lo_hi_commitments(
        &c.ct_lo.commitment,
        &c.ct_hi.commitment,
        TRANSFER_AMOUNT_LO_BITS,
    )
    .expect("combine");
    let amount_opening =
        try_combine_lo_hi_openings(&c.op_lo, &c.op_hi, TRANSFER_AMOUNT_LO_BITS).expect("combine");
    let fee_commitment = try_combine_lo_hi_commitments(
        &fee_ct_lo.commitment,
        &fee_ct_hi.commitment,
        FEE_AMOUNT_LO_BITS,
    )
    .expect("combine");
    let fee_opening =
        try_combine_lo_hi_openings(&fee_op_lo, &fee_op_hi, FEE_AMOUNT_LO_BITS).expect("combine");

    let net_commitment = &amount_commitment - &fee_commitment;
    let net_opening = &amount_opening - &fee_opening;

    // Match the generator rule for claimed Δ (cap -> 0).
    let (claimed_commitment, claimed_opening) = Pedersen::new(params.claimed_delta);
    let (delta_commitment, delta_opening) = delta_commitment_and_opening(
        (&amount_commitment, &amount_opening),
        (&fee_commitment, &fee_opening),
        case.bps,
    );
    let percentage = build_percentage_with_cap_proof_data(
        &fee_commitment,
        &fee_opening,
        params.fee,
        &delta_commitment,
        &delta_opening,
        params.claimed_delta,
        &claimed_commitment,
        &claimed_opening,
        case.max_fee,
    )
    .expect("percentage-with-cap proof");

    let validity2 = build_batched_grouped_ciphertext_2_handles_validity_proof_data(
        p.destination.pubkey(),
        p.withdraw_withheld.pubkey(),
        &fee_ct_lo,
        &fee_ct_hi,
        fee_lo,
        fee_hi,
        &fee_op_lo,
        &fee_op_hi,
    )
    .expect("fee validity proof");

    let complement = MAX_FEE_BASIS_POINTS_SUB_ONE
        .checked_sub(params.claimed_delta)
        .expect("claimed Δ < 10^4");
    let max_sub_one = Pedersen::with(MAX_FEE_BASIS_POINTS_SUB_ONE, &PedersenOpening::default());
    let complement_commitment = &max_sub_one - &claimed_commitment;
    let complement_opening = PedersenOpening::default() - &claimed_opening;

    let values = [
        c.new_balance,
        c.lo,
        c.hi,
        params.claimed_delta,
        complement,
        fee_lo,
        fee_hi,
        params.net,
    ];
    let openings = [
        &c.new_opening,
        &c.op_lo,
        &c.op_hi,
        &claimed_opening,
        &complement_opening,
        &fee_op_lo,
        &fee_op_hi,
        &net_opening,
    ];
    let range = build_batched_range_proof_u256_data(
        vec![
            &c.new_commitment,
            &c.ct_lo.commitment,
            &c.ct_hi.commitment,
            &claimed_commitment,
            &complement_commitment,
            &fee_ct_lo.commitment,
            &fee_ct_hi.commitment,
            &net_commitment,
        ],
        values.to_vec(),
        FEE_WIDTHS.to_vec(),
        openings.to_vec(),
    )
    .expect("range u256 proof");
    let witness = RangeWitness::from_context(
        &range.context_data().commitments,
        &values,
        &openings,
        &FEE_WIDTHS,
    );

    FeeFixture {
        case,
        params,
        equality: c.equality,
        validity3: c.validity3,
        percentage,
        validity2,
        range,
        auditor_lo: c.auditor_lo,
        auditor_hi: c.auditor_hi,
        new_decryptable: c.new_decryptable,
        claimed_commitment,
        claimed_opening,
        witness,
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn delta_commitment_and_opening(
    (amount_commitment, amount_opening): (&PedersenCommitment, &PedersenOpening),
    (fee_commitment, fee_opening): (&PedersenCommitment, &PedersenOpening),
    bps: u16,
) -> (PedersenCommitment, PedersenOpening) {
    let rate = Scalar::from(bps);
    let one = Scalar::from(MAX_FEE_BASIS_POINTS);
    (
        fee_commitment * one - amount_commitment * rate,
        fee_opening * one - amount_opening * rate,
    )
}
