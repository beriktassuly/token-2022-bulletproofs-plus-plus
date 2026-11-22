//! Token-2022 end-to-end checks for chunked-16.
//!
//! zk-sdk 8.1.0 builds transfers with and without fees, the Token-2022 proof extractor
//! 0.7.0 checks them with its own context types, and chunked-16 runs on the exact
//! commitment bytes the extractor accepted. `token2022_chunked16` is the code the paired
//! Criterion benchmark measures as `BPPP verify/chunked/*`.

mod common;

use {
    common::{
        extract::{
            extract_fee, extract_plain, verify_range_zk_fee, verify_range_zk_plain,
            verify_sigma_fee, verify_sigma_plain,
        },
        fixtures::{
            fee_cases, fee_params, plain, with_fee, FeeBranch, Parties, RangeWitness, SigmaBranch,
            SourceAccount,
        },
        sdk_tx,
    },
    curve25519_dalek::scalar::Scalar,
    fastcrypto::{
        groups::ristretto255::RistrettoScalar,
        pedersen::{Blinding, PedersenCommitment},
        serde_helpers::ToFromByteArray,
    },
    solana_zk_sdk::encryption::pedersen::{Pedersen, PedersenOpening},
    t22zk::proof_data::ZkProofData,
    token2022_chunked16::{self as chunked16, ChunkedProof},
};

const DST: &[u8] = b"token-2022/chunked-16";
const SOURCE_BALANCE: u64 = 1 << 49;
const PLAIN_AMOUNT: u64 = 1_234_567;

// Control values from the SDK smoke run: real SDK instructions, v1 config with a
// 1,000,000 CU limit, signatures included.
const TX_PLAIN_INLINE: usize = 2_390;
const TX_PLAIN_CONTEXT_STATE: usize = 2_884;
const TX_FEE_INLINE: usize = 3_242;
const TX_FEE_CONTEXT_STATE: usize = 4_066;
// Control value from the paired benchmark: proof plus auxiliary commitments, with fee.
const CHUNKED_FEE_BYTES: usize = 800;

fn declared_widths(witness: &RangeWitness) -> Vec<u32> {
    witness.widths.iter().map(|&width| width as u32).collect()
}

fn blindings(witness: &RangeWitness) -> Vec<Blinding> {
    witness
        .openings
        .iter()
        .map(|opening| {
            Blinding(
                RistrettoScalar::from_byte_array(&opening.to_bytes()).expect("canonical opening"),
            )
        })
        .collect()
}

fn prove(witness: &RangeWitness, widths: &[u32]) -> ChunkedProof {
    chunked16::prove(
        &witness.values,
        &blindings(witness),
        widths,
        DST,
        &mut rand::thread_rng(),
    )
    .expect("chunked-16 prove")
}

fn context_bytes<C: bytemuck::Pod>(commitments: &[C], n: usize) -> Vec<[u8; 32]> {
    commitments[..n]
        .iter()
        .map(|c| {
            bytemuck::bytes_of(c)
                .try_into()
                .expect("32-byte commitment")
        })
        .collect()
}

/// Proves and verifies on the extractor-checked bytes; rejects a reordering and a foreign DST.
fn check_chunked(name: &str, witness: &RangeWitness, context: &[[u8; 32]]) -> ChunkedProof {
    assert_eq!(
        witness.commitments, context,
        "{name}: witness differs from the extractor context"
    );
    let declared = declared_widths(witness);
    let proof = prove(witness, &declared);
    chunked16::verify(context, &declared, &proof, DST)
        .unwrap_or_else(|e| panic!("{name}: chunked-16 rejected the extractor commitments: {e:?}"));
    let mut swapped = context.to_vec();
    swapped.swap(1, 2);
    assert!(
        chunked16::verify(&swapped, &declared, &proof, DST).is_err(),
        "{name}: swapped commitments accepted"
    );
    assert!(
        chunked16::verify(context, &declared, &proof, b"other/dst").is_err(),
        "{name}: foreign DST accepted"
    );
    proof
}

#[test]
fn pedersen_bases_match_zk_sdk() {
    let fc = PedersenCommitment::new(
        &RistrettoScalar::from(42u64),
        &Blinding(RistrettoScalar::from(17u64)),
    );
    let solana = Pedersen::with(42u64, &PedersenOpening::new(Scalar::from(17u64)));
    assert_eq!(fc.0.to_byte_array(), solana.to_bytes());
}

#[test]
fn fee_rule_matches_generator_0_7_0() {
    use {FeeBranch::*, SigmaBranch::*};
    let expected = [
        ("percentage", Percentage, BelowMax, 3_087, 5_825),
        ("raw_eq_max", Percentage, AtMax, 3_087, 5_825),
        ("cap", Cap, AtMax, 3_086, 0),
        ("cap_max_zero", Cap, AtMax, 0, 0),
        ("zero_rate", Percentage, BelowMax, 0, 0),
        ("zero_rate_max_zero", Percentage, AtMax, 0, 0),
        ("full_rate", Percentage, BelowMax, 1_234_567, 0),
        ("max_amount", Percentage, BelowMax, 703_687_441_777, 3_625),
    ];
    let cases = fee_cases();
    assert_eq!(cases.len(), expected.len());
    for (case, (name, branch, sigma, fee, claimed)) in cases.iter().zip(expected) {
        assert_eq!(case.name, name);
        let p = fee_params(case.amount, case.bps, case.max_fee).unwrap();
        assert_eq!(
            (p.branch, p.sigma, p.fee, p.claimed_delta),
            (branch, sigma, fee, claimed),
            "{name}"
        );
    }
}

#[test]
fn sdk_control_nine_scenarios() {
    let p = Parties::new();
    let src = SourceAccount::new(&p, SOURCE_BALANCE);

    let pl = plain(&p, &src, PLAIN_AMOUNT);
    verify_sigma_plain(&pl).unwrap();
    verify_range_zk_plain(&pl).unwrap();
    assert!(extract_plain(&pl).is_ok());
    let inline = sdk_tx::plain_inline(&pl, None);
    let context = sdk_tx::plain_context_state(&pl, None);
    println!(
        "plain: TX v1 inline {} B, context-state {} B",
        inline.transaction, context.transaction
    );
    assert_eq!(
        (inline.transaction, context.transaction),
        (TX_PLAIN_INLINE, TX_PLAIN_CONTEXT_STATE)
    );

    for case in fee_cases() {
        let fx = with_fee(&p, &src, case);
        verify_sigma_fee(&fx).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        verify_range_zk_fee(&fx).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert!(
            extract_fee(&fx, case.bps, case.max_fee).is_ok(),
            "{}",
            case.name
        );
        assert!(
            extract_fee(&fx, case.bps ^ 1, case.max_fee).is_err(),
            "{}: wrong rate accepted",
            case.name
        );
        assert!(
            extract_fee(&fx, case.bps, case.max_fee ^ 1).is_err(),
            "{}: wrong cap accepted",
            case.name
        );
        if fx.params.branch == FeeBranch::Cap {
            assert_eq!(fx.params.claimed_delta, 0, "{}", case.name);
        }
        assert_eq!(
            fx.claimed_commitment,
            Pedersen::with(fx.params.claimed_delta, &fx.claimed_opening),
            "{}",
            case.name
        );
        let inline = sdk_tx::fee_inline(&fx, None);
        let context = sdk_tx::fee_context_state(&fx, None);
        println!(
            "{}: TX v1 inline {} B, context-state {} B",
            case.name, inline.transaction, context.transaction
        );
        assert_eq!(
            (inline.transaction, context.transaction),
            (TX_FEE_INLINE, TX_FEE_CONTEXT_STATE),
            "{}",
            case.name
        );
        assert!(context.transaction <= sdk_tx::PACKET_V1, "{}", case.name);
    }
}

#[test]
fn chunked16_on_extractor_accepted_commitments() {
    let p = Parties::new();
    let src = SourceAccount::new(&p, SOURCE_BALANCE);

    let pl = plain(&p, &src, PLAIN_AMOUNT);
    assert!(extract_plain(&pl).is_ok());
    let context = context_bytes(
        &pl.range.context_data().commitments,
        pl.witness.widths.len(),
    );
    let proof = check_chunked("plain", &pl.witness, &context);
    println!(
        "plain: chunked-16 {} proof bytes + {} auxiliary bytes",
        proof.proof_bytes(),
        proof.auxiliary_bytes()
    );

    for case in fee_cases() {
        let fx = with_fee(&p, &src, case);
        assert!(
            extract_fee(&fx, case.bps, case.max_fee).is_ok(),
            "{}",
            case.name
        );
        let context = context_bytes(
            &fx.range.context_data().commitments,
            fx.witness.widths.len(),
        );
        let proof = check_chunked(case.name, &fx.witness, &context);
        assert_eq!(
            proof.proof_bytes() + proof.auxiliary_bytes(),
            CHUNKED_FEE_BYTES,
            "{}",
            case.name
        );

        // A proof made for a 64-bit delta slot carries three extra chunks; it must not
        // verify against the declared 16-bit slot.
        let declared = declared_widths(&fx.witness);
        let mut widened = declared.clone();
        widened[3] = 64;
        let wide = prove(&fx.witness, &widened);
        assert!(
            chunked16::verify(&context, &widened, &wide, DST).is_ok(),
            "{}",
            case.name
        );
        assert!(
            chunked16::verify(&context, &declared, &wide, DST).is_err(),
            "{}",
            case.name
        );
    }
}
