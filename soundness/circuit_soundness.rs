//! Soundness checks for the two bug classes reported against distributed-lab/bp-pp:
//! #5 (reciprocal challenge drawn before the digit commitments) and
//! #6 (a C_S slot reaching the T^3 coefficient of f(T)).
//! Included into circuit.rs by scripts/soundness.sh; not part of upstream.

use super::*;
use crate::bulletproofspp::constraints::value_row;
use std::array::from_fn;

fn any_witness(params: &CircuitParams, values: &[u64]) -> Witness {
    let mut rng = rand::thread_rng();
    let blindings: Vec<S> = values.iter().map(|_| S::rand(&mut rng)).collect();
    Witness::new(params, &mut rng, values, &blindings)
}

/// Run the prover on `witness` with honest reciprocals, then verify.
fn prove_and_verify(range: Range, witness: &Witness) -> FastCryptoResult<()> {
    let params = CircuitParams::new(range, witness.values.len()).unwrap();
    let gens = Generators::new(params.nm).unwrap();
    let mut t = BpppTranscript::new(b"test");
    let (proof, v) = prove_witness(&mut t, &gens, &params, witness, &|alpha| {
        reciprocals(&params, &witness.n_l, alpha)
    })
    .unwrap();
    let mut t = BpppTranscript::new(b"test");
    verify(&mut t, &gens, &params, &proof, &v)
}

/// bp-pp #5: a prover that knows alpha before committing to digits and
/// multiplicities balances the set-membership row for a digit outside the table.
/// `alpha_guess` is the challenge a verifier would draw if alpha came right after V.
/// The control shows the witness satisfies every row at `alpha_guess`; the proof
/// must still be rejected, because alpha is drawn after C_L and C_O.
#[test]
fn soundness_alpha_is_drawn_after_digit_commitments() {
    let params = CircuitParams::new(Range::Bits16, 1).unwrap();
    let gens = Generators::new(params.nm).unwrap();
    let mut cheat = any_witness(&params, &[0]);
    cheat.values = vec![S::from(1u64 << 16)];
    cheat.n_l[3] = S::from(16u64); // 16 * 16^3 = 2^16; digit 16 is not in the table

    let v = cheat.input_commitments(&gens).unwrap();
    let mut t = BpppTranscript::new(b"test");
    t.domain_sep(b"bppp_circuit");
    t.append_commits(b"V", &v);
    let alpha_guess = t.challenge_scalar(b"alpha");

    // 1/(a+16) + m_1/(a(a+1)) = 1/a, so m_1 = 16(a+1)/(a+16).
    let sixteen = S::from(16u64);
    let m_1 = sixteen * (alpha_guess + one()) * (alpha_guess + sixteen).inverse().unwrap();
    cheat.n_o = vec![S::zero(); params.nm];
    cheat.n_o[0] = m_1;

    // Control: at alpha_guess every row holds, so the attack is real.
    let mut rng = rand::thread_rng();
    let [mu, lambda] = from_fn(|_| S::rand(&mut rng));
    let n_r = reciprocals(&params, &cheat.n_l, alpha_guess).unwrap();
    let row = value_row(
        &params,
        alpha_guess,
        mu,
        lambda,
        &cheat.values,
        &cheat.n_l,
        &n_r,
        &cheat.n_o,
    );
    assert_eq!(row, S::zero(), "cheating witness invalid at alpha_guess: test is vacuous");

    assert!(prove_and_verify(Range::Bits16, &cheat).is_err());
}

/// bp-pp #6, generalized: nothing the prover picks after beta and delta (the C_S
/// opening: r_S[0], every H slot including l_S, and the mask n_S) may change the
/// T^3 coefficient of f(T), which carries the circuit check.
#[test]
fn soundness_c_s_cannot_reach_the_value_row() {
    let mut rng = rand::thread_rng();
    for (range, m) in [(Range::Bits64, 1), (Range::Bits16, 8), (Range::Bits16, 16)] {
        let params = CircuitParams::new(range, m).unwrap();
        let [alpha, mu, lambda, beta, delta] = from_fn(|_| S::rand(&mut rng));
        let mut random = |len: usize| (0..len).map(|_| S::rand(&mut rng)).collect::<Vec<S>>();
        let constraints = Constraints::new(&params, alpha, mu, lambda).unwrap();
        let delta_inv = delta.inverse().unwrap();
        let c = c(&constraints, beta);

        // Any witness: soundness must not depend on the prover being honest.
        let mut w = any_witness(&params, &vec![0; m]);
        w.values = random(m);
        w.n_l = random(params.nm);
        w.n_o = random(params.nm);
        w.n_s = vec![S::zero(); params.nm];
        let n_r = random(params.nm);
        let t3 = |w: &Witness, r_s: Option<(S, Vec<S>)>| {
            let opening =
                opening_without_r_s(&params, &constraints, w, n_r.clone(), delta, delta_inv);
            let opening = match r_s {
                Some((r_s0, h)) => opening.with_r_s(r_s0, h),
                None => opening,
            };
            f(&opening, &c, &constraints.norm_weights).coeff(3)
        };
        let base = t3(&w, None);

        w.n_s = random(params.nm);
        assert_eq!(t3(&w, None), base, "n_S reaches T^3 for {}x{m}", range.bits());

        let r_s0 = random(1)[0];
        let only_r_s0 = Some((r_s0, vec![S::zero(); H_LEN]));
        assert_eq!(t3(&w, only_r_s0), base, "r_S[0] reaches T^3 for {}x{m}", range.bits());

        for slot in 0..H_LEN {
            let mut h = vec![S::zero(); H_LEN];
            h[slot] = random(1)[0];
            let got = t3(&w, Some((S::zero(), h)));
            assert_eq!(got, base, "C_S slot {slot} reaches T^3 for {}x{m}", range.bits());
        }
    }
}
