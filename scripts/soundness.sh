#!/usr/bin/env bash
# Bulletproofs++ soundness checks for the bug classes reported against
# distributed-lab/bp-pp (#5: reciprocal challenge before the digit commitments,
# #6: a C_S slot reaching the T^3 row). Runs extra circuit tests on a copy of the
# pinned, patched fastcrypto, then shows each test fails once the bug is put back.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
results="$root/soundness-results"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$results"
: > "$results/summary.txt"

# shellcheck source=scripts/upstream.sh
source "$root/scripts/upstream.sh"
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
fetch_fastcrypto

export CARGO_TARGET_DIR="$root/.upstream/soundness-target"
circuit=fastcrypto/src/bulletproofspp/circuit.rs

# The pinned checkout stays untouched (upstream.sh checks it against the patch).
original="$work/original"
cp -r "$upstream/fastcrypto" "$original"
cp "$root/soundness/circuit_soundness.rs" "$original/fastcrypto/src/bulletproofspp/"
printf '\n#[cfg(test)]\n#[path = "circuit_soundness.rs"]\nmod soundness_tests;\n' \
    >> "$original/$circuit"

fc_test() {
    local dir=$1 log=$2
    shift 2
    (cd "$dir" && cargo test --locked -p fastcrypto --features experimental --lib "$@") \
        2>&1 | tee "$log"
}

# 1. Every BP++ test, old and new, passes on the pinned code.
fc_test "$original" "$results/original.log" -- bulletproofspp::

# 2. Each bug put back must make the named tests fail.
mutant() {
    local name=$1 perl_script=$2
    shift 2
    local dir="$work/$name"
    cp -r "$original" "$dir"
    perl -0pi -e "$perl_script" "$dir/$circuit"
    diff -u "$original/$circuit" "$dir/$circuit" > "$results/$name.diff" || true
    fc_test "$dir" "$results/$name-build.log" --no-run
    local filter
    for filter in "$@"; do
        if fc_test "$dir" "$results/$name-$filter.log" -- "$filter"; then
            printf 'NOT DETECTED: %s still passes %s\n' "$name" "$filter" \
                | tee -a "$results/summary.txt" >&2
            exit 1
        fi
        printf 'detected: %s fails %s\n' "$name" "$filter" | tee -a "$results/summary.txt"
    done
}

# bp-pp #5: draw alpha before absorbing C_L and C_O, in both prover and verifier.
m5='s/(    transcript\.append_point\(b"C_L", &c_l\);\n    transcript\.append_point\(b"C_O", &c_o\);\n)((?:\n|    \/\/[^\n]*\n)*    let alpha = transcript\.challenge_scalar\(b"alpha"\);\n)/$2$1/ or die "prove: no match\n";
s/(    transcript\.append_point\(b"C_L", &proof\.c_l\);\n    transcript\.append_point\(b"C_O", &proof\.c_o\);\n)(    let alpha = transcript\.challenge_scalar\(b"alpha"\);\n)/$2$1/ or die "verify: no match\n";'

# bp-pp #6: put T^4 into c_r_hat, so one C_S slot lands on T^3.
m6='s/const CR_POWERS: \[i32; H_LEN - 1\] = \[-1, 1, 2, 3, 5, 6, 7\];/const CR_POWERS: [i32; H_LEN - 1] = [-1, 1, 2, 3, 4, 5, 6];/ or die "CR_POWERS: no match\n";'

mutant m5-alpha-before-digits "$m5" soundness_alpha_is_drawn_after_digit_commitments
mutant m6-t4-in-c_r "$m6" soundness_c_s_cannot_reach_the_value_row \
    test_out_of_range_value_cannot_be_proven

printf 'All mutations detected.\n' | tee -a "$results/summary.txt"
