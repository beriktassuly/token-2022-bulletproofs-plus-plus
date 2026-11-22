#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
results="$root/benchmark-results"
mkdir -p "$results"

# shellcheck source=scripts/upstream.sh
source "$root/scripts/upstream.sh"
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal

fetch_zk_elgamal_proof
fetch_fastcrypto

export CARGO_TARGET_DIR="$work_dir/target" CARGO_PROFILE_BENCH_LTO=thin
export RUSTFLAGS='-C target-cpu=x86-64-v3'
cpu=$(awk '/^Cpus_allowed_list:/ { split($2, cpus, /[-,]/); print cpus[1] }' /proc/self/status)
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="taskset -c $cpu"

{
    lscpu
    rustc --version --verbose
    printf 'Benchmark affinity: CPU %s\n' "$cpu"
    printf 'Rust flags: %s\n' "$RUSTFLAGS"
} | tee "$results/environment.txt"

cd "$upstream/zk-elgamal-proof"
cargo test --locked --release -p solana-zk-sdk --test batched_range_proof_inputs 2>&1 | tee "$results/zk-sdk-tests.log"

bench_solana() {
    cd "$upstream/zk-elgamal-proof"
    cargo bench --locked -p solana-zk-sdk --bench range_proof -- \
        --warm-up-time 1 --measurement-time 3 --sample-size 25 --noplot 2>&1 | tee "$results/solana-$1.log"
}

bench_fastcrypto() {
    cd "$upstream/fastcrypto"
    cargo bench --locked -p fastcrypto --features solana-pedersen-bases --bench bulletproofspp -- \
        '^(BP|BPPP) verify/(16-bit/(1|4|8)|32-bit/(1|2|8)|64-bit/(1|2)|(lifted|chunked)/transfer(_with_fee)?)$' \
        --sample-size 25 --noplot 2>&1 | tee "$results/fastcrypto-$1.log"
}

bench_solana first
bench_fastcrypto first
solana_fixture=$(grep '^Solana Pedersen fixture: ' "$results/solana-first.log")
fastcrypto_fixture=$(grep '^Solana Pedersen fixture: ' "$results/fastcrypto-first.log")
if [[ "$solana_fixture" != "$fastcrypto_fixture" ]]; then
    printf 'Pedersen commitment differs between zk-sdk and fastcrypto\n' >&2
    exit 1
fi
printf 'zk-sdk and fastcrypto Pedersen fixtures match.\n'
bench_fastcrypto second
bench_solana second
