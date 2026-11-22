#!/usr/bin/env bash
# Token-2022 end-to-end checks for chunked-16, then one pass of the benchmark's
# lifted/chunked cases in Criterion test mode (same chunked16/src/lib.rs code).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
results="$root/e2e-results"
mkdir -p "$results"

# shellcheck source=scripts/upstream.sh
source "$root/scripts/upstream.sh"
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
fetch_fastcrypto

cd "$root/chunked16"
export CARGO_TARGET_DIR="$root/chunked16/target"
cargo test --locked --release -- --nocapture 2>&1 | tee "$results/chunked16-tests.log"
cp Cargo.lock "$results/Cargo.lock"

cd "$upstream/fastcrypto"
cargo bench --locked -p fastcrypto --features solana-pedersen-bases --bench bulletproofspp -- \
    --test '^BPPP verify/(lifted|chunked)/transfer(_with_fee)?$' 2>&1 | tee "$results/fastcrypto-bench-test.log"
