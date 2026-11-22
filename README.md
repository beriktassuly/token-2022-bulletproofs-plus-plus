# Token-2022 Range Proof Benchmarks

Can Bulletproofs++ reduce CPU time for Token-2022 confidential-transfer range-proof verification? This repository compares Solana's current Bulletproofs verifier with an experimental BP++ construction at Token-2022 range widths.

**Status:** research prototype. No validator or Token-2022 runtime change is included. The prototype is not production-ready.

## Verification results

Proof verification only, on one GitHub-hosted Ubuntu 24.04 runner. The workflow ran two paired cycles on the same runner: zk-sdk, BP++, BP++, zk-sdk. Values below are Criterion estimates; the full intervals are in the raw logs.

| Scenario | Pair 1: zk-sdk -> chunked-16 | Change | Pair 2: zk-sdk -> chunked-16 | Change |
|---|---:|---:|---:|---:|
| Transfer without fee (U128) | 1.3584 -> 0.4849 ms | -64.3% (2.80x) | 1.2579 -> 0.4676 ms | -62.8% (2.69x) |
| Transfer with fee (U256) | 2.2590 -> 0.7589 ms | -66.4% (2.98x) | 2.1076 -> 0.7288 ms | -65.4% (2.89x) |

Runner details, compiler version, flags, and raw Criterion output are in results/2026-11-22/benchmark/. Runner hardware can vary; compare paired measurements from one run.

~~~mermaid
xychart-beta
    title "Range proof verification time (Criterion estimate, ms)"
    x-axis ["No fee, zk-sdk", "No fee, chunked-16", "Fee, zk-sdk", "Fee, chunked-16"]
    y-axis "ms" 0 --> 2.5
    bar [1.3584, 0.4849, 2.2590, 0.7589]
~~~

## Proof and transaction sizes

| Transfer | Current zk-sdk proof | BP++ lifted | BP++ chunked-16 |
|---|---:|---:|---:|
| Without fee | 736 B | 608 B | 480 B proof + 128 B commitments = 608 B |
| With fee | 800 B | 672 B | 544 B proof + 256 B commitments = 800 B |

The end-to-end fixture builds current-format TX v1 transactions with the real SDK instruction builders. These are not measurements of a deployed chunked-16 instruction:

| Transfer | Proofs inline | Proofs in context-state accounts |
|---|---:|---:|
| Without fee | 2,390 B | 2,884 B |
| With fee | 3,242 B | 4,066 B |

The TX v1 packet limit is 4,096 B. The harness does not execute a validator transaction or charge a new CU price.

## Checks

The CI end-to-end suite checks Token-2022 proof extraction, the Token-2022 range widths, fee-proof scenarios, commitment compatibility between zk-sdk and fastcrypto, and rejection of altered commitments. It passed 4 unit tests and 4 integration tests. Logs are in results/2026-11-22/e2e/.

Chunked-16 proves 16-bit chunks and includes auxiliary commitments for the high chunks. Its verifier is shared by the local module tests and fastcrypto benchmark through chunked16/src/lib.rs.

## Limitations

- The CPU result does not translate directly into on-chain CU savings. The ZK ElGamal proof program charges fixed CU tariffs; this repository does not change those tariffs or add a deployable proof instruction.
- BP++ in fastcrypto is experimental. Chunked-16 has not received a formal proof or an independent audit.
- No real validator execution, SBF verification benchmark, or production deployment is included.

## Reproduce

On Linux x86-64 with AVX2 and BMI2:

~~~bash
bash scripts/e2e.sh
bash scripts/bench.sh
~~~

The scripts use Rust 1.98.0, pin the upstream sources, and write logs to e2e-results/ and benchmark-results/.

| Upstream | Pinned revision |
|---|---|
| solana-program/zk-elgamal-proof | caebf47f7af8d59b24280d67c8728272d753cd46 |
| MystenLabs/fastcrypto | 2a17486674e2173e5ee4ce3f790850f0e45c222c |

## References

- Eagen, Kanjalkar, Ruffing, and Nick, Bulletproofs++: Next Generation Confidential Transactions via Reciprocal Set Membership Arguments, Eurocrypt 2024, ePrint 2022/510.
- MystenLabs/fastcrypto.
- Solana ZK ElGamal proof program and zk-sdk.
- Token-2022 confidential transfer proof extraction.

## License

Apache-2.0. See LICENSE.