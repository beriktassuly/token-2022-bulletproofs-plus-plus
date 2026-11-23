# Agave instruction measurements

Ratios are current verifier time divided by chunked-16 verifier time.

## All machines

| Scenario | Backend | Machines | Pairs | Median current, µs | Median chunked-16, µs | Median ratio | p5 ratio | Min ratio |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| U128 | default | 3 | 150 | 1708.34 | 819.05 | 2.235 | 2.040 | 1.981 |
| U128 | serial | 3 | 150 | 1863.01 | 648.46 | 2.902 | 2.789 | 2.308 |
| U256 | default | 3 | 150 | 2820.89 | 1377.91 | 2.357 | 1.827 | 1.760 |
| U256 | serial | 3 | 150 | 3099.05 | 1017.37 | 3.075 | 3.007 | 2.886 |

## Default backend by scenario and CPU

| Scenario | CPU model | Pairs | Median ratio | p5 ratio |
|---|---|---:|---:|---:|
| U128 | AMD EPYC 7763 64-Core Processor | 50 | 2.254 | 2.148 |
| U128 | AMD EPYC 9V74 80-Core Processor | 50 | 2.235 | 2.139 |
| U128 | Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz | 50 | 2.065 | 2.033 |
| U256 | AMD EPYC 7763 64-Core Processor | 50 | 2.406 | 2.342 |
| U256 | AMD EPYC 9V74 80-Core Processor | 50 | 2.362 | 2.330 |
| U256 | Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz | 50 | 1.903 | 1.772 |
