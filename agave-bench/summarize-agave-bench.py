#!/usr/bin/env python3
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

SCENARIOS = {"A": "U128", "B": "U256"}


def percentile(values, p):
    ranked = sorted(values)
    position = (len(ranked) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    return ranked[lower] + (ranked[upper] - ranked[lower]) * (position - lower)


def summarize(rows):
    print("# Agave instruction measurements\n")
    print("Ratios are current verifier time divided by chunked-16 verifier time.\n")
    print("## All machines\n")

    all_groups = defaultdict(list)
    cpu_groups = defaultdict(list)
    for row in rows:
        key = (row["scenario"], row["backend"])
        all_groups[key].append(row)
        if row["backend"] == "default":
            cpu_groups[(row["scenario"], row["cpu_model"])].append(row)
    print("| Scenario | Backend | Machines | Pairs | Median current, µs | Median chunked-16, µs | Median ratio | p5 ratio | Min ratio |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for (scenario, backend), group in sorted(all_groups.items()):
        runs = {r["run_id"] for r in group}
        assert len(runs) == 3
        ratios = [float(r["ratio"]) for r in group]
        old = statistics.median(int(r["old_ns"]) for r in group) / 1000
        new = statistics.median(int(r["new_ns"]) for r in group) / 1000
        print(f"| {SCENARIOS[scenario]} | {backend} | {len(runs)} | {len(group)} | {old:.2f} | {new:.2f} | {statistics.median(ratios):.3f} | {percentile(ratios, 0.05):.3f} | {min(ratios):.3f} |")
    print("\n## Default backend by scenario and CPU\n\n| Scenario | CPU model | Pairs | Median ratio | p5 ratio |")
    print("|---|---|---:|---:|---:|")
    for (scenario, cpu), group in sorted(cpu_groups.items()):
        ratios = [float(r["ratio"]) for r in group]
        print(f"| {SCENARIOS[scenario]} | {cpu} | {len(group)} | {statistics.median(ratios):.3f} | {percentile(ratios, 0.05):.3f} |")


if __name__ == "__main__":
    with Path(__file__).with_name("results.csv").open(encoding="utf-8", newline="") as file:
        summarize(list(csv.DictReader(file)))
