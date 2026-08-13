# Evaluation Guide

How to reproduce Z-Privesc's evaluation results.

## Prerequisites

- Linux host (Kali, Ubuntu, or similar) with root access
- GCC, make, python3
- multipass (optional, for multi-distro verification)

## Quick Start

```bash
# Build
make -j$(nproc)

# Run test suite
make test

# Run full scan (all 17 probes)
sudo ./build/bin/z_privesc --all --json > results.json
```

## Expanded Corpus Evaluation

The expanded corpus contains **37 planted targets + 2 clean-host baselines**
(39 total). See `evaluation/corpus.expanded.json` for the full target list.

### Running the full evaluation

```bash
# Plant all testbeds
bash testbeds/expanded/plant.sh

# Run Z-Privesc
sudo ./build/bin/z_privesc --all --json > /tmp/eval.json

# Analyze results
python3 eval_results/analyze_expanded.py

# Clean up
bash testbeds/expanded/cleanup_all.sh
```

### Multi-distro verification

Two targets (kernel_hardening, process_root) require a non-WSL2 host
because WSL2 locks sysctls and kills background processes.

```bash
# On Ubuntu 22.04 multipass VM
multipass exec zp-2204 -- sudo /tmp/zp/build/bin/z_privesc --all --json
```

## Expected Results

| Metric | Value |
|--------|-------|
| Detection recall | 1.000 (37/37) |
| Detection precision | 1.000 (37/37) |
| Path recall | 0.943 (33/35) |
| Path precision | 0.971 (33/34) |
| Brier score (seed) | 0.109 |
| Observations | 353 |
| Clean-host findings | 47 per host |
| Mean scan time | 2.65 s (full `--all` scan) |

## Ground Truth

Each target in the corpus has:
- `setup.sh` — plants the misconfiguration
- `cleanup.sh` — removes it
- `ground_truth.expected_findings` — artifact signatures that must appear
- `ground_truth.root_reachable` — whether a root path is composable

Detection = planted artifact's unique signature appears in probe findings
with a `DETERMINISTIC` verdict.

## Calibration

Seed weights are defined in `src/compose.c` (`RULES[]` array). The
evaluation harness fits calibrated weights via Laplace-smoothed MLE
(`evaluation/calibrate.py`). Brier score measures calibration quality.

## Re-generating Benchmark Data

```bash
# From the project root, inside a multipass VM
bash scripts/bench_mp.sh
```

This writes JSON files into `benchmarks/data/` (build times, probe
timings, test results, environment info).
