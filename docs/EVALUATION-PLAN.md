# Evaluation Plan — Corpus, Metrics, Calibration Protocol

This plan turns the research contribution into something a program committee
can scrutinise: a **reproducible corpus**, **explicit metrics**, and a
**calibration protocol** that converts the composition engine's seed
probabilities into *measured* ones. It is the specification for the code in
`evaluation/`. Every step is automatable; nothing here requires manual
judgement at run time.

---

## 1. Corpus specification

A corpus is a JSON manifest validated against `evaluation/corpus.schema.json`.
Each target declares:

| Field | Meaning |
|-------|---------|
| `id` | Stable identifier (used in reports). |
| `distro` / `release` / `kernel` | Environment labels for slicing results. |
| `provisioner` | `multipass` \| `docker` \| `ssh`. How the target is brought up. |
| `image` / `host` | Provisioner-specific target (VM image, image ref, or SSH host). |
| `setup` / `teardown` | Shell scripts that plant / remove the escalation state. |
| `ground_truth.reachable_tokens` | Capability tokens that *should* be derivable. |
| `ground_truth.expected_paths` | Path `technique` labels (e.g. `"WRITE_SUDOERS -> root"`) that must appear. |
| `ground_truth.expected_findings` | Finding `id`s that must appear (signature-level check). |
| `verify_steps[]` | Per-step exploit-verification commands used for calibration. |
| `verify_paths[]` | Per-path end-to-end exploit-verification commands. |
| `baselines[]` | Optional baseline tools to run for comparison. |

The corpus is **versioned** (`schema` field) and **append-only in practice**:
adding targets is configuration, not code. `corpus.example.json` seeds it with
the existing `testbeds/` and is the reference the harness runs by default.

**Scale target for a credible submission:** ≥ 40 targets spanning ≥ 4 distros
and ≥ 3 kernel majors, including CTF/Docker/CVE environments, not only the
planted testbeds. The framework imposes no upper bound.

---

## 2. Metrics

All metrics are computed by `evaluation/metrics.py` from collected JSON and
emitted as `results/metrics.json`. Definitions:

### 2.1 Detection (signature-level)
For each target, parse Z-Privesc `findings[]`. A finding `id` in
`expected_findings` is a **true positive (TP)**; a reported HIGH/CRITICAL
finding *not* in any target's expected set on a *clean* baseline is a
**false positive (FP)**.

- `recall = TP / (TP + FN)`
- `precision = TP / (TP + FP)`
- `false_negative_rate = FN / (TP + FN)`

### 2.2 Composition (path-level)
Parse `escalation_paths[]`. A reported `technique` label in
`expected_paths` is a path-TP; an expected path absent is a path-FN; a
reported path *not* in `expected_paths` while the target is *not* expected to
be root-reachable is a path-FP.

- `path_recall`, `path_precision`, `path_false_positive_rate`

### 2.3 Calibration (confidence-level) — the novel metric
Aggregate every reported step as an observation `(p, y)` where `p` is the
step `reliability` and `y ∈ {0,1}` is the verified exploit outcome from
`verify_steps`/`verify_paths`.

- **Brier score** = meanᵢ (pᵢ − yᵢ)². Lower is better; 0 = perfect.
- **Reliability bins**: 10 equal-width bins of `p`; per bin report
  `(mean p, observed frequency, count)`. A calibrated model has
  `observed ≈ mean p` in every bin.
- **Negative log-likelihood** of the Bernoulli product model, for information
  criteria.

### 2.4 Cost
- `scan_time_seconds` per target (wall clock of `z_privesc --all --json`).

All metrics are reported **per target**, **per distro slice**, and
**aggregated**, with sample sizes so variance is visible. No single-number
headline without its n.

---

## 3. Calibration protocol

Goal: replace the seed `p` values in `src/compose.c` `RULES[]` with values
fitted to observed exploit success.

**Step 1 — Collect outcomes.** The harness runs, for every target, the
`verify_steps[]` and `verify_paths[]` commands and records `y ∈ {0,1}` per
step/technique.

**Step 2 — Per-rule MLE.** Group outcomes by step `technique` string (which
uniquely identifies a `RULES[]` entry). For rule `r` with `s` successes in
`n` trials, use **Laplace-smoothed** estimation:

```
p_r = (s + α) / (n + 2α),   α = 1
```

Laplace smoothing avoids zero/one over-confidence on small `n` and is the
conservative, defensible choice for security base rates.

**Step 3 — Emit calibrated table.** `evaluation/calibrate.py` writes:
- `results/calibration.json` — per-rule `s`, `n`, `p`, Brier before/after,
  reliability bins.
- `results/RULES.calibrated.h` — a drop-in C initializer for `RULES[]` using
  the fitted `p` (and a `RULES.seed.h` retained for reproducibility).

**Step 4 — Re-validate.** Re-run the corpus with the calibrated binary; the
Brier score and reliability-bin deviation must *improve* or the calibration
is rejected (the seed values were already better — keep the better set).

**Determinism:** outcomes are boolean and aggregated by exact string key, so
calibration is fully reproducible given the same corpus and `verify` commands.

---

## 4. Baseline comparison

For each target where a baseline is declared (`linpeas`, `lynis`, …), the
harness runs it and records its raw output. Detection is measured by the same
signature-substring method used in `scripts/ground_truth.sh`, but now
**explicitly labelled as a heuristic** and reported alongside Z-Privesc's
structured detection. Head-to-head tables: recall, precision, FPR, scan time,
per tool, on the identical corpus.

---

## 5. Reporting

`evaluation/report.py` consumes `results/metrics.json` and
`results/calibration.json` and emits:

- `results/report.md` — Markdown with per-target table, aggregate table,
  calibration table, reliability bins, and Brier before/after.
- `results/report.json` — machine-readable mirror for archival / plotting.

---

## 6. Reproducibility contract

- The manifest is the single source of truth; re-running the harness on the
  same manifest and corpus yields identical metrics (no randomness in Z-Privesc
  or the metrics code).
- `verify` commands must be idempotent and exit `0` on success, non-zero on
  failure, so `y` is unambiguous.
- Binaries under test are pinned by `build_id` (already emitted in the audit
  JSON), recorded in the report.
- Secrets / exploit payloads live only in `testbeds/` setup scripts, never in
  the corpus or reports.
