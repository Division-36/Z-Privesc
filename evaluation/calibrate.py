#!/usr/bin/env python3
"""Z-Privesc confidence calibration.

Fits the composition engine's per-rule exploit-reliability weights `p` from
observed exploit outcomes collected by run_eval.sh, using Laplace-smoothed
maximum-likelihood estimation, and emits:

  <results>/calibration.json   : per-rule stats + overall calibration
  <results>/RULES.calibrated.h : drop-in C initializer for src/compose.c

The rule table below is an explicit mirror of `src/compose.c` `RULES[]`; the
two MUST stay in sync (token order, technique strings, result/pre tokens).

Input: <results>/<target_id>/outcomes.json entries shaped
       { "label": <rule tech string>, "p": <seed p>, "y": <0|1> }.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

# --------------------------------------------------------------------------
# Mirror of src/compose.c RULES[] — token order and tech strings must match.
# --------------------------------------------------------------------------
RULES_REF: List[Dict[str, object]] = [
    {"tech": "execute code as root",            "pre": "T_EXEC_AS_ROOT",    "result": "T_ROOT",          "seed": 0.97},
    {"tech": "append NOPASSWD to sudoers",      "pre": "T_WRITE_SUDOERS",   "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "hijack a root-run systemd unit",  "pre": "T_WRITE_SYSTEMD",   "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "hijack a root-run cron job",      "pre": "T_WRITE_CRON",      "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "LD_PRELOAD into root processes",   "pre": "T_INJECT_PRELOAD",  "result": "T_EXEC_AS_ROOT",  "seed": 0.90},
    {"tech": "plant trojan in writable PATH",   "pre": "T_WRITE_PATH_TROJAN","result": "T_EXEC_AS_ROOT",  "seed": 0.85},
    {"tech": "escape container to host root",   "pre": "T_CONTAINER_ESCAPE","result": "T_ROOT",          "seed": 0.85},
    {"tech": "SSH in as root with stolen key",  "pre": "T_READ_ROOT_KEY",   "result": "T_ROOT",          "seed": 0.95},
    {"tech": "read/write raw disk for root secrets","pre": "T_WRITE_DISK",  "result": "T_ROOT",          "seed": 0.90},
    {"tech": "use file capability to setuid",   "pre": "T_SETUID_CAP",      "result": "T_EXEC_AS_ROOT",  "seed": 0.93},
    {"tech": "run kernel LPE exploit",          "pre": "T_KERNEL_LPE",      "result": "T_ROOT",          "seed": 0.90},
    {"tech": "exploit polkit/pkexec",           "pre": "T_POLKIT_LPE",      "result": "T_ROOT",          "seed": 0.95},
]

ALPHA = 1.0  # Laplace smoothing prior (pseudocount per outcome class)


class CalibrationError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CalibrationError(message)


def load_json(path: str) -> object:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise CalibrationError(f"failed to parse {path}: {exc}") from exc


@dataclass
class RuleStats:
    tech: str
    seed: float
    n: int = 0
    s: int = 0  # successes (y == 1)

    def calibrated_p(self) -> float:
        # Laplace-smoothed MLE; falls back to seed when no data.
        if self.n == 0:
            return self.seed
        return (self.s + ALPHA) / (self.n + 2.0 * ALPHA)

    def brier(self, p_used: float) -> Optional[float]:
        if self.n == 0:
            return None
        return sum((p_used - (1.0 if yi else 0.0)) ** 2 for yi in self._ys) / self.n

    _ys: List[int] = None  # type: ignore

    def __post_init__(self) -> None:
        self._ys = []


def collect_outcomes(results_dir: str, corpus: dict) -> List[dict]:
    out: List[dict] = []
    for t in corpus.get("targets", []):
        tid = str(t.get("id", ""))
        path = os.path.join(results_dir, tid, "outcomes.json")
        raw = load_json(path)
        if isinstance(raw, list):
            out.extend(e for e in raw if isinstance(e, dict))
    return out


def brier_overall(pairs: List[tuple]) -> Optional[float]:
    if not pairs:
        return None
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def reliability_bins(pairs: List[tuple], n_bins: int = 10) -> List[dict]:
    if not pairs:
        return []
    width = 1.0 / n_bins
    bins = [{"bin_low": round(i * width, 4), "bin_high": round((i + 1) * width, 4),
             "mean_p": 0.0, "observed": 0.0, "count": 0} for i in range(n_bins)]
    for p, y in pairs:
        idx = min(int(p / width), n_bins - 1)
        b = bins[idx]
        b["mean_p"] += p
        b["observed"] += y
        b["count"] += 1
    for b in bins:
        if b["count"]:
            b["mean_p"] = round(b["mean_p"] / b["count"], 4)
            b["observed"] = round(b["observed"] / b["count"], 4)
    return bins


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate Z-Privesc rule probabilities")
    parser.add_argument("--results", required=True)
    parser.add_argument("--bins", type=int, default=10)
    args = parser.parse_args(argv)

    results_dir = args.results
    if not os.path.isdir(results_dir):
        print(f"error: results dir not found: {results_dir}", file=sys.stderr)
        return 2

    corpus = load_json(os.path.join(results_dir, "corpus.json"))
    if not isinstance(corpus, dict):
        print("error: corpus.json missing", file=sys.stderr)
        return 2

    outcomes = collect_outcomes(results_dir, corpus)

    # group by rule tech string
    stats: Dict[str, RuleStats] = {
        r["tech"]: RuleStats(tech=r["tech"], seed=float(r["seed"])) for r in RULES_REF
    }
    seed_pairs: List[tuple] = []   # (seed_p, y)
    for e in outcomes:
        tech = e.get("label")
        p = e.get("p")
        y = e.get("y")
        if tech not in stats or not isinstance(p, (int, float)) or y not in (0, 1):
            continue
        st = stats[tech]
        st.n += 1
        st.s += int(y)
        st._ys.append(int(y))
        seed_pairs.append((float(p), int(y)))

    # per-rule calibration
    rule_out = []
    calibrated_pairs: List[tuple] = []
    any_changed = False
    for ref in RULES_REF:
        st = stats[ref["tech"]]
        cal_p = st.calibrated_p()
        if st.n > 0 and abs(cal_p - st.seed) > 1e-6:
            any_changed = True
        rule_out.append({
            "tech": ref["tech"],
            "pre": ref["pre"],
            "result": ref["result"],
            "seed_p": round(st.seed, 4),
            "calibrated_p": round(cal_p, 4),
            "n": st.n,
            "successes": st.s,
            "brier_before": _round(st.brier(st.seed)),
            "brier_after": _round(st.brier(cal_p)),
            "calibrated": st.n > 0,
        })
        if st.n > 0:
            for yi in st._ys:
                calibrated_pairs.append((cal_p, yi))

    overall = {
        "n_observations": len(outcomes),
        "brier_seed": _round(brier_overall(seed_pairs)),
        "brier_calibrated": _round(brier_overall(calibrated_pairs)),
        "reliability_bins_seed": reliability_bins(seed_pairs, args.bins),
        "reliability_bins_calibrated": reliability_bins(calibrated_pairs, args.bins),
    }

    calib = {
        "schema": "zp-eval/calibration/v1",
        "alpha": ALPHA,
        "rules": rule_out,
        "overall": overall,
        "recommendation": (
            "APPLY calibrated_p (replace RULES[] p values in src/compose.c)"
            if any_changed else "seed values already optimal; no change required"
        ),
    }

    calib_path = os.path.join(results_dir, "calibration.json")
    with open(calib_path, "w", encoding="utf-8") as fh:
        json.dump(calib, fh, indent=2, sort_keys=True)
    print(f"wrote {calib_path} ({len(outcomes)} observations, changed={any_changed})")

    header = _emit_c_header(rule_out)
    header_path = os.path.join(results_dir, "RULES.calibrated.h")
    with open(header_path, "w", encoding="utf-8") as fh:
        fh.write(header)
    print(f"wrote {header_path}")
    return 0


def _round(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None


def _emit_c_header(rule_out: List[dict]) -> str:
    lines = []
    lines.append("/* AUTO-GENERATED by evaluation/calibrate.py -- do not edit by hand. */")
    lines.append("/* Calibrated exploit-reliability weights. Mirror ordering of src/compose.c. */")
    lines.append("static const struct rule RULES[] = {")
    for r in rule_out:
        pre = r["pre"]
        result = r["result"]
        p = r["calibrated_p"]
        tech = r["tech"].replace('"', '\\"')
        changed = "" if not r["calibrated"] else "  /* calibrated (n=%d, s=%d) */" % (r["n"], r["successes"])
        lines.append('    { TK(%s), %s, %.3ff, "%s" },%s' % (pre, result, p, tech, changed))
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
