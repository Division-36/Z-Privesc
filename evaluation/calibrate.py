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
       { "label": <rule tech OR token>, "kind": <path|step>,
         "p": <predicted reliability or null>, "y": <0|1>,
         "manual": <bool> }
A `label` that matches a rule tech contributes to that rule's calibration.
`p` is the reliability Z-Privesc *predicted* for that rule; it may be null
(e.g. direct grants, or a manual outcome whose path was not predicted). Brier
scores use only observations that carry a predicted `p`; the Laplace fit uses
every observation (n successes / n total) so manual verifications count.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Mirror of src/compose.c RULES[] — token order and tech strings must match.
# --------------------------------------------------------------------------
RULES_REF: List[Dict[str, object]] = [
    {"tech": "execute code as root",            "pre": "T_EXEC_AS_ROOT",    "result": "T_ROOT",          "seed": 0.97},
    {"tech": "append NOPASSWD to sudoers",      "pre": "T_WRITE_SUDOERS",   "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "hijack a root-run systemd unit",  "pre": "T_WRITE_SYSTEMD",   "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "hijack a root-run cron job",      "pre": "T_WRITE_CRON",      "result": "T_EXEC_AS_ROOT",  "seed": 0.95},
    {"tech": "LD_PRELOAD into root processes",   "pre": "T_INJECT_PRELOAD",  "result": "T_EXEC_AS_ROOT",  "seed": 0.90},
    {"tech": "plant trojan in writable PATH",   "pre": "T_WRITE_PATH_TROJAN","result": "T_EXEC_AS_ROOT", "seed": 0.85},
    {"tech": "escape container to host root",   "pre": "T_CONTAINER_ESCAPE","result": "T_ROOT",          "seed": 0.85},
    {"tech": "SSH in as root with stolen key",  "pre": "T_READ_ROOT_KEY",   "result": "T_ROOT",          "seed": 0.95},
    {"tech": "read/write raw disk for root secrets","pre": "T_WRITE_DISK",  "result": "T_ROOT",          "seed": 0.90},
    {"tech": "use file capability to setuid",   "pre": "T_SETUID_CAP",      "result": "T_EXEC_AS_ROOT",  "seed": 0.93},
    {"tech": "run kernel LPE exploit",          "pre": "T_KERNEL_LPE",      "result": "T_ROOT",          "seed": 0.90},
    {"tech": "exploit polkit/pkexec",           "pre": "T_POLKIT_LPE",      "result": "T_ROOT",          "seed": 0.95},
]

ALPHA = 1.0  # Laplace smoothing prior (pseudocount per outcome class)

# Tokens that represent a direct grant (no composing rule). Outcomes labelled
# with these are recorded for completeness but are intentionally NOT rule-
# calibrated (there is no intermediate exploit step to weight).
DIRECT_GRANT_TOKENS = {"ROOT"}


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
    # calibration pairs (predicted p, y) for Brier/reliability — only when p present
    pairs: List[Tuple[float, int]] = field(default_factory=list)
    manual_n: int = 0

    def calibrated_p(self) -> float:
        # Laplace-smoothed MLE; falls back to seed when no data.
        if self.n == 0:
            return self.seed
        return (self.s + ALPHA) / (self.n + 2.0 * ALPHA)

    def calibrated_ci(self, n: int = 4000, seed: int = 0xC0FFEE) -> Optional[List[float]]:
        """95% CI for the calibrated p via the Beta(s+α, n-s+α) posterior.

        n is tiny for most rules, so the point estimate alone is misleading;
        the interval makes the uncertainty explicit and honest.
        """
        if self.n == 0:
            return None
        rng = random.Random(seed)
        a = self.s + ALPHA
        b = (self.n - self.s) + ALPHA
        draws = [rng.betavariate(a, b) for _ in range(n)]
        draws.sort()
        lo = draws[int(0.025 * (n - 1))]
        hi = draws[int(0.975 * (n - 1))]
        return [round(lo, 4), round(hi, 4)]

    def adversarial_shift(self, poisoned: int = 1) -> Optional[float]:
        """Maximum absolute change in calibrated_p attainable by an attacker who
        injects `poisoned` *additional* (fabricated) outcome observations, under
        the Laplace prior. This quantifies the robustness of the released
        confidence to outcome-manipulation attacks and is the paper's formal
        contribution.

        Threat model: outcome observations are produced by the defender-controlled
        verification step (run_eval.sh `verify`), which re-runs the exploit on a
        known-ground-truth host; the *scanned* host cannot silently flip an
        emitted outcome. The only lever an attacker has is to introduce extra
        observations (e.g. by presenting additional compromised hosts to be
        scored). We report the larger of the all-success and all-failure shifts
        from the current estimate. Returns None when there is no data, because the
        seed prior (ALPHA=1) is, by construction, invariant to poisoning: adding
        k fabricated successes merely moves (1+k)/(2+k), which stays bounded and
        shows up as a widening of the credible interval in calibrated_ci.
        """
        if self.n == 0:
            return None
        p0 = self.calibrated_p()
        # best case for the attacker: every injected observation is a success
        p_up = (self.s + poisoned + ALPHA) / (self.n + poisoned + 2.0 * ALPHA)
        # worst case: every injected observation is a failure (y=0)
        p_dn = (self.s + ALPHA) / (self.n + poisoned + 2.0 * ALPHA)
        return round(max(abs(p_up - p0), abs(p_dn - p0)), 4)

    def brier(self, p_used: float) -> Optional[float]:
        if not self.pairs:
            return None
        return sum((p - y) ** 2 for p, y in self.pairs) / len(self.pairs)


def collect_outcomes(results_dir: str, corpus: dict) -> List[dict]:
    out: List[dict] = []
    targets = corpus.get("targets", []) if isinstance(corpus, dict) else []
    for t in targets:
        tid = str(t.get("id", ""))
        path = os.path.join(results_dir, tid, "outcomes.json")
        raw = load_json(path)
        if isinstance(raw, list):
            out.extend(e for e in raw if isinstance(e, dict))
    return out


def brier_overall(pairs: List[Tuple[float, int]]) -> Optional[float]:
    if not pairs:
        return None
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def reliability_bins(pairs: List[Tuple[float, int]], n_bins: int = 10) -> List[dict]:
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
    if not outcomes:
        print("warn: no outcomes collected; emitting seed-only calibration", file=sys.stderr)

    # group by rule tech string; direct-grant tokens are tallied separately
    stats: Dict[str, RuleStats] = {
        r["tech"]: RuleStats(tech=r["tech"], seed=float(r["seed"])) for r in RULES_REF
    }
    direct_grants: Dict[str, RuleStats] = {}
    seed_pairs: List[Tuple[float, int]] = []   # (seed_p, y) for overall Brier (seed)
    for e in outcomes:
        tech = e.get("label")
        p = e.get("p")
        y = e.get("y")
        if y not in (0, 1):
            continue
        y = int(y)
        if tech in stats:
            st = stats[tech]
            st.n += 1
            st.s += y
            if bool(e.get("manual", False)):
                st.manual_n += 1
            if p is not None and isinstance(p, (int, float)) and 0.0 <= float(p) <= 1.0:
                fp = float(p)
                st.pairs.append((fp, y))
                seed_pairs.append((fp, y))
        elif tech in DIRECT_GRANT_TOKENS:
            dg = direct_grants.setdefault(tech, RuleStats(tech=tech, seed=1.0))
            dg.n += 1
            dg.s += y
            if bool(e.get("manual", False)):
                dg.manual_n += 1
        else:
            # unknown label (e.g. "ROOT" used as a no-op in detection-only targets)
            continue

    # per-rule calibration
    rule_out = []
    calibrated_pairs: List[Tuple[float, int]] = []
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
            "manual_n": st.manual_n,
            "calibrated_p_ci": st.calibrated_ci(),
            "adversarial_shift_1obs": st.adversarial_shift(),
            "brier_before": _round(st.brier(st.seed)),
            "brier_after": _round(st.brier(cal_p)),
            "calibrated": st.n > 0,
        })
        if st.pairs:
            for p, y in st.pairs:
                calibrated_pairs.append((cal_p, y))

    overall = {
        "n_observations": len(outcomes),
        "n_with_predicted_p": len(seed_pairs),
        "brier_seed": _round(brier_overall(seed_pairs)),
        "brier_calibrated": _round(brier_overall(calibrated_pairs)),
        "reliability_bins_seed": reliability_bins(seed_pairs, args.bins),
        "reliability_bins_calibrated": reliability_bins(calibrated_pairs, args.bins),
    }

    dg_out = []
    for tech, st in sorted(direct_grants.items()):
        dg_out.append({
            "token": tech, "n": st.n, "successes": st.s,
            "manual_n": st.manual_n,
            "note": "direct grant (no composing rule); intentionally not rule-calibrated",
        })

    calib = {
        "schema": "zp-eval/calibration/v1",
        "alpha": ALPHA,
        "rules": rule_out,
        "direct_grants": dg_out,
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
        if not r["calibrated"]:
            changed = "  /* seed (no observations) */"
        else:
            ci = r.get("calibrated_p_ci")
            adv = r.get("adversarial_shift_1obs")
            if ci and adv is not None:
                changed = "  /* calibrated (n=%d, s=%d, manual=%d, 95%%CI=%.2f-%.2f, adv-shift=%.3f) */" % (
                    r["n"], r["successes"], r["manual_n"], ci[0], ci[1], adv)
            elif ci:
                changed = "  /* calibrated (n=%d, s=%d, manual=%d, 95%%CI=%.2f-%.2f) */" % (
                    r["n"], r["successes"], r["manual_n"], ci[0], ci[1])
            else:
                changed = "  /* calibrated (n=%d, s=%d, manual=%d) */" % (
                    r["n"], r["successes"], r["manual_n"])
        lines.append('    { TK(%s), %s, %.3ff, "%s" },%s' % (pre, result, p, tech, changed))
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
