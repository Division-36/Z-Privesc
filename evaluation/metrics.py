#!/usr/bin/env python3
"""Z-Privesc evaluation metrics engine.

Reads a collected evaluation results directory (produced by run_eval.sh)
and computes detection, composition, calibration and cost metrics. Pure,
deterministic: identical inputs always yield identical outputs.

Inputs (under --results):
  corpus.json                 : copy of the corpus manifest
  baseline_zp.json            : Z-Privesc run on a clean (no-plant) host
  <target_id>/zp.json         : Z-Privesc JSON for the target
  <target_id>/outcomes.json   : [{label, kind, p, y}] exploit-verify results

Output:
  <results>/metrics.json      : full metric tree (per-target, per-slice, aggregate)
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Error handling
# --------------------------------------------------------------------------
class MetricsError(RuntimeError):
    """Raised for any unrecoverable input/processing error."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MetricsError(message)


def load_json(path: str) -> Any:
    """Load and parse a JSON file. Never returns partially; raises on any error."""
    if not os.path.isfile(path):
        raise MetricsError(f"missing required file: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise MetricsError(f"failed to parse JSON {path}: {exc}") from exc
    return data


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Observation:
    """A single (predicted probability, actual outcome) pair for calibration."""
    p: float
    y: int  # 0 or 1

    def __post_init__(self) -> None:
        if not (0.0 <= self.p <= 1.0):
            raise MetricsError(f"probability out of range: {self.p}")
        if self.y not in (0, 1):
            raise MetricsError(f"outcome must be 0/1, got {self.y}")


@dataclass
class TargetMetrics:
    target_id: str
    distro: str = ""
    release: str = ""
    kernel: str = ""
    # detection
    tp: int = 0
    fn: int = 0
    fp: int = 0
    # composition (path-level)
    path_tp: int = 0
    path_fn: int = 0
    path_fp: int = 0
    root_expected: bool = False
    root_reported: bool = False
    scan_time_sec: float = 0.0
    n_findings: int = 0
    n_paths: int = 0
    # calibration observations attributed to this target
    observations: List[Observation] = field(default_factory=list)

    def detection_recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return (self.tp / denom) if denom else None

    def detection_precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return (self.tp / denom) if denom else None

    def path_recall(self) -> Optional[float]:
        denom = self.path_tp + self.path_fn
        return (self.path_tp / denom) if denom else None

    def path_precision(self) -> Optional[float]:
        denom = self.path_tp + self.path_fp
        return (self.path_tp / denom) if denom else None


# --------------------------------------------------------------------------
# Parsing helpers (self-contained re: Z-Privesc audit JSON schema)
# --------------------------------------------------------------------------
def parse_findings(zp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten every finding across all probes into one list.

    Z-Privesc audit JSON shape (subset used here):
      { "findings": [ ... ] }                # top-level flat list (preferred)
      or { "probes": [ { "name": str, "findings": [ ... ] } ] }
    """
    if not isinstance(zp, dict):
        raise MetricsError("zp document is not an object")
    if isinstance(zp.get("findings"), list):
        return [f for f in zp["findings"] if isinstance(f, dict)]
    out: List[Dict[str, Any]] = []
    probes = zp.get("probes")
    if isinstance(probes, list):
        for probe in probes:
            if isinstance(probe, dict) and isinstance(probe.get("findings"), list):
                for f in probe["findings"]:
                    if isinstance(f, dict):
                        out.append(f)
    return out


def parse_paths(zp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return escalation_paths (list of {technique, confidence, steps})."""
    paths = zp.get("escalation_paths")
    if paths is None:
        return []
    if not isinstance(paths, list):
        raise MetricsError("escalation_paths is not a list")
    return [p for p in paths if isinstance(p, dict)]


def finding_ids(findings: List[Dict[str, Any]]) -> List[str]:
    ids: List[str] = []
    for f in findings:
        fid = f.get("id")
        if isinstance(fid, str) and fid:
            ids.append(fid)
    return ids


def is_high_critical(f: Dict[str, Any]) -> bool:
    sev = f.get("severity")
    return sev in ("HIGH", "CRITICAL")


# --------------------------------------------------------------------------
# Per-target metric computation
# --------------------------------------------------------------------------
def compute_target(
    target: Dict[str, Any],
    zp: Dict[str, Any],
    baseline_ids: set,
    scan_time_sec: float,
) -> TargetMetrics:
    tid = str(target.get("id", "<unknown>"))
    gt = target.get("ground_truth") or {}
    expected_findings = [str(x) for x in gt.get("expected_findings", [])]
    expected_paths = [str(x) for x in gt.get("expected_paths", [])]
    root_expected = bool(gt.get("root_reachable", bool(expected_paths)))

    findings = parse_findings(zp)
    fids = set(finding_ids(findings))
    paths = parse_paths(zp)
    reported_path_techniques = [str(p.get("technique", "")) for p in paths]
    root_reported = any("ROOT" in (p.get("technique", "") or "").upper() for p in paths)

    # detection
    tp = sum(1 for e in expected_findings if e in fids)
    fn = sum(1 for e in expected_findings if e not in fids)
    reported_hc = {f.get("id") for f in findings if is_high_critical(f) and f.get("id")}
    fp = sum(
        1
        for fid in reported_hc
        if fid not in set(expected_findings) and fid not in baseline_ids
    )

    # composition (path-level)
    path_tp = sum(1 for t in expected_paths if t in reported_path_techniques)
    path_fn = sum(1 for t in expected_paths if t not in reported_path_techniques)
    path_fp = 0
    if not root_expected:
        # any reported root path on a host that should NOT be root-reachable is a FP
        path_fp = sum(1 for t in reported_path_techniques if "ROOT" in t.upper())

    tm = TargetMetrics(
        target_id=tid,
        distro=str(target.get("distro", "")),
        release=str(target.get("release", "")),
        kernel=str(target.get("kernel", "")),
        tp=tp, fn=fn, fp=fp,
        path_tp=path_tp, path_fn=path_fn, path_fp=path_fp,
        root_expected=root_expected, root_reported=root_reported,
        scan_time_sec=scan_time_sec,
        n_findings=len(findings),
        n_paths=len(paths),
    )
    return tm


# --------------------------------------------------------------------------
# Calibration statistics
# --------------------------------------------------------------------------
def brier_score(obs: List[Observation]) -> Optional[float]:
    if not obs:
        return None
    return sum((o.p - o.y) ** 2 for o in obs) / len(obs)


def reliability_bins(obs: List[Observation], n_bins: int = 10) -> List[Dict[str, float]]:
    """Equal-width bins of predicted p; report observed frequency per bin."""
    _require(n_bins > 0, "n_bins must be positive")
    if not obs:
        return []
    width = 1.0 / n_bins
    bins: List[Dict[str, float]] = [
        {"bin_low": round(i * width, 4),
         "bin_high": round((i + 1) * width, 4),
         "mean_p": 0.0, "observed": 0.0, "count": 0}
        for i in range(n_bins)
    ]
    for o in obs:
        idx = min(int(o.p / width), n_bins - 1)
        b = bins[idx]
        b["mean_p"] += o.p
        b["observed"] += o.y
        b["count"] += 1
    for b in bins:
        c = b["count"]
        if c > 0:
            b["mean_p"] = round(b["mean_p"] / c, 4)
            b["observed"] = round(b["observed"] / c, 4)
    return bins


def negative_log_likelihood(obs: List[Observation]) -> Optional[float]:
    if not obs:
        return None
    nll = 0.0
    for o in obs:
        eps = 1e-9
        p = min(max(o.p, eps), 1.0 - eps)
        nll += -(o.y * math.log(p) + (1 - o.y) * math.log(1.0 - p))
    return nll


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------
def _safe_mean(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return (sum(vals) / len(vals)) if vals else None


def aggregate(targets: List[TargetMetrics]) -> Dict[str, Any]:
    if not targets:
        return {"count": 0}
    # macro-averaged rates
    det_recall = _safe_mean([t.detection_recall() for t in targets])
    det_prec = _safe_mean([t.detection_precision() for t in targets])
    path_recall = _safe_mean([t.path_recall() for t in targets])
    path_prec = _safe_mean([t.path_precision() for t in targets])
    total_tp = sum(t.tp for t in targets)
    total_fn = sum(t.fn for t in targets)
    total_fp = sum(t.fp for t in targets)
    total_path_tp = sum(t.path_tp for t in targets)
    total_path_fn = sum(t.path_fn for t in targets)
    total_path_fp = sum(t.path_fp for t in targets)
    micro_det_recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) else None
    micro_det_prec = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) else None
    micro_path_recall = (total_path_tp / (total_path_tp + total_path_fn)) if (total_path_tp + total_path_fn) else None
    micro_path_prec = (total_path_tp / (total_path_tp + total_path_fp)) if (total_path_tp + total_path_fp) else None

    all_obs: List[Observation] = []
    for t in targets:
        all_obs.extend(t.observations)

    return {
        "count": len(targets),
        "macro": {
            "detection_recall": _round(det_recall),
            "detection_precision": _round(det_prec),
            "path_recall": _round(path_recall),
            "path_precision": _round(path_prec),
        },
        "micro": {
            "detection_recall": _round(micro_det_recall),
            "detection_precision": _round(micro_det_prec),
            "path_recall": _round(micro_path_recall),
            "path_precision": _round(micro_path_prec),
            "tp": total_tp, "fn": total_fn, "fp": total_fp,
            "path_tp": total_path_tp, "path_fn": total_path_fn, "path_fp": total_path_fp,
        },
        "calibration": {
            "n_observations": len(all_obs),
            "brier_score": _round(brier_score(all_obs)),
            "negative_log_likelihood": _round(negative_log_likelihood(all_obs)),
            "reliability_bins": reliability_bins(all_obs, 10),
        },
        "cost": {
            "mean_scan_time_sec": _round(_safe_mean([t.scan_time_sec for t in targets])),
        },
    }


def _round(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None


def slice_by(targets: List[TargetMetrics], key: str) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[TargetMetrics]] = {}
    for t in targets:
        val = getattr(t, key, "") or "unknown"
        groups.setdefault(val, []).append(t)
    return {k: aggregate(v) for k, v in sorted(groups.items())}


# --------------------------------------------------------------------------
# Outcomes loading
# --------------------------------------------------------------------------
def load_outcomes(path: str) -> List[Observation]:
    """Load <target>/outcomes.json -> [Observation]. Missing file => empty."""
    if not os.path.isfile(path):
        return []
    raw = load_json(path)
    if not isinstance(raw, list):
        raise MetricsError(f"outcomes file is not a list: {path}")
    obs: List[Observation] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        p = entry.get("p")
        y = entry.get("y")
        if not isinstance(p, (int, float)) or y not in (0, 1):
            continue
        obs.append(Observation(p=float(p), y=int(y)))
    return obs


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Z-Privesc evaluation metrics engine")
    parser.add_argument("--results", required=True, help="results directory")
    parser.add_argument("--bins", type=int, default=10, help="reliability bin count")
    args = parser.parse_args(argv)

    results_dir = args.results
    if not os.path.isdir(results_dir):
        print(f"error: results dir not found: {results_dir}", file=sys.stderr)
        return 2

    corpus = load_json(os.path.join(results_dir, "corpus.json"))
    if not isinstance(corpus, dict) or not isinstance(corpus.get("targets"), list):
        print("error: corpus.json missing 'targets'", file=sys.stderr)
        return 2

    baseline_ids: set = set()
    baseline_path = os.path.join(results_dir, "baseline_zp.json")
    if os.path.isfile(baseline_path):
        baseline_ids = set(finding_ids(parse_findings(load_json(baseline_path))))

    targets_meta = corpus["targets"]
    computed: List[TargetMetrics] = []

    for tmeta in targets_meta:
        tid = str(tmeta.get("id", ""))
        zp_path = os.path.join(results_dir, tid, "zp.json")
        if not os.path.isfile(zp_path):
            print(f"warning: no zp.json for target {tid}; skipping", file=sys.stderr)
            continue
        try:
            zp = load_json(zp_path)
            scan_time = 0.0
            st_path = os.path.join(results_dir, tid, "scan_time_sec.txt")
            if os.path.isfile(st_path):
                try:
                    with open(st_path, "r", encoding="utf-8") as fh:
                        scan_time = float(fh.read().strip())
                except (OSError, ValueError):
                    scan_time = 0.0
            tm = compute_target(tmeta, zp, baseline_ids, scan_time)
            tm.observations = load_outcomes(os.path.join(results_dir, tid, "outcomes.json"))
            computed.append(tm)
        except MetricsError as exc:
            print(f"warning: target {tid} failed: {exc}", file=sys.stderr)
            continue

    if not computed:
        print("error: no targets computed", file=sys.stderr)
        return 1

    per_target = []
    for t in computed:
        per_target.append({
            "target_id": t.target_id,
            "distro": t.distro,
            "release": t.release,
            "kernel": t.kernel,
            "tp": t.tp, "fn": t.fn, "fp": t.fp,
            "path_tp": t.path_tp, "path_fn": t.path_fn, "path_fp": t.path_fp,
            "root_expected": t.root_expected, "root_reported": t.root_reported,
            "detection_recall": _round(t.detection_recall()),
            "detection_precision": _round(t.detection_precision()),
            "path_recall": _round(t.path_recall()),
            "path_precision": _round(t.path_precision()),
            "n_findings": t.n_findings, "n_paths": t.n_paths,
            "scan_time_sec": _round(t.scan_time_sec),
            "calibration": {
                "n_observations": len(t.observations),
                "brier_score": _round(brier_score(t.observations)),
            },
        })

    out = {
        "schema": "zp-eval/metrics/v1",
        "n_targets": len(computed),
        "per_target": per_target,
        "aggregate": aggregate(computed),
        "by_distro": slice_by(computed, "distro"),
        "by_kernel": slice_by(computed, "kernel"),
    }

    out_path = os.path.join(results_dir, "metrics.json")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, sort_keys=True)
    except OSError as exc:
        print(f"error: cannot write metrics.json: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out_path} ({len(computed)} targets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
