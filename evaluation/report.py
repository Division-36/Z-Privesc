#!/usr/bin/env python3
"""Z-Privesc evaluation report generator.

Consumes results/metrics.json and results/calibration.json and emits a
human-readable Markdown report plus a machine-readable JSON mirror.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional


def _fmt(v: Optional[float]) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def _load(path: str) -> Optional[Any]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _md_table(headers: list, rows: list) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def build_markdown(metrics: Dict[str, Any], calib: Optional[Dict[str, Any]]) -> str:
    blocks: list = []
    blocks.append("# Z-Privesc Evaluation Report\n")
    blocks.append(f"Targets evaluated: **{metrics.get('n_targets', 0)}**\n")

    agg = metrics.get("aggregate", {})
    micro = agg.get("micro", {})
    macro = agg.get("macro", {})
    blocks.append("## Aggregate\n")
    blocks.append(_md_table(
        ["Metric", "Micro", "Macro"],
        [
            ["Detection recall", _fmt(micro.get("detection_recall")), _fmt(macro.get("detection_recall"))],
            ["Detection precision", _fmt(micro.get("detection_precision")), _fmt(macro.get("detection_precision"))],
            ["Path recall", _fmt(micro.get("path_recall")), _fmt(macro.get("path_recall"))],
            ["Path precision", _fmt(micro.get("path_precision")), _fmt(macro.get("path_precision"))],
            ["TP / FN / FP", f"{micro.get('tp',0)}/{micro.get('fn',0)}/{micro.get('fp',0)}",
             f"{micro.get('path_tp',0)}/{micro.get('path_fn',0)}/{micro.get('path_fp',0)} (path)"],
        ],
    ))
    blocks.append("")

    cal = agg.get("calibration", {})
    blocks.append("## Calibration (confidence vs verified outcome)\n")
    blocks.append(_md_table(
        ["Measure", "Value"],
        [
            ["Observations", str(cal.get("n_observations", 0))],
            ["Brier score", _fmt(cal.get("brier_score"))],
            ["Neg log-likelihood", _fmt(cal.get("negative_log_likelihood"))],
            ["Mean scan time (s)", _fmt(agg.get("cost", {}).get("mean_scan_time_sec"))],
        ],
    ))
    blocks.append("")

    bins = cal.get("reliability_bins", [])
    if bins:
        blocks.append("### Reliability bins (mean p vs observed frequency)\n")
        blocks.append(_md_table(
            ["p range", "mean p", "observed", "n"],
            [[f"{b['bin_low']:.2f}-{b['bin_high']:.2f}", f"{b['mean_p']:.3f}",
              f"{b['observed']:.3f}", str(b["count"])] for b in bins],
        ))
        blocks.append("")

    blocks.append("## Per-target\n")
    rows = []
    for t in metrics.get("per_target", []):
        rows.append([
            t.get("target_id", ""),
            _fmt(t.get("detection_recall")),
            _fmt(t.get("detection_precision")),
            _fmt(t.get("path_recall")),
            _fmt(t.get("path_precision")),
            str(t.get("n_findings", 0)),
            str(t.get("n_paths", 0)),
            _fmt(t.get("scan_time_sec")),
        ])
    blocks.append(_md_table(
        ["target", "det.rec", "det.prec", "path.rec", "path.prec", "findings", "paths", "sec"],
        rows,
    ))
    blocks.append("")

    if calib:
        blocks.append("## Confidence calibration (per rule)\n")
        rrows = []
        for r in calib.get("rules", []):
            rrows.append([
                r.get("tech", ""),
                _fmt(r.get("seed_p")),
                _fmt(r.get("calibrated_p")),
                str(r.get("n", 0)),
                str(r.get("successes", 0)),
                _fmt(r.get("brier_before")),
                _fmt(r.get("brier_after")),
            ])
        blocks.append(_md_table(
            ["technique", "seed p", "calib p", "n", "succ", "brier pre", "brier post"],
            rrows,
        ))
        blocks.append("")
        ov = calib.get("overall", {})
        blocks.append(f"Brier (seed): **{_fmt(ov.get('brier_seed'))}**  |  "
                      f"Brier (calibrated): **{_fmt(ov.get('brier_calibrated'))}**\n")
        blocks.append(f"Recommendation: {calib.get('recommendation', '')}\n")

    return "\n".join(blocks)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate evaluation report")
    parser.add_argument("--results", required=True)
    args = parser.parse_args(argv)

    metrics = _load(os.path.join(args.results, "metrics.json"))
    if metrics is None:
        print("error: metrics.json not found; run metrics.py first", file=sys.stderr)
        return 1
    calib = _load(os.path.join(args.results, "calibration.json"))

    md = build_markdown(metrics, calib)
    md_path = os.path.join(args.results, "report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    # JSON mirror (handy for archival / plotting)
    out = {"markdown": md, "metrics": metrics, "calibration": calib}
    json_path = os.path.join(args.results, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    print(f"wrote {md_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
