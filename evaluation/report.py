#!/usr/bin/env python3
"""Z-Privesc evaluation report generator.

Consumes results/{metrics.json, calibration.json, baselines.json} and emits a
human-readable Markdown report plus a machine-readable JSON mirror.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional


def _fmt(v: Optional[float]) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def _fmt_ci(ci: Optional[list]) -> str:
    if not ci or len(ci) != 2:
        return "n/a"
    return f"[{ci[0]:.2f}-{ci[1]:.2f}]"


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


def _zp_detection_recall(metrics: Dict[str, Any]) -> Optional[float]:
    agg = metrics.get("aggregate", {})
    return agg.get("macro", {}).get("detection_recall")


def build_markdown(metrics: Dict[str, Any], calib: Optional[Dict[str, Any]],
                   baselines: Optional[Dict[str, Any]]) -> str:
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

    # ---- Calibration quality ------------------------------------------
    blocks.append("## Confidence calibration (predicted vs verified)\n")
    if calib:
        ov = calib.get("overall", {})
        blocks.append(_md_table(
            ["Measure", "Value"],
            [
                ["Observations (all)", str(ov.get("n_observations", 0))],
                ["Observations (with predicted p)", str(ov.get("n_with_predicted_p", 0))],
                ["Brier score (seed weights)", _fmt(ov.get("brier_seed"))],
                ["Brier score (calibrated weights)", _fmt(ov.get("brier_calibrated"))],
                ["Brier score 95% CI (calibrated)", _fmt_ci(metrics.get("aggregate", {}).get("calibration", {}).get("brier_score_95ci"))],
                ["Mean scan time (s)", _fmt(agg.get("cost", {}).get("mean_scan_time_sec"))],
            ],
        ))
        blocks.append("")

        bins = ov.get("reliability_bins_calibrated", [])
        if bins:
            blocks.append("### Reliability bins after calibration (mean p vs observed)\n")
            blocks.append(_md_table(
                ["p range", "mean p", "observed", "n"],
                [[f"{b['bin_low']:.2f}-{b['bin_high']:.2f}", f"{b['mean_p']:.3f}",
                  f"{b['observed']:.3f}", str(b["count"])] for b in bins],
            ))
            blocks.append("")

        blocks.append("### Per-rule calibration\n")
        rrows = []
        for r in calib.get("rules", []):
            rrows.append([
                r.get("tech", ""),
                _fmt(r.get("seed_p")),
                _fmt(r.get("calibrated_p")),
                _fmt_ci(r.get("calibrated_p_ci")),
                str(r.get("n", 0)),
                str(r.get("successes", 0)),
                str(r.get("manual_n", 0)),
                _fmt(r.get("brier_before")),
                _fmt(r.get("brier_after")),
            ])
        blocks.append(_md_table(
            ["technique", "seed p", "calib p", "calib 95% CI", "n", "succ", "manual", "brier pre", "brier post"],
            rrows,
        ))
        blocks.append("")
        blocks.append(f"Recommendation: {calib.get('recommendation', '')}\n")

        dg = calib.get("direct_grants", [])
        if dg:
            blocks.append("Direct grants (no composing rule; not rule-calibrated): "
                          + ", ".join(f"{d['token']} (n={d['n']}, succ={d['successes']})" for d in dg) + "\n")
    else:
        blocks.append("_calibration.json not found_\n")
    blocks.append("")

    # ---- Baseline comparison ------------------------------------------
    if baselines and baselines.get("tools"):
        blocks.append("## Baseline comparison (enumerators)\n")
        blocks.append("Detection recall is measured against the **same** planted-artifact "
                       "signatures used for Z-Privesc. The false-positive proxy counts "
                       "warning/vulnerable-style lines on the clean baseline host. These are "
                       "Tier-A read-only enumerators: they surface state but perform no "
                       "composition and attach no calibrated confidence, so their value here is "
                       "recall of the planted artifact and alert volume. The directly comparable "
                       "Tier-B auto-exploit tool (Traitor) is mutating and excluded from this "
                       "shared-host run (see paper: isolation caveat).\n")
        zp_rec = _zp_detection_recall(metrics)
        rows = [["Z-Privesc (this work)", _fmt(zp_rec), "-", "-", "-"]]
        for tool, t in baselines["tools"].items():
            a = t.get("aggregate", {})
            rows.append([
                tool,
                _fmt(a.get("detection_recall")),
                str(a.get("tp", 0)),
                str(a.get("fn", 0)),
                str(a.get("fp_clean_host_lines")),
            ])
        blocks.append(_md_table(
            ["tool", "detection recall", "TP", "FN", "FP (clean-host lines)"],
            rows,
        ))
        blocks.append("")

        # per-target baseline detail for available tools
        for tool, t in baselines["tools"].items():
            blocks.append(f"### {tool} per-target\n")
            rows = []
            for pt in t.get("per_target", []):
                rows.append([
                    pt.get("target_id", ""),
                    str(pt.get("tp", 0)),
                    str(pt.get("fn", 0)),
                    _fmt(pt.get("recall")),
                    _fmt(pt.get("runtime_sec")),
                ])
            blocks.append(_md_table(
                ["target", "TP", "FN", "recall", "runtime s"],
                rows,
            ))
            blocks.append("")

    # ---- Per-target -----------------------------------------------------
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

    # ---- Slices --------------------------------------------------------
    for slice_name, key in (("By distro", "by_distro"), ("By kernel", "by_kernel")):
        sl = metrics.get(key, {})
        if sl:
            blocks.append(f"## {slice_name}\n")
            rows = []
            for name, sub in sorted(sl.items()):
                m = sub.get("macro", {})
                rows.append([
                    name,
                    str(sub.get("count", 0)),
                    _fmt(m.get("detection_recall")),
                    _fmt(m.get("path_recall")),
                ])
            blocks.append(_md_table(
                ["group", "n", "det.recall", "path.recall"],
                rows,
            ))
            blocks.append("")

    blocks.append("## Honest limitations\n")
    blocks.append(
        "- Calibration `n` is small; per-rule confidence intervals are wide. Scale the "
        "corpus (corpus.json) across distros/kernels before claiming precise `p`.\n"
        "- Manual outcomes (container escape, cron/systemd/ld_preload/writable-PATH, "
        "kernel LPE, polkit, NFS) are human-verified, not auto-exploited; they are "
        "labelled `manual` in outcomes.json.\n"
        "- Baseline detection is a signature-substring heuristic and an FP proxy; it is "
        "not a structured comparison and is reported as such.\n"
        "- Runtime for Z-Privesc is wall-clock of a single `--all` scan; baseline runtime "
        "is captured where the tool was installed.\n"
    )

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
    baselines = _load(os.path.join(args.results, "baselines.json"))

    md = build_markdown(metrics, calib, baselines)
    md_path = os.path.join(args.results, "report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    out = {"markdown": md, "metrics": metrics, "calibration": calib, "baselines": baselines}
    json_path = os.path.join(args.results, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    print(f"wrote {md_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
