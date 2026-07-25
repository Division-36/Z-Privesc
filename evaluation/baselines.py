#!/usr/bin/env python3
"""Z-Privesc baseline comparison engine.

Parses LinPEAS / Lynis raw output captured by run_eval.sh for each corpus
target and compares detection against the SAME ground truth used for
Z-Privesc, producing a like-for-like recall/precision/FPR comparison plus a
false-positive proxy from the clean-host baseline run.

This is deliberately heuristic where the baseline tools do not emit
structured findings: a planted-artifact SIGNATURE (e.g. 'zprivesc-nopasswd')
is counted as detected if it appears anywhere in the tool's raw output. The
false-positive proxy counts warning/vulnerable-style lines on the clean
baseline host. Both proxies are explicitly labelled as such in the report.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional


class BaselineError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def load_json(path: str) -> Any:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise BaselineError(f"failed to parse {path}: {exc}") from exc


def read_text(path: str) -> Optional[str]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise BaselineError(f"cannot read {path}: {exc}") from exc


def _fp_lines(text: str, tool: str) -> int:
    """Coarse false-positive proxy: warning/vulnerable/noise lines on a clean
    host. A single pattern covers all read-only enumerators (Tier A); the point
    is to quantify alert volume, not to parse each tool's private format."""
    pat = re.compile(r"warning|vulnerable|\[\!", re.IGNORECASE)
    return sum(1 for line in text.splitlines() if pat.search(line))


def analyze_gftobins(results_dir: str, corpus: dict) -> dict:
    """GTFOBins as an *automated* baseline.

    GTFOBins is a curated manual reference of binary->privilege techniques. It
    performs no automated presence-detection (it does not scan a host) and emits
    no composition or calibrated confidence. To measure its relevance we compute
    two honest numbers:

      * knowledge_coverage_recall: fraction of the corpus's planted techniques
        that correspond to a documented GTFOBins technique. This is a *static*
        property of the test suite, not of a scan.
      * automated_detection_recall: 0.0 by construction, because GTFOBins cannot
        inspect a host to detect whether a vulnerable configuration is actually
        present.

    Binary/capability techniques (sudo, SUID, capabilities, ssh, docker, systemd,
    cron, ld.so.preload, PATH hijack, pkexec) ARE covered; process-injection and
    kernel-LPE are intentionally NOT (GTFOBins documents neither), which is the
    point: Z-Privesc covers attack surface GTFOBins has no knowledge of.
    """
    # (substring present in a corpus expected_finding, GTFOBins technique name)
    GTFOBINS_INDEX = [
        ("zprivesc-nopasswd", "sudo"),
        ("zprivesc-cmd", "sudo"),
        ("zprivesc-weak", "sudo"),
        ("bash-root-suid", "sudo (SUID)"),
        ("python3-suid", "sudo (SUID)"),
        ("python3-cap", "capabilities"),
        ("python3-cap2", "capabilities"),
        ("id_rsa", "ssh"),
        ("id_ed25519", "ssh"),
        ("docker", "docker"),
        ("zprivesc-weak.service", "systemd"),
        ("zprivesc-svc2.service", "systemd"),
        ("cron.d/zprivesc-weak", "cron"),
        ("cron.d/zprivesc-cron2", "cron"),
        ("zprivesc-weak.conf", "ld.so.preload"),
        ("zprivesc-pre2.conf", "ld.so.preload"),
        ("evil-path", "sudo (PATH hijack)"),
        ("pkexec", "pkexec"),
        # not mapped: ww-root-proc (process injection) and KHARD (kernel LPE)
    ]
    targets_meta = corpus.get("targets", [])
    per_target: List[dict] = []
    total_expected = 0
    total_covered = 0
    for t in targets_meta:
        tid = str(t.get("id", ""))
        gt = t.get("ground_truth") or {}
        # clean hosts have no expected_findings -> excluded from knowledge coverage
        expected = [str(x) for x in gt.get("expected_findings", [])]
        if not expected:
            continue
        covered = [e for e in expected
                   if any(key in e for key, _ in GTFOBINS_INDEX)]
        total_expected += len(expected)
        total_covered += len(covered)
        per_target.append({
            "target_id": tid,
            "expected": expected,
            "knowledge_covered": covered,
            "knowledge_coverage": round(len(covered) / len(expected), 4),
        })
    if not per_target:
        return {
            "tool": "gtfobins",
            "type": "static-knowledge-baseline (no automated scan)",
            "aggregate": {
                "knowledge_coverage_recall": None,
                "automated_detection_recall": 0.0,
                "note": "no vulnerable targets in corpus",
            },
            "per_target": [],
        }
    return {
        "tool": "gtfobins",
        "type": "static-knowledge-baseline (no automated scan)",
        "n_targets": len(per_target),
        "aggregate": {
            "expected_total": total_expected,
            "knowledge_covered": total_covered,
            "knowledge_coverage_recall": round(total_covered / total_expected, 4),
            "automated_detection_recall": 0.0,
            "note": ("GTFOBins covers binary/capability techniques but provides "
                     "no automated presence-detection (0% scan recall) and no "
                     "multi-step composition or calibrated confidence."),
        },
        "per_target": per_target,
    }


def analyze_tool(tool: str, results_dir: str, corpus: dict) -> Optional[dict]:
    targets_meta = corpus.get("targets", [])
    per_target: List[dict] = []
    total_tp = 0
    total_fn = 0
    for t in targets_meta:
        tid = str(t.get("id", ""))
        gt = t.get("ground_truth") or {}
        expected = [str(x) for x in gt.get("expected_findings", [])]
        txt = read_text(os.path.join(results_dir, tid, f"{tool}.txt"))
        if txt is None:
            continue  # tool not captured for this target
        low = txt.lower()
        detected = [e for e in expected if e.lower() in low]
        tp = len(detected)
        fn = len(expected) - tp
        total_tp += tp
        total_fn += fn
        runtime = None
        rt_path = os.path.join(results_dir, tid, f"{tool}_time_sec.txt")
        if os.path.isfile(rt_path):
            try:
                with open(rt_path, "r", encoding="utf-8") as fh:
                    runtime = round(float(fh.read().strip()), 3)
            except (OSError, ValueError):
                runtime = None
        per_target.append({
            "target_id": tid,
            "expected": expected,
            "detected": detected,
            "tp": tp,
            "fn": fn,
            "recall": round(tp / len(expected), 4) if expected else None,
            "runtime_sec": runtime,
        })

    if not per_target:
        return None

    recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) else None
    # false-positive proxy from clean-host baseline run
    base_txt = read_text(os.path.join(results_dir, f"baseline_{tool}.txt"))
    fp_clean = _fp_lines(base_txt, tool) if base_txt is not None else None

    return {
        "tool": tool,
        "n_targets_captured": len(per_target),
        "aggregate": {
            "tp": total_tp,
            "fn": total_fn,
            "detection_recall": round(recall, 4) if recall is not None else None,
            "fp_clean_host_lines": fp_clean,
        },
        "per_target": per_target,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Z-Privesc baseline comparison")
    parser.add_argument("--results", required=True)
    args = parser.parse_args(argv)

    results_dir = args.results
    if not os.path.isdir(results_dir):
        print(f"error: results dir not found: {results_dir}", file=sys.stderr)
        return 2
    corpus = load_json(os.path.join(results_dir, "corpus.json"))
    if not isinstance(corpus, dict):
        print("error: corpus.json missing", file=sys.stderr)
        return 2

    out: Dict[str, Any] = {"schema": "zp-eval/baselines/v1", "tools": {}}
    # Discover every baseline tool for which captures exist. enumerate_targets in
    # run_eval.sh writes <tool>.txt per target and baseline_<tool>.txt.
    known = ("linpeas", "lynis", "linenum", "lse", "unix-privesc-check", "traitor")
    for tool in known:
        res = analyze_tool(tool, results_dir, corpus)
        if res is not None:
            out["tools"][tool] = res

    # GTFOBins is a static reference baseline (no capture file required).
    out["tools"]["gtfobins"] = analyze_gftobins(results_dir, corpus)

    if not out["tools"]:
        print("warn: no baseline captures found; wrote empty baselines.json", file=sys.stderr)

    out_path = os.path.join(results_dir, "baselines.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
    print(f"wrote {out_path} (tools: {', '.join(out['tools'].keys()) or 'none'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
