#!/bin/bash
# Ground-truth accuracy study for Z-Privesc on a clean Linux VM.
#
# Methodology
# -----------
# The 16 testbeds/ directories are treated as the GROUND TRUTH: each
# setup.sh plants one known, uniquely-named privilege-escalation
# misconfiguration. For every category we:
#   1. run setup.sh
#   2. run Z-Privesc --all and check whether the planted artifact's
#      unique signature string appears in the JSON findings (TRUE POSITIVE)
#   3. run cleanup.sh
# A category is a FALSE NEGATIVE if its signature never appears.
#
# A clean baseline (no testbed active) run counts HIGH/CRITICAL findings
# as the FALSE-POSITIVE proxy (noise on a properly-configured host).
#
# LinPEAS and Lynis are run ONCE on the fully-planted system and their
# detection is measured heuristically by keyword presence in their raw
# output (coarse, clearly labelled as such). Their clean-baseline noise
# is also counted.
#
# Run as root (passwordless sudo) inside the multipass VM.
set -u
cd "$(dirname "$0")/.."
ZP=./build/bin/z_privesc
OUT=benchmarks/data/accuracy
mkdir -p "$OUT"

CATS="suid writable_path capabilities writable_etc docker polkit world_writable cron sudoers ssh_keys groups service kernel_hardening process nfs ld_preload"
NOTE_kernel_vuln="version-based (not plantable); excluded from TP/FN"
NOTE_kernel_hardening="best-effort sysctl writes; may be partially applied"
NOTE_process="runtime process state; depends on the planted PID still running"

# unique planted-artifact signature per category (substring in Z-Privesc JSON)
sig_suid="bash-root-suid"
sig_writable_path="evil-path"
sig_capabilities="python3-cap"
sig_writable_etc="zprivesc-weak"
sig_docker="docker.sock"
sig_polkit="pkexec"
sig_world_writable="weak-config"
sig_cron="cron.d/zprivesc-weak"
sig_sudoers="zprivesc-nopasswd"
sig_ssh_keys="id_rsa"
sig_groups="docker"
sig_service="zprivesc-weak.service"
sig_kernel_hardening="KHARD"
sig_process="ww-root-proc"
sig_nfs="no_root_squash"
sig_ld_preload="zprivesc-weak.conf"

run_zp() { sudo env PATH="/tmp/evil-path:$PATH" "$ZP" --all --json --quiet "$@"; }

echo "==> Ensuring clean baseline"
for c in $CATS; do sudo bash "testbeds/$c/cleanup.sh" >/dev/null 2>&1 || true; done

echo "==> Clean baseline (Z-Privesc)"
run_zp > "$OUT/baseline_zp.json"
BASE_FP=$(jq '[.probes[].findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")] | length' "$OUT/baseline_zp.json")

echo "category,signature,baseline_present,planted_present,zp_verdict,planted_high" > "$OUT/zp_matrix.csv"
tp=0; fn=0
for c in $CATS; do
  sudo bash "testbeds/$c/setup.sh" >/dev/null 2>&1 || true
  run_zp > "$OUT/run_$c.json"
  sig=$(eval echo "\$sig_$c")
  planted_present=$(grep -c -- "$sig" "$OUT/run_$c.json")
  base_present=$(grep -c -- "$sig" "$OUT/baseline_zp.json")
  verdict=$(jq --arg c "$c" '[.probes[] | select(.name==$c) | .verdict] | join(",")' "$OUT/run_$c.json" 2>/dev/null)
  planted_high=$(jq --arg c "$c" '[.probes[] | select(.name==$c) | .findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")] | length' "$OUT/run_$c.json" 2>/dev/null)
  echo "$c,$sig,$base_present,$planted_present,$verdict,$planted_high" >> "$OUT/zp_matrix.csv"
  if [ "$planted_present" -gt 0 ]; then tp=$((tp+1)); else fn=$((fn+1)); fi
  sudo bash "testbeds/$c/cleanup.sh" >/dev/null 2>&1 || true
done

echo "==> Planting ALL categories for cross-tool comparison"
for c in $CATS; do sudo bash "testbeds/$c/setup.sh" >/dev/null 2>&1 || true; done
run_zp > "$OUT/all_zp.json"
ALL_ZP_TP=$(grep -c -- "bash-root-suid\|evil-path\|python3-cap\|zprivesc-weak\|docker.sock\|pkexec\|weak-config\|cron.d/zprivesc-weak\|zprivesc-nopasswd\|id_rsa\|zprivesc-weak.service\|KHARD\|ww-root-proc\|no_root_squash\|zprivesc-weak.conf" "$OUT/all_zp.json")

echo "==> LinPEAS (all-planted + clean baseline)"
if [ -x linpeas.sh ]; then
  timeout 200 bash linpeas.sh -q -a > "$OUT/all_linpeas.txt" 2>&1 || true
  for c in $CATS; do sudo bash "testbeds/$c/cleanup.sh" >/dev/null 2>&1 || true; done
  timeout 200 bash linpeas.sh -q -a > "$OUT/clean_linpeas.txt" 2>&1 || true
else
  echo "linpeas.sh not present, skipping" 
fi

echo "==> Lynis (all-planted + clean baseline)"
if command -v lynis >/dev/null 2>&1; then
  for c in $CATS; do sudo bash "testbeds/$c/setup.sh" >/dev/null 2>&1 || true; done
  timeout 200 sudo lynis audit system --quick --no-colors > "$OUT/all_lynis.txt" 2>&1 || true
  for c in $CATS; do sudo bash "testbeds/$c/cleanup.sh" >/dev/null 2>&1 || true; done
  timeout 200 sudo lynis audit system --quick --no-colors > "$OUT/clean_lynis.txt" 2>&1 || true
else
  echo "lynis not present, skipping"
fi

# Cross-tool heuristic detection (keyword presence in all-planted output)
detect_tool() {
  local f="$1"; shift
  local res=""
  for c in $CATS; do
    sig=$(eval echo "\$sig_$c")
    if [ -f "$f" ] && grep -q -- "$sig" "$f" 2>/dev/null; then res="$res$c=1 "; else res="$res$c=0 "; fi
  done
  echo "$res"
}
LP_DET=$(detect_tool "$OUT/all_linpeas.txt")
LY_DET=$(detect_tool "$OUT/all_lynis.txt")
LP_CLEAN=$( [ -f "$OUT/clean_linpeas.txt" ] && grep -c '\[!\]\|WARNING' "$OUT/clean_linpeas.txt" || echo 0 )
LY_CLEAN=$( [ -f "$OUT/clean_lynis.txt" ] && grep -c -i 'warning\|vulnerable' "$OUT/clean_lynis.txt" || echo 0 )

cat > "$OUT/accuracy.json" <<JSON
{
  "method": "planted testbeds as ground truth; Z-Privesc detection = unique artifact signature in JSON findings; LinPEAS/Lynis detection = heuristic keyword presence in raw output",
  "categories_planted": 15,
  "zp_true_positives": $tp,
  "zp_false_negatives": $fn,
  "zp_recall": $(awk "BEGIN{printf \"%.3f\", $tp/15}"),
  "zp_baseline_high_critical_findings": $BASE_FP,
  "zp_false_positive_proxy": $BASE_FP,
  "linpeas_detected_categories": "$LP_DET",
  "lynis_detected_categories": "$LY_DET",
  "linpeas_clean_baseline_flagged_lines": $LP_CLEAN,
  "lynis_clean_baseline_flagged_lines": $LY_CLEAN,
  "notes": {
    "kernel_vuln": "$NOTE_kernel_vuln",
    "kernel_hardening": "$NOTE_kernel_hardening",
    "process": "$NOTE_process"
  }
}
JSON

echo "==> DONE"
echo "Z-Privesc TP=$tp FN=$fn recall=$(awk "BEGIN{printf \"%.3f\", $tp/15}") baseline_high=$BASE_FP"
echo "LinPEAS detected: $LP_DET"
echo "Lynis detected:   $LY_DET"
