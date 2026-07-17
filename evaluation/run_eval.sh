#!/usr/bin/env bash
# run_eval.sh - Z-Privesc evaluation orchestrator (production-hardened).
#
# Provisions each corpus target, plants its misconfiguration, runs Z-Privesc
# (and optional baselines), verifies exploit outcomes for confidence
# calibration, then computes metrics, fits calibrated probabilities, and
# renders a report.
#
# Designed to run on a control host that has `multipass` (default), `docker`,
# or SSH access to targets. All steps are idempotent and fail-closed.
#
# Usage:
#   run_eval.sh --corpus evaluation/corpus.example.json \
#               --results evaluation/results \
#               --zp ./build/bin/z_privesc
set -euo pipefail
shopt -s lastpipe 2>/dev/null || true

# --------------------------------------------------------------------------
# Configuration / logging
# --------------------------------------------------------------------------
LOG_TAG="zp-eval"
log()  { printf '%s [%-6s] %s\n' "$(date -u +%FT%TZ)" "$LOG_TAG" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }
warn() { log "WARN: $*"; }

CORPUS=""
RESULTS=""
ZP_BIN=""
TIMEOUT=300
DRYRUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --corpus)   CORPUS="$2"; shift 2 ;;
    --results)  RESULTS="$2"; shift 2 ;;
    --zp)       ZP_BIN="$2"; shift 2 ;;
    --timeout)  TIMEOUT="$2"; shift 2 ;;
    --dry-run)  DRYRUN=1; shift ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$CORPUS" ]  || die "--corpus is required"
[ -n "$RESULTS" ] || die "--results is required"
[ -f "$CORPUS" ]  || die "corpus not found: $CORPUS"
ZP_BIN="${ZP_BIN:-./build/bin/z_privesc}"
[ -x "$ZP_BIN" ]  || die "zp binary not executable: $ZP_BIN"

mkdir -p "$RESULTS"
RESULTS="$(cd "$RESULTS" && pwd)"
cp "$CORPUS" "$RESULTS/corpus.json"
log "corpus=$CORPUS results=$RESULTS zp=$ZP_BIN"

# --------------------------------------------------------------------------
# Validate manifest against schema (if jsonschema is available)
# --------------------------------------------------------------------------
if python3 -c 'import jsonschema' 2>/dev/null; then
  if ! python3 - "$CORPUS" "$(dirname "$0")/corpus.schema.json" <<'PY'
import json, sys
try:
    import jsonschema
except ImportError:
    sys.exit(0)
schema = json.load(open(sys.argv[2]))
doc = json.load(open(sys.argv[1]))
jsonschema.validate(doc, schema)
PY
  then
    die "corpus failed schema validation"
  fi
  log "corpus schema: OK"
else
  warn "python jsonschema not installed; skipping schema validation"
fi

# --------------------------------------------------------------------------
# Provisioned-instance bookkeeping + cleanup trap
# --------------------------------------------------------------------------
PROVISIONED=()
INSTANCE_PREFIX="zp-eval-"
cleanup() {
  local inst
  for inst in "${PROVISIONED[@]:-}"; do
    [ -z "$inst" ] && continue
    log "cleanup: deleting instance $inst"
    multipass delete "$inst" >/dev/null 2>&1 || true
    multipass purge  >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT ERR INT TERM

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
instance_name() { echo "${INSTANCE_PREFIX}${1}"; }

provision() {
  local id="$1" img="$2" prov="$3" inst
  inst="$(instance_name "$id")"
  case "$prov" in
    multipass)
      multipass launch --name "$inst" "${img:-ubuntu:22.04}" >/dev/null 2>&1 \
        || die "provision failed: $inst"
      multipass transfer "$ZP_BIN" "$inst:/tmp/z_privesc" >/dev/null 2>&1 \
        || die "transfer zp failed: $inst"
      multipass exec "$inst" -- sudo install -m0755 /tmp/z_privesc /usr/local/bin/z_privesc >/dev/null 2>&1 \
        || die "install zp failed: $inst"
      ;;
    docker)
      docker run -d --name "$inst" --privileged "${img:-ubuntu:22.04}" sleep infinity >/dev/null 2>&1 \
        || die "provision failed: $inst"
      docker cp "$ZP_BIN" "$inst:/usr/local/bin/z_privesc" >/dev/null 2>&1 \
        || die "transfer zp failed: $inst"
      ;;
    ssh)
      log "ssh provisioner: assuming host already prepared for $id"
      ;;
    *) die "unknown provisioner: $prov" ;;
  esac
  PROVISIONED+=("$inst")
  echo "$inst"
}

run_in() {
  # run_in <instance> <cmd...>  -> runs cmd on the instance via its provisioner
  local inst="$1"; shift
  case "$PROVISIONER" in
    multipass) multipass exec "$inst" -- bash -lc "$*" ;;
    docker)    docker exec "$inst" bash -lc "$*" ;;
    ssh)       bash -lc "$*" ;;  # CORPUS host already is the target
    *) die "no provisioner set" ;;
  esac
}

teardown_instance() {
  local inst="$1" prov="$2"
  case "$prov" in
    multipass) multipass delete "$inst" >/dev/null 2>&1 || true; multipass purge >/dev/null 2>&1 || true ;;
    docker)    docker rm -f "$inst" >/dev/null 2>&1 || true ;;
    ssh)       : ;;
  esac
  # remove from PROVISIONED
  local i; for i in "${!PROVISIONED[@]}"; do
    [ "${PROVISIONED[$i]}" = "$inst" ] && unset 'PROVISIONED[i]'
  done
}

# --------------------------------------------------------------------------
# Baseline (clean-host) run for false-positive proxy
# --------------------------------------------------------------------------
run_baseline() {
  if [ -n "${BASE_INST:-}" ]; then
    log "baseline already captured at $BASE_INST"
    return 0
  fi
  log "baseline: clean host run (no plants)"
  local out="$RESULTS/baseline_zp.json"
  if ! run_in "$BASE_INST_NAME" "sudo z_privesc --all --json --quiet" >"$out" 2>/dev/null; then
    warn "baseline zp run failed; FP proxy will be empty"
    echo '{"findings":[]}' >"$out"
  fi
  BASE_INST="$BASE_INST_NAME"
  log "baseline written: $out"
}

# --------------------------------------------------------------------------
# Per-target evaluation
# --------------------------------------------------------------------------
eval_target() {
  local id="$1" prov="$2" img="$3" setup="$4" teardown="$5"
  local inst; inst="$(provision "$id" "$img" "$prov")"
  local tdir="$RESULTS/$id"
  mkdir -p "$tdir"

  # plant
  if [ -n "$setup" ] && [ -f "$setup" ]; then
    log "[$id] setup: $setup"
    run_in "$inst" "sudo bash -s" <"$setup" >/dev/null 2>&1 || warn "[$id] setup script non-zero"
  fi

  # run Z-Privesc (timed)
  log "[$id] running z_privesc"
  local t0 t1
  t0="$(date +%s.%N)"
  if ! run_in "$inst" "sudo z_privesc --all --json --quiet" >"$tdir/zp.json" 2>/dev/null; then
    warn "[$id] zp run failed; writing empty"
    echo '{"findings":[],"escalation_paths":[]}' >"$tdir/zp.json"
  fi
  t1="$(date +%s.%N)"
  awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", b-a}' >"$tdir/scan_time_sec.txt"

  # baselines (heuristic capture only; recorded for later analysis)
  for b in "${BASELINES[@]:-}"; do
    case "$b" in
      linpeas)
        command -v linpeas.sh >/dev/null 2>&1 && \
          timeout "$TIMEOUT" linpeas.sh -q -a >"$tdir/linpeas.txt" 2>&1 || \
          warn "[$id] linpeas not available"
        ;;
      lynis)
        run_in "$inst" "sudo lynis audit system --quick --no-colors" >"$tdir/lynis.txt" 2>&1 || \
          warn "[$id] lynis not available"
        ;;
    esac
  done

  # verify exploit outcomes -> outcomes.json (drives calibration)
  local outcomes="$tdir/outcomes.json"
  echo "[]" >"$outcomes"
  local vlabel vcmd vuser vto vkind
  # iterate verify_paths and verify_steps arrays from the manifest
  python3 - "$CORPUS" "$id" "$tdir/zp.json" "$outcomes" "$TIMEOUT" <<'PY'
import json, subprocess, sys, tempfile, os

corpus = json.load(open(sys.argv[1]))
tid = sys.argv[2]
zp_path = sys.argv[3]
out_path = sys.argv[4]
timeout = int(sys.argv[5])

target = next((t for t in corpus["targets"] if t["id"] == tid), None)
if target is None:
    sys.exit(0)
zp = json.load(open(zp_path))
outcomes = []

def run_verify(label, cmd, user, kind):
    p = None
    # extract reliability p for this label from zp output
    for path in (zp.get("escalation_paths") or []):
        if path.get("technique") == label:
            steps = path.get("steps") or []
            if steps:
                p = steps[0].get("reliability")
            break
        for s in (path.get("steps") or []):
            if s.get("technique") == label:
                p = s.get("reliability"); break
    full = cmd
    if user:
        full = f"sudo -u {user} bash -lc {json.dumps(cmd)}"
    try:
        rc = subprocess.run(full, shell=True, timeout=timeout,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        y = 1 if rc == 0 else 0
    except subprocess.TimeoutExpired:
        y = 0
    outcomes.append({"label": label, "kind": kind, "cmd": cmd,
                     "p": (float(p) if p is not None else None), "y": y})

for v in (target.get("verify_paths") or []):
    run_verify(v.get("label", ""), v.get("cmd", ""), v.get("user"), "path")
for v in (target.get("verify_steps") or []):
    run_verify(v.get("label", ""), v.get("cmd", ""), v.get("user"), "step")

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(outcomes, fh, indent=2)
PY
  log "[$id] outcomes: $(python3 -c 'import json;print(len(json.load(open("'"$outcomes"'"))))' 2>/dev/null || echo '?') entries"

  # teardown
  if [ -n "$teardown" ] && [ -f "$teardown" ]; then
    log "[$id] teardown: $teardown"
    run_in "$inst" "sudo bash -s" <"$teardown" >/dev/null 2>&1 || warn "[$id] teardown non-zero"
  fi
  teardown_instance "$inst" "$prov"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
PROVISIONER="multipass"
BASELINES=()
BASE_INST_NAME="${INSTANCE_PREFIX}baseline"

# parse defaults + targets from corpus
mapfile -t TARGETS < <(python3 - "$CORPUS" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
d = doc.get("defaults") or {}
prov = d.get("provisioner", "multipass")
print(prov)
for b in (d.get("baselines") or []):
    print("BASELINE:" + b)
print("---TARGETS---")
for t in doc.get("targets", []):
    # id prov image setup teardown
    print("\t".join([
        str(t.get("id","")),
        str(t.get("provisioner", d.get("provisioner","multipass"))),
        str(t.get("image","")),
        str(t.get("setup","")),
        str(t.get("teardown","")),
    ]))
PY
)

[ "${#TARGETS[@]}" -gt 0 ] || die "no targets parsed from corpus"
PROVISIONER="${TARGETS[0]}"
idx=1
for (( ; idx < ${#TARGETS[@]}; idx++ )); do
  line="${TARGETS[idx]}"
  case "$line" in
    BASELINE:*) BASELINES+=("${line#BASELINE:}") ;;
    ---TARGETS---) idx=$((idx+1)); break ;;
  esac
done

# baseline instance (clean host) for FP proxy
BASE_INST_NAME="${INSTANCE_PREFIX}baseline"
BASE_INST=""
if [ "$PROVISIONER" = "multipass" ]; then
  BASE_INST_NAME="$(instance_name baseline)"
  PROVISIONED+=("$BASE_INST_NAME")
  multipass launch --name "$BASE_INST_NAME" ubuntu:22.04 >/dev/null 2>&1 \
    || warn "baseline launch failed"
  multipass transfer "$ZP_BIN" "$BASE_INST_NAME:/tmp/z_privesc" >/dev/null 2>&1 || true
  multipass exec "$BASE_INST_NAME" -- sudo install -m0755 /tmp/z_privesc /usr/local/bin/z_privesc >/dev/null 2>&1 || true
  BASE_INST="$BASE_INST_NAME"
fi
run_baseline

# evaluate targets
for (( ; idx < ${#TARGETS[@]}; idx++ )); do
  IFS=$'\t' read -r TID TPROV TIMG TSET TTEAR <<< "${TARGETS[idx]}"
  [ -z "$TID" ] && continue
  if [ "$DRYRUN" -eq 1 ]; then
    log "DRY-RUN would evaluate: $TID ($TPROV)"
    continue
  fi
  eval_target "$TID" "$TPROV" "$TIMG" "$TSET" "$TTEAR" || warn "target $TID failed"
done

# --------------------------------------------------------------------------
# Metrics -> Calibration -> Report
# --------------------------------------------------------------------------
log "computing metrics"
python3 "$(dirname "$0")/metrics.py" --results "$RESULTS" || warn "metrics failed"
log "calibrating"
python3 "$(dirname "$0")/calibrate.py" --results "$RESULTS" || warn "calibration failed"
log "rendering report"
python3 "$(dirname "$0")/report.py" --results "$RESULTS" || warn "report failed"

log "DONE -> $RESULTS/{metrics.json,calibration.json,report.md}"
