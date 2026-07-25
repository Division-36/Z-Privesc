#!/usr/bin/env bash
# run_eval.sh - Z-Privesc evaluation orchestrator (production-hardened).
#
# Provisions each corpus target, plants its misconfiguration, runs Z-Privesc
# (and optional baselines), verifies exploit outcomes with GENUINE,
# non-destructive root-escalation checks (or human-verified manual outcomes)
# for confidence calibration, then computes metrics, fits calibrated
# probabilities, and renders a report.
#
# CRITICAL CORRECTNESS PROPERTY
# -----------------------------
# Every automatic verify command returns exit 0 IF AND ONLY IF the escalation
# to root genuinely succeeds. Outcomes are NEVER fabricated: categories where
# safe automated verification is impractical are marked "manual" and carry a
# human-verified expected_y. This keeps the calibration data truthful.
#
# Designed to run on a control host that has `multipass` (default), `docker`,
# or SSH access to targets. All steps are idempotent and fail-closed.
#
# Usage:
#   run_eval.sh --corpus evaluation/corpus.local.json \
#               --results evaluation/results \
#               --zp ./build/bin/z_privesc
set -uo pipefail
shopt -s lastpipe 2>/dev/null || true

# --------------------------------------------------------------------------
# Configuration / logging
# --------------------------------------------------------------------------
LOG_TAG="zp-eval"
log()  { printf '%s [%-6s] %s\n' "$(date -u +%FT%TZ)" "$LOG_TAG" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }
warn() { log "WARN: $*"; }
# Validate that a zp JSON output contains the escalation_paths key (jq-free:
# some minimal hosts lack jq; python3 is always present).
_json_ok() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if "escalation_paths" in d else 1)' "$1" 2>/dev/null
}

CORPUS=""
RESULTS=""
ZP_BIN=""
TIMEOUT=300
DRYRUN=0
PRECLEAN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --corpus)   CORPUS="$2"; shift 2 ;;
    --results)  RESULTS="$2"; shift 2 ;;
    --zp)       ZP_BIN="$2"; shift 2 ;;
    --timeout)  TIMEOUT="$2"; shift 2 ;;
    --preclean) PRECLEAN=1; shift ;;
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
CORPUS_DIR="$(cd "$(dirname "$CORPUS")" && pwd)"
REPO_ROOT="$(cd "$CORPUS_DIR/.." && pwd)"
log "corpus=$CORPUS results=$RESULTS zp=$ZP_BIN timeout=$TIMEOUT"

# Defensive: a world-writable sudoers.d drop-in breaks `sudo` parsing entirely
# (every sudo invocation errors out). The harness runs as root, so it can remove
# such files directly without depending on the (possibly broken) sudo binary.
if [ "$(id -u)" -eq 0 ]; then
  find /etc/sudoers.d -maxdepth 1 -type f -perm -0002 -exec rm -f {} \; 2>/dev/null || true
fi

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
      log "ssh provisioner: target is the local control host; ensuring zp on PATH"
      install -m0755 "$ZP_BIN" /usr/local/bin/z_privesc >/dev/null 2>&1 \
        || die "install zp to /usr/local/bin failed (need write to /usr/local/bin)"
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
    ssh)       bash -lc "$*" ;;  # corpus host already is the target
    *) die "no provisioner set" ;;
  esac
}

run_check_on_inst() {
  # run_check_on_inst <instance> <fullcmd> -> echoes 0/1 success (timeout-guarded)
  # NOTE: run_in is a shell function, so `timeout` (which only execs external
  # binaries) cannot invoke it directly. Inline the provisioner command here so
  # `timeout` execs a real binary (bash/multipass/docker) that then runs run_in's
  # exact command.
  local inst="$1"; shift
  local rc=0
  local ef; ef="$(mktemp)"
  local check_cmd
  case "$PROVISIONER" in
    multipass) check_cmd=(multipass exec "$inst" -- bash -lc "$*") ;;
    docker)    check_cmd=(docker exec "$inst" bash -lc "$*") ;;
    ssh)       check_cmd=(bash -lc "$*") ;;
    *) die "no provisioner set" ;;
  esac
  if timeout "$TIMEOUT" "${check_cmd[@]}" >/dev/null 2>"$ef"; then
    rc=0
  else
    rc=$?
    [ "$rc" -eq 124 ] && warn "verify timed out (>$TIMEOUT s)"
    if [ -s "$ef" ]; then
      while IFS= read -r el; do warn "verify stderr: $el"; done < "$ef"
    fi
  fi
  rm -f "$ef"
  # success iff the check exited 0
  [ "$rc" -eq 0 ] && echo 1 || echo 0
}

teardown_instance() {
  local inst="$1" prov="$2"
  case "$prov" in
    multipass) multipass delete "$inst" >/dev/null 2>&1 || true; multipass purge >/dev/null 2>&1 || true ;;
    docker)    docker rm -f "$inst" >/dev/null 2>&1 || true ;;
    ssh)       : ;;
  esac
  local i; for i in "${!PROVISIONED[@]}"; do
    [ "${PROVISIONED[$i]}" = "$inst" ] && unset 'PROVISIONED[i]'
  done
}

# Resolve baseline-tool binaries. Each tool is downloaded (best-effort) if not
# on PATH, so the comparison suite is reproducible without manual setup. Tools
# that fail to download are warned-and-skipped; the evaluation still runs.
#
# Two comparison tiers (see benchmarks.md):
#   Tier A (read-only enumerators): linpeas, lynis, linenum, lse,
#                                     unix-privesc-check -- surface state, no
#                                     composition, no confidence.
#   Tier B (automated exploit chainers): traitor -- the only directly comparable
#                                     tool (it attempts root automatically); it is
#                                     MUTATING and is therefore NOT run on a shared
#                                     host (see paper: isolation caveat).
declare -A TOOL_BIN=()
declare -A TOOL_ARGS=()
_dl() {  # _dl <url> <dest>  -> best-effort download, chmod +x
  command -v curl >/dev/null 2>&1 || return 1
  curl -fsSL "$1" -o "$2" 2>/dev/null && chmod +x "$2" 2>/dev/null && return 0
  return 1
}
ensure_baseline_tools() {
  local t
  for t in "${BASELINES[@]:-}"; do
    [ -z "$t" ] && continue
    case "$t" in
      lynis)
        command -v lynis >/dev/null 2>&1 && TOOL_BIN["lynis"]="lynis" ;;
      linpeas)
        if command -v linpeas.sh >/dev/null 2>&1; then TOOL_BIN["linpeas"]="linpeas.sh"
        elif _dl "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" /usr/local/bin/linpeas.sh; then
          TOOL_BIN["linpeas"]=/usr/local/bin/linpeas.sh; TOOL_ARGS["linpeas"]="-q -a"
        else warn "linpeas unavailable"; fi ;;
      linenum)
        if _dl "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" /usr/local/bin/linenum.sh; then
          TOOL_BIN["linenum"]=/usr/local/bin/linenum.sh
        else warn "linenum unavailable"; fi ;;
      lse)
        if _dl "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" /usr/local/bin/lse.sh; then
          TOOL_BIN["lse"]=/usr/local/bin/lse.sh
        else warn "lse unavailable"; fi ;;
      unix-privesc-check)
        if _dl "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1.4/unix-privesc-check.tar.gz" /tmp/upc.tgz; then
          tar -xzf /tmp/upc.tgz -C /tmp >/dev/null 2>&1
          if find /tmp -name 'unix-privesc-check' -type f -exec install -m0755 {} /usr/local/bin/unix-privesc-check \; >/dev/null 2>&1; then
            TOOL_BIN["unix-privesc-check"]=/usr/local/bin/unix-privesc-check
          fi
        else warn "unix-privesc-check unavailable"; fi ;;
      traitor)
        warn "traitor is a MUTATING auto-exploit; not run automatically on a shared host (Tier-B baseline, see paper)" ;;
      *) warn "unknown baseline tool: $t" ;;
    esac
  done
}
run_baseline_tool() {
  # run_baseline_tool <tool> <outfile> <timefile>
  # For the ssh provisioner the control host IS the target, so running the tool
  # directly here is correct; for multipass/docker the same call would need to be
  # wrapped in run_in (left as future work -- those provisioners are unavailable
  # on the control host used for this evaluation).
  local tool="$1" outfile="$2" timefile="$3"
  local bin="${TOOL_BIN[$tool]:-}"
  [ -z "$bin" ] && return 0
  local t0 t1
  t0="$(date +%s.%N)"
  case "$tool" in
    lynis) ( timeout --foreground "$TIMEOUT" sudo lynis audit system --quick --no-colors >"$outfile" 2>&1 ) || warn "baseline $tool failed" ;;
    *)     ( timeout --foreground "$TIMEOUT" "$bin" ${TOOL_ARGS[$tool]:-} >"$outfile" 2>&1 ) || warn "baseline $tool failed" ;;
  esac
  t1="$(date +%s.%N)"
  awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", b-a}' >"$timefile"
}

# --------------------------------------------------------------------------
# Baseline (clean-host) run for false-positive proxy + baseline comparison
# --------------------------------------------------------------------------
run_baseline() {
  log "baseline: clean host run (no plants)"
  local out="$RESULTS/baseline_zp.json"
  # NOTE: z_privesc exits 2 (ZP_EXIT_VULN) when findings are present and 0 when
  # clean; both are valid runs. Validate the produced JSON instead of the exit code.
  run_in "$BASE_INST_NAME" "sudo /usr/local/bin/z_privesc --all --json" >"$out" 2>/dev/null || true
  if ! _json_ok "$out"; then
    warn "baseline zp run failed; FP proxy will be empty"
    echo '{"findings":[],"escalation_paths":[]}' >"$out"
  fi
  # baseline baselines (for FP comparison of the baselines themselves)
  for b in "${BASELINES[@]:-}"; do
    [ -z "$b" ] && continue
    run_baseline_tool "$b" "$RESULTS/baseline_${b}.txt" "$RESULTS/baseline_${b}_time_sec.txt"
  done
  log "baseline written: $out"
}

# --------------------------------------------------------------------------
# Per-target evaluation
# --------------------------------------------------------------------------
eval_target() {
  local id="$1" prov="$2" img="$3" setup="$4" teardown="$5"
  case "$setup" in /*) ;; *) [ -n "$setup" ] && setup="$REPO_ROOT/$setup" ;; esac
  case "$teardown" in /*) ;; *) [ -n "$teardown" ] && teardown="$REPO_ROOT/$teardown" ;; esac
  local inst; inst="$(provision "$id" "$img" "$prov")"
  local tdir="$RESULTS/$id"
  mkdir -p "$tdir"

  # plant
  if [ -n "$setup" ] && [ -f "$setup" ]; then
    log "[$id] setup: $setup"
    if ! run_in "$inst" "sudo bash -s" <"$setup" >/dev/null 2>&1; then
      warn "[$id] setup script non-zero; results may be incomplete"
    fi
  fi

  # run Z-Privesc (timed)
  log "[$id] running z_privesc"
  local t0 t1
  t0="$(date +%s.%N)"
  # NOTE: z_privesc exits 2 (ZP_EXIT_VULN) when findings are present and 0 when
  # clean; both are valid runs. Validate the produced JSON instead of the exit code.
  run_in "$inst" "sudo /usr/local/bin/z_privesc --all --json" >"$tdir/zp.json" 2>/dev/null || true
  if ! _json_ok "$tdir/zp.json"; then
    warn "[$id] zp run failed; writing empty"
    echo '{"findings":[],"escalation_paths":[]}' >"$tdir/zp.json"
  fi
  t1="$(date +%s.%N)"
  awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", b-a}' >"$tdir/scan_time_sec.txt"

  # baselines (recorded for later comparison)
  for b in "${BASELINES[@]:-}"; do
    [ -z "$b" ] && continue
    run_baseline_tool "$b" "$tdir/${b}.txt" "$tdir/${b}_time_sec.txt"
  done

  # ---- verify exploit outcomes (drives calibration) -------------------
  # 1) emit verify specs (one JSON object per line)
  python3 - "$CORPUS" "$id" >"$tdir/verify_spec.jsonl" <<'PY'
import json, sys
corpus = json.load(open(sys.argv[1]))
tid = sys.argv[2]
target = next((t for t in corpus["targets"] if t["id"] == tid), None)
if target is None:
    sys.exit(0)
for v in (target.get("verify") or []):
    spec = {
        "label": str(v.get("label", "")),
        "kind": str(v.get("kind", "step")),
        "check": str(v.get("check", "")) if not v.get("manual", False) else "",
        "as_user": str(v.get("as_user", "ubuntu")),
        "manual": bool(v.get("manual", False)),
        "expected_y": int(v.get("expected_y", 0)) if v.get("manual", False) else None,
        "notes": str(v.get("notes", "")),
    }
    print(json.dumps(spec))
PY

  # 2) execute each spec on the instance (or honor manual outcome)
  : > "$tdir/verify_rc.tsv"
  while IFS= read -r spec; do
    [ -z "$spec" ] && continue
    manual=$(printf '%s' "$spec" | python3 -c 'import json,sys; print("1" if json.loads(sys.stdin.read()).get("manual") else "0")')
    if [ "$manual" = "1" ]; then
      ey=$(printf '%s' "$spec" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("expected_y",0))')
      lab=$(printf '%s' "$spec" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["label"])')
      printf '%s\t%s\n' "$lab" "$ey" >> "$tdir/verify_rc.tsv"
      log "[$id] manual outcome label=$lab y=$ey"
    else
      check=$(printf '%s' "$spec" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("check",""))')
      as_user=$(printf '%s' "$spec" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("as_user","ubuntu"))')
      lab=$(printf '%s' "$spec" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["label"])')
      inner="sudo -u ${as_user} ${check}"
      if [ "$DRYRUN" -eq 1 ]; then
        y=0
        log "[$id] DRY-RUN verify $lab -> $inner"
      else
        y=$(run_check_on_inst "$inst" "$inner")
        log "[$id] verify $lab -> y=$y (cmd: $inner)"
      fi
      printf '%s\t%s\n' "$lab" "$y" >> "$tdir/verify_rc.tsv"
    fi
  done < "$tdir/verify_spec.jsonl"

  # 3) assemble outcomes.json (label, kind, p from zp, y, manual)
  python3 - "$tdir/zp.json" "$tdir/verify_spec.jsonl" "$tdir/verify_rc.tsv" "$tdir/outcomes.json" <<'PY'
import json, sys
zp_path, spec_path, rc_path, out_path = sys.argv[1:5]
try:
    zp = json.load(open(zp_path))
except Exception:
    zp = {}
paths = zp.get("escalation_paths") or []
def reliability_for(label):
    for p in paths:
        for s in (p.get("steps") or []):
            if s.get("technique") == label and isinstance(s.get("reliability"), (int, float)):
                return float(s["reliability"])
    return None
rc = {}
try:
    with open(rc_path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            lab, vy = line.split("\t")
            rc[lab] = int(vy)
except FileNotFoundError:
    pass
outcomes = []
with open(spec_path) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        spec = json.loads(line)
        lab = spec["label"]
        p = reliability_for(lab)
        y = rc.get(lab)
        if y is None:
            continue
        outcomes.append({
            "label": lab,
            "kind": spec.get("kind", "step"),
            "p": p,
            "y": int(y),
            "manual": bool(spec.get("manual", False)),
            "check": spec.get("check", ""),
            "as_user": spec.get("as_user", "ubuntu"),
            "notes": spec.get("notes", ""),
        })
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(outcomes, fh, indent=2)
PY

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
BASE_INST_NAME=""

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
    print("\x1f".join([
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

# baseline instance (clean host) for FP proxy + baseline comparison
BASE_INST_NAME=""
if [ "$PROVISIONER" = "multipass" ]; then
  BASE_INST_NAME="$(instance_name baseline)"
  PROVISIONED+=("$BASE_INST_NAME")
  multipass launch --name "$BASE_INST_NAME" ubuntu:22.04 >/dev/null 2>&1 \
    || warn "baseline launch failed"
  multipass transfer "$ZP_BIN" "$BASE_INST_NAME:/tmp/z_privesc" >/dev/null 2>&1 || true
  multipass exec "$BASE_INST_NAME" -- sudo install -m0755 /tmp/z_privesc /usr/local/bin/z_privesc >/dev/null 2>&1 || true
elif [ "$PROVISIONER" = "docker" ]; then
  BASE_INST_NAME="$(instance_name baseline)"
  PROVISIONED+=("$BASE_INST_NAME")
  docker run -d --name "$BASE_INST_NAME" --privileged ubuntu:22.04 sleep infinity >/dev/null 2>&1 || true
  docker cp "$ZP_BIN" "$BASE_INST_NAME:/usr/local/bin/z_privesc" >/dev/null 2>&1 || true
elif [ "$PROVISIONER" = "ssh" ]; then
  BASE_INST_NAME="__local__"   # sentinel; run_in ssh ignores the instance
  install -m0755 "$ZP_BIN" /usr/local/bin/z_privesc >/dev/null 2>&1 \
    || warn "could not install zp to /usr/local/bin for ssh baseline"
fi
ensure_baseline_tools || true
run_baseline

# optional pre-clean of every target's teardown (ensures a clean baseline start)
if [ "$PRECLEAN" -eq 1 ] && [ "$PROVISIONER" = "ssh" ]; then
  log "preclean: running teardown scripts for all targets"
  for (( j=idx; j < ${#TARGETS[@]}; j++ )); do
    IFS=$'\x1f' read -r TID TPROV TIMG TSET TTEAR <<< "${TARGETS[j]}"
    [ -z "$TTEAR" ] && continue
    case "$TTEAR" in /*) ;; *) TTEAR="$REPO_ROOT/$TTEAR" ;; esac
    [ -f "$TTEAR" ] && run_in "$BASE_INST_NAME" "sudo bash -s" <"$TTEAR" >/dev/null 2>&1 || true
  done
fi

# evaluate targets
for (( ; idx < ${#TARGETS[@]}; idx++ )); do
  IFS=$'\x1f' read -r TID TPROV TIMG TSET TTEAR <<< "${TARGETS[idx]}"
  [ -z "$TID" ] && continue
  if [ "$DRYRUN" -eq 1 ]; then
    log "DRY-RUN would evaluate: $TID ($TPROV)"
    continue
  fi
  eval_target "$TID" "$TPROV" "$TIMG" "$TSET" "$TTEAR" || warn "target $TID failed"
done

# --------------------------------------------------------------------------
# Metrics -> Calibration -> Baselines -> Report
# --------------------------------------------------------------------------
log "computing metrics"
python3 "$(dirname "$0")/metrics.py" --results "$RESULTS" || warn "metrics failed"
log "calibrating"
python3 "$(dirname "$0")/calibrate.py" --results "$RESULTS" || warn "calibration failed"
log "baseline comparison"
python3 "$(dirname "$0")/baselines.py" --results "$RESULTS" || warn "baseline comparison failed"
log "rendering report"
python3 "$(dirname "$0")/report.py" --results "$RESULTS" || warn "report failed"

log "DONE -> $RESULTS/{metrics.json,calibration.json,baselines.json,report.md}"
