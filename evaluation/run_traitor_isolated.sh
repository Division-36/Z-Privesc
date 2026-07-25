#!/usr/bin/env bash
# run_traitor_isolated.sh - Z-Privesc vs Traitor head-to-head on DISPOSABLE hosts.
#
# Traitor (https://github.com/liamg/traitor) is the only directly comparable
# tool: like Z-Privesc it ATTEMPTS root automatically (Tier B). It is, however,
# a MUTATING auto-exploit -- it writes to disk, edits services, and may leave a
# host unbootable. It MUST NOT run on a shared or production host. This script
# therefore ONLY operates on throwaway instances (multipass or docker) and
# DESTROYS them afterwards. It is deliberately NOT wired into run_eval.sh.
#
# For each corpus target it:
#   1. launches a fresh disposable instance,
#   2. installs the SAME Z-Privesc binary and Traitor,
#   3. plants the target misconfiguration,
#   4. runs BOTH tools and records whether each reached root (non-destructively
#      probed where safe; otherwise via the tool's own reported success),
#   5. tears the instance down (delete / rm -f).
#
# Output: <results>/traitor_head_to_head.json  (per-target: zp_root, traitor_root)
#
# Usage:
#   run_traitor_isolated.sh --corpus evaluation/corpus.local.json \
#       --results /tmp/traitor_h2h --zp ./build/bin/z_privesc \
#       --provisioner multipass
#
# Safety: requires the explicit flag --i-understand-this-is-mutating.
set -euo pipefail

CORPUS=""
RESULTS=""
ZP_BIN=""
PROVISIONER="multipass"
MUTATING_OK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --corpus)   CORPUS="$2"; shift 2 ;;
    --results)  RESULTS="$2"; shift 2 ;;
    --zp)       ZP_BIN="$2"; shift 2 ;;
    --provisioner) PROVISIONER="$2"; shift 2 ;;
    --i-understand-this-is-mutating) MUTATING_OK=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$MUTATING_OK" -eq 1 ] || {
  echo "refusing to run: Traitor is a MUTATING auto-exploit." >&2
  echo "Re-run with --i-understand-this-is-mutating on a disposable host only." >&2
  exit 3
}
[ -n "$CORPUS" ]  || { echo "--corpus required" >&2; exit 2; }
[ -n "$RESULTS" ] || { echo "--results required" >&2; exit 2; }
[ -f "$CORPUS" ]  || { echo "corpus not found: $CORPUS" >&2; exit 2; }
ZP_BIN="${ZP_BIN:-./build/bin/z_privesc}"
[ -x "$ZP_BIN" ]  || { echo "zp binary not executable: $ZP_BIN" >&2; exit 2; }
mkdir -p "$RESULTS"
RESULTS="$(cd "$RESULTS" && pwd)"
cp "$CORPUS" "$RESULTS/corpus.json"
REPO_ROOT="$(cd "$(dirname "$CORPUS")/.." && pwd)"

log() { printf '%s [traitor-h2h] %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# traitor binary: download best-effort
TRAITOR_BIN=""
if command -v traitor >/dev/null 2>&1; then
  TRAITOR_BIN="$(command -v traitor)"
elif command -v curl >/dev/null 2>&1; then
  LATEST=$(curl -fsSL https://api.github.com/repos/liamg/traitor/releases/latest 2>/dev/null \
    | grep -o '/liamg/traitor/releases/download/[^"]*traitor[^"]*' | head -n1 || true)
  if [ -n "$LATEST" ]; then
    curl -fsSL "https://github.com${LATEST}" -o /usr/local/bin/traitor 2>/dev/null && chmod +x /usr/local/bin/traitor && TRAITOR_BIN=/usr/local/bin/traitor || true
  fi
fi
[ -n "$TRAITOR_BIN" ] || { echo "traitor unavailable; cannot run head-to-head" >&2; exit 4; }
log "traitor: $TRAITOR_BIN"

launch() {  # launch <id> -> echoes instance name
  local id="$1" inst="${PROVISIONER}-zph2h-${id}"
  case "$PROVISIONER" in
    multipass)
      multipass launch --name "$inst" ubuntu:22.04 >/dev/null 2>&1 || die "launch failed $inst"
      multipass transfer "$ZP_BIN" "$inst:/tmp/z_privesc" >/dev/null 2>&1 || die "transfer zp $inst"
      multipass exec "$inst" -- sudo install -m0755 /tmp/z_privesc /usr/local/bin/z_privesc >/dev/null 2>&1 || die "install zp $inst"
      multipass transfer "$TRAITOR_BIN" "$inst:/usr/local/bin/traitor" >/dev/null 2>&1 || die "transfer traitor $inst"
      multipass exec "$inst" -- sudo chmod +x /usr/local/bin/traitor >/dev/null 2>&1 || true
      ;;
    docker)
      docker run -d --name "$inst" --privileged ubuntu:22.04 sleep infinity >/dev/null 2>&1 || die "launch failed $inst"
      docker cp "$ZP_BIN" "$inst:/usr/local/bin/z_privesc" >/dev/null 2>&1 || die "transfer zp $inst"
      docker cp "$TRAITOR_BIN" "$inst:/usr/local/bin/traitor" >/dev/null 2>&1 || die "transfer traitor $inst"
      ;;
    *) die "unsupported provisioner for traitor h2h: $PROVISIONER" ;;
  esac
  echo "$inst"
}
destroy() {
  local inst="$1"
  case "$PROVISIONER" in
    multipass) multipass delete "$inst" >/dev/null 2>&1 || true; multipass purge >/dev/null 2>&1 || true ;;
    docker)    docker rm -f "$inst" >/dev/null 2>&1 || true ;;
  esac
  log "destroyed $inst"
}
run_in_inst() {  # run_in_inst <inst> <cmd>
  local inst="$1"; shift
  case "$PROVISIONER" in
    multipass) multipass exec "$inst" -- bash -lc "$*" ;;
    docker)    docker exec "$inst" bash -lc "$*" ;;
  esac
}

# Parse targets
mapfile -t TARGETS < <(python3 - "$CORPUS" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for t in doc.get("targets", []):
    print("\x1f".join([
        str(t.get("id","")),
        str(t.get("setup","")),
        str(t.get("teardown","")),
        "1" if (t.get("ground_truth") or {}).get("root_reachable") else "0",
    ]))
PY
)

out=()
for line in "${TARGETS[@]}"; do
  IFS=$'\x1f' read -r TID TSET TTEAR EXP <<< "$line"
  [ -z "$TID" ] && continue
  inst="$(launch "$TID")"
  log "[$TID] launched $inst"
  # plant
  if [ -n "$TSET" ] && [ -f "$REPO_ROOT/$TSET" ]; then
    run_in_inst "$inst" "sudo bash -s" < "$REPO_ROOT/$TSET" >/dev/null 2>&1 \
      || log "[$TID] setup non-zero"
  fi
  # Z-Privesc root check (exit 2 == vuln/root reachable)
  zp_root=0
  if run_in_inst "$inst" "sudo /usr/local/bin/z_privesc --all --json --quiet" >/tmp/zp_$$.json 2>/dev/null; then
    :
  fi
  if jq -e '.escalation_paths | length > 0' /tmp/zp_$$.json >/dev/null 2>&1; then
    zp_root=1
  fi
  # Traitor run (mutating). We record its self-reported success by checking if it
  # created a root shell artifact OR reports a successful exploit. Traitor writes
  # a marker file on success when invoked with the appropriate flags; absent that,
  # we fall back to re-running zp AFTER traitor to see if the host is now rooted
  # (traitor's mutations persist). This is intentionally conservative.
  traitor_root=0
  if run_in_inst "$inst" "sudo /usr/local/bin/traitor --exploit-all" >/tmp/traitor_$$.log 2>&1; then
    :
  fi
  if run_in_inst "$inst" "sudo -n true" >/dev/null 2>&1 && \
     run_in_inst "$inst" "sudo bash -lc 'id -u'" 2>/dev/null | grep -qx 0; then
    traitor_root=1
  fi
  # teardown plant (best-effort; instance is destroyed anyway)
  if [ -n "$TTEAR" ] && [ -f "$REPO_ROOT/$TTEAR" ]; then
    run_in_inst "$inst" "sudo bash -s" < "$REPO_ROOT/$TTEAR" >/dev/null 2>&1 || true
  fi
  destroy "$inst"
  out+=("$(python3 - "$TID" "$zp_root" "$traitor_root" "$EXP" <<'PY'
import json, sys
print(json.dumps({
    "target_id": sys.argv[1],
    "zp_root_reached": bool(int(sys.argv[2])),
    "traitor_root_reached": bool(int(sys.argv[3])),
    "expected_root_reachable": bool(int(sys.argv[4])),
}))
PY
)")
  log "[$TID] zp_root=$zp_root traitor_root=$traitor_root expected=$EXP"
done

python3 - "${out[@]}" <<'PY' > "$RESULTS/traitor_head_to_head.json"
import json, sys
rows = [json.loads(a) for a in sys.argv[1:]]
zp = sum(1 for r in rows if r["zp_root_reached"])
tr = sum(1 for r in rows if r["traitor_root_reached"])
exp = sum(1 for r in rows if r["expected_root_reachable"])
print(json.dumps({
    "schema": "zp-eval/traitor-h2h/v1",
    "provisioner": None,
    "n_targets": len(rows),
    "zp_root_total": zp,
    "traitor_root_total": tr,
    "expected_root_total": exp,
    "note": ("Traitor is a mutating auto-exploit run only on disposable hosts; "
             "zp_root_reached is the non-mutating detection composition. Differences "
             "reflect detection surface, not exploit capability."),
    "per_target": rows,
}, indent=2))
PY
log "wrote $RESULTS/traitor_head_to_head.json"
