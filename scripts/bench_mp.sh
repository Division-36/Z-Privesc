#!/bin/bash
# Real benchmark data collector for Z-Privesc (runs inside a Linux VM, e.g. multipass)
# Writes machine-readable JSON into benchmarks/data/ from a clean build + full scan.
set -e
cd "$(dirname "$0")/.."

OUT_DIR=benchmarks/data
mkdir -p "$OUT_DIR"

now() { date +%s.%N; }
elapsed() { python3 -c "import time;print('%.4f'%(time.time()-$1))" 2>/dev/null || echo '0'; }

echo '==> Collecting environment'
cat > "$OUT_DIR/environment.json" <<JSON
{
  "host": "$(uname -n)",
  "kernel": "$(uname -r)",
  "arch": "$(uname -m)",
  "os": "$(. /etc/os-release 2>/dev/null; echo $PRETTY_NAME)",
  "gcc": "$(gcc --version | head -1)",
  "nproc": $(nproc),
  "mem_mb": $(free -m | awk '/Mem:/{print $2}'),
  "date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "build_id": "$(make -s build-id 2>/dev/null || echo unknown)"
}
JSON

echo '==> Build timing (dynamic)'
t0=$(now)
make clean >/dev/null 2>&1
make -j"$(nproc)" >/dev/null 2>&1
dyn_time=$(elapsed "$t0")
dyn_size=$(stat -c %s build/bin/z_privesc)

echo '==> Static build timing'
t0=$(now)
make static >/dev/null 2>&1
static_time=$(elapsed "$t0")
static_size=$(stat -c %s build/bin/z_privesc)
strip build/bin/z_privesc 2>/dev/null
stripped_size=$(stat -c %s build/bin/z_privesc)

cat > "$OUT_DIR/build.json" <<JSON
{
  "dynamic_build_time_s": $dyn_time,
  "dynamic_binary_bytes": $dyn_size,
  "static_build_time_s": $static_time,
  "static_binary_bytes": $static_size,
  "stripped_static_bytes": $stripped_size
}
JSON

echo '==> Run all probes individually and time each'
PROBES="suid writable_path capabilities writable_etc docker_socket polkit world_writable kernel_vuln cron sudoers ssh_keys groups service kernel_hardening process nfs ld_preload"
echo "[" > "$OUT_DIR/probe-timings.json"
first=1
for p in $PROBES; do
  t0=$(now)
  out=$(./build/bin/z_privesc --probe="$p" --json --quiet 2>/dev/null || true)
  dt=$(elapsed "$t0")
  findings=$(echo "$out" | python3 -c "import sys,json;
try:
    d=json.load(sys.stdin)
    prs=d.get('probes',[])
    print(sum(len(pr.get('findings',[])) for pr in prs))
except Exception:
    print(0)" 2>/dev/null || echo 0)
  if [ $first -eq 0 ]; then echo "," >> "$OUT_DIR/probe-timings.json"; fi
  first=0
  cat >> "$OUT_DIR/probe-timings.json" <<JSON
  { "probe": "$p", "time_s": $dt, "findings": $findings }
JSON
done
echo "]" >> "$OUT_DIR/probe-timings.json"

echo '==> Full --all run timing'
t0=$(now)
./build/bin/z_privesc --all --json --quiet >/dev/null 2>&1 || true
all_time=$(elapsed "$t0")

echo '==> Unit test suite timing'
t0=$(now)
make clean >/dev/null 2>&1
make test >/tmp/zp_test.log 2>&1 || true
test_time=$(elapsed "$t0")
passed=$(grep -c 'OK ' /tmp/zp_test.log)
failed=$(grep -c 'FAIL' /tmp/zp_test.log)
skipped=$(grep -c 'SKIP' /tmp/zp_test.log)
total=$(grep -c '^\[' /tmp/zp_test.log)

cat > "$OUT_DIR/test-results.json" <<JSON
{
  "total_cases": $total,
  "passed": $passed,
  "failed": $failed,
  "skipped": $skipped,
  "suite_time_s": $test_time
}
JSON

cat > "$OUT_DIR/summary.json" <<JSON
{
  "dynamic_build_time_s": $dyn_time,
  "static_build_time_s": $static_time,
  "full_scan_time_s": $all_time,
  "test_suite_time_s": $test_time,
  "tests_passed": $passed,
  "tests_failed": $failed,
  "tests_skipped": $skipped
}
JSON

echo '==> DONE'
echo "Dynamic build: $dyn_time s, $dyn_size bytes"
echo "Static build: $static_time s, $static_size bytes"
echo "Full scan: $all_time s"
echo "Test suite: $test_time s ($passed pass / $failed fail / $skipped skip)"
