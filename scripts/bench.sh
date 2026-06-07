#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Use Python for reliable float timing instead of bc
timer_start() {
    python3 -c "import time; print(time.time())"
}

timer_end() {
    local start=$1
    python3 -c "import time; print('%.3f' % (time.time() - $start))"
}

echo "=== Z-Privesc Benchmark Report ==="
echo "Date:       $(date -u +%Y-%m-%d)"
echo "Build ID:   $(make -s build-id 2>/dev/null || echo 'N/A')"
echo "Git SHA:    $(git rev-parse --short=8 HEAD 2>/dev/null || echo 'N/A')"
echo ""

echo "== System =="
uname -a 2>/dev/null || true
echo "GCC: $(gcc --version 2>/dev/null | head -1 || echo 'N/A')"
echo ""

echo "== Build =="
T0=$(timer_start)
make clean 2>&1 > /dev/null
make -j"$(nproc)" 2>&1 > /dev/null
echo "Build time: $(timer_end $T0)s"
BIN_SIZE=$(stat --format=%s build/bin/z_privesc 2>/dev/null || echo 0)
echo "Binary size: $BIN_SIZE bytes"

echo "== Static build =="
T0=$(timer_start)
make static 2>&1 > /dev/null
echo "Static build time: $(timer_end $T0)s"
STATIC_SIZE=$(stat --format=%s build/bin/z_privesc 2>/dev/null || echo 0)
echo "Static binary size: $STATIC_SIZE bytes"
strip build/bin/z_privesc 2>/dev/null || true
STRIPPED_SIZE=$(stat --format=%s build/bin/z_privesc 2>/dev/null || echo 0)
echo "Stripped static size: $STRIPPED_SIZE bytes"
echo ""

echo "== Unit Tests =="
T0=$(timer_start)
make clean 2>&1 > /dev/null
make test 2>&1 | tee /tmp/zp-test-out.txt
echo "Test time: $(timer_end $T0)s"
echo ""
PASSED=$(grep -c 'OK' /tmp/zp-test-out.txt 2>/dev/null || echo 0)
FAILED=$(grep -c 'FAIL' /tmp/zp-test-out.txt 2>/dev/null || echo 0)
SKIPPED=$(grep -c 'SKIP' /tmp/zp-test-out.txt 2>/dev/null || echo 0)
echo "Passed: $PASSED, Failed: $FAILED, Skipped: $SKIPPED"
echo ""

echo "== Coverage =="
make clean 2>&1 > /dev/null
make coverage 2>&1 | tail -5
echo ""

COV_FILES=$(find build/coverage -name '*.gcov' 2>/dev/null | wc -l)
echo "Coverage files: $COV_FILES"
if [ -d build/coverage ]; then
    du -sh build/coverage/
fi
