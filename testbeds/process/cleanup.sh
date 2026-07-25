#!/bin/sh
# testbeds/process/cleanup.sh - kill the fake process and remove the binary.
set -e
[ -f /tmp/ww-root-proc.pid ] && kill "$(cat /tmp/ww-root-proc.pid)" 2>/dev/null || true
rm -f /tmp/ww-root-proc /tmp/ww-root-proc.pid
echo "process testbed removed"
