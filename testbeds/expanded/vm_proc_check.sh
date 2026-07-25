#!/bin/bash
echo "=== Process check ==="
pgrep -a ww-root-proc || echo "no ww-root-proc process"
for pid in $(pgrep ww-root-proc); do
  echo "PID=$pid"
  ls -la /proc/$pid/exe 2>/dev/null
  stat -c '%a %U %G' /proc/$pid/exe 2>/dev/null
  cat /proc/$pid/status 2>/dev/null | grep -E 'Uid|Name'
done
echo "=== File check ==="
ls -la /tmp/ww-root-proc 2>/dev/null
stat -c '%a %U %G' /tmp/ww-root-proc 2>/dev/null
echo "=== /proc scan sample ==="
ls /proc/ | head -20
echo "=== Running as ==="
whoami; id
