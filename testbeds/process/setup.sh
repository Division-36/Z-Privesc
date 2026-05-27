#!/bin/sh
# testbeds/process/setup.sh - create a fake world-writable root-owned process.
# In WSL2 we cannot set SUID on a script. We make a small ELF-like file
# and run it as root so /proc/<pid>/exe resolves to a ww file.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
cp -f /bin/sleep /tmp/ww-root-proc
chmod 0666 /tmp/ww-root-proc
chown root:root /tmp/ww-root-proc
/tmp/ww-root-proc 9999 &
PID=$!
echo "$PID" > /tmp/ww-root-proc.pid
echo "process testbed ready: pid=$PID /tmp/ww-root-proc (mode 0666)"
