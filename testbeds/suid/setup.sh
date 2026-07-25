#!/bin/sh
# testbeds/suid/setup.sh - create a deliberately-vulnerable SUID binary.
# Run as root.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
SRC=$(command -v bash || echo /bin/bash)
[ -x "$SRC" ] || { echo "no bash found" >&2; exit 1; }
mkdir -p /home/ubuntu/zptest
cp -f "$SRC" /home/ubuntu/zptest/bash-root-suid
chown root:root /home/ubuntu/zptest/bash-root-suid
chmod 4755 /home/ubuntu/zptest/bash-root-suid
echo "suid testbed ready: /home/ubuntu/zptest/bash-root-suid"
