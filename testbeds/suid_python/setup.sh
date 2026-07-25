#!/bin/sh
# testbeds/suid_python/setup.sh - create a deliberately-vulnerable SUID python3.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
SRC=$(command -v python3 || echo /usr/bin/python3)
[ -x "$SRC" ] || { echo "no python3 found" >&2; exit 1; }
mkdir -p /home/ubuntu/zptest
cp -f "$SRC" /home/ubuntu/zptest/python3-suid
chown root:root /home/ubuntu/zptest/python3-suid
chmod 4755 /home/ubuntu/zptest/python3-suid
echo "suid-python testbed ready: /home/ubuntu/zptest/python3-suid"
