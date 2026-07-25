#!/bin/sh
# testbeds/capabilities/setup.sh - grant a powerful capability to a binary.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
SRC=$(command -v python3 || echo /usr/bin/python3)
[ -x "$SRC" ] || { echo "no python3 found" >&2; exit 1; }
mkdir -p /home/ubuntu/zptest
cp -f "$SRC" /home/ubuntu/zptest/python3-cap
chown root:root /home/ubuntu/zptest/python3-cap
setcap cap_setuid,cap_setgid,cap_dac_override+ep /home/ubuntu/zptest/python3-cap
echo "capabilities testbed ready: /home/ubuntu/zptest/python3-cap"
