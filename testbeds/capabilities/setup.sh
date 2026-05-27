#!/bin/sh
# testbeds/capabilities/setup.sh - grant a powerful capability to a binary.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
SRC=$(command -v python3 || echo /usr/bin/python3)
[ -x "$SRC" ] || { echo "no python3 found" >&2; exit 1; }
cp -f "$SRC" /tmp/python3-cap
chown root:root /tmp/python3-cap
setcap cap_setuid,cap_setgid,cap_dac_override+ep /tmp/python3-cap
echo "capabilities testbed ready: /tmp/python3-cap"
