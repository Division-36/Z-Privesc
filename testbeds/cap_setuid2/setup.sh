#!/bin/sh
# testbeds/cap_setuid2/setup.sh - grant cap_setuid to a second binary (variant).
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
SRC=$(command -v python3 || echo /usr/bin/python3)
[ -x "$SRC" ] || { echo "no python3 found" >&2; exit 1; }
mkdir -p /home/ubuntu/zptest
cp -f "$SRC" /home/ubuntu/zptest/python3-cap2
chown root:root /home/ubuntu/zptest/python3-cap2
setcap cap_setuid,cap_setgid+ep /home/ubuntu/zptest/python3-cap2
echo "cap-setuid2 testbed ready: /home/ubuntu/zptest/python3-cap2"
