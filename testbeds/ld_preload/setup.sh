#!/bin/sh
# testbeds/ld_preload/setup.sh - create a world-writable ld.so.conf drop-in.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/ld.so.conf.d
echo "/tmp" > /etc/ld.so.conf.d/zprivesc-weak.conf
chmod 0666 /etc/ld.so.conf.d/zprivesc-weak.conf
echo "ld_preload testbed ready: /etc/ld.so.conf.d/zprivesc-weak.conf (mode 0666)"
