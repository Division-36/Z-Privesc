#!/bin/sh
# testbeds/ld_preload2/setup.sh - create a second world-writable ld.so.conf drop-in.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/ld.so.conf.d
echo "/tmp" > /etc/ld.so.conf.d/zprivesc-pre2.conf
chmod 0666 /etc/ld.so.conf.d/zprivesc-pre2.conf
echo "ld-preload2 testbed ready: /etc/ld.so.conf.d/zprivesc-pre2.conf (mode 0666)"
