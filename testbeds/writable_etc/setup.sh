#!/bin/sh
# testbeds/writable_etc/setup.sh - mark a sudoers drop-in world-writable.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/sudoers.d
cp -f /etc/sudoers /etc/sudoers.d/zprivesc-weak
chmod 0666 /etc/sudoers.d/zprivesc-weak
echo "writable_etc testbed ready"
