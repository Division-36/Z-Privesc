#!/bin/sh
# testbeds/world_writable/setup.sh - create a world-writable sensitive file.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
touch /etc/weak-config
chmod 0666 /etc/weak-config
echo "world_writable testbed ready"
