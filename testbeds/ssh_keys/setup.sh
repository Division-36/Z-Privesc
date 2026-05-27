#!/bin/sh
# testbeds/ssh_keys/setup.sh - create a world-readable SSH private key.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /root/.ssh
cp -f /etc/passwd /root/.ssh/id_rsa
chmod 0644 /root/.ssh/id_rsa
echo "ssh_keys testbed ready: /root/.ssh/id_rsa (mode 0644)"
