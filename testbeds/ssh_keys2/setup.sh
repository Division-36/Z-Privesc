#!/bin/sh
# testbeds/ssh_keys2/setup.sh - plant a second world-readable root SSH private key.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
KEY=/root/.ssh/id_ed25519
mkdir -p /root/.ssh
chmod 700 /root/.ssh
rm -f "$KEY" "$KEY.pub"
ssh-keygen -t ed25519 -N '' -f "$KEY" -q -C "zprivesc-test2" >/dev/null 2>&1
chmod 0644 "$KEY"            # world-readable private key (the vulnerability)
cat "$KEY.pub" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "ssh-keys2 testbed ready: $KEY (mode 0644, world-readable root private key)"
