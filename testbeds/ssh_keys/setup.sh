#!/bin/sh
# testbeds/ssh_keys/setup.sh - plant a world-readable root SSH private key.
# The genuine escalation (SSH in as root with the stolen key) requires a live
# sshd with root login permitted; verification of the exploit is performed
# out-of-band (the vector is a documented root escalator). This script only
# plants the detectable misconfiguration: a readable root private key.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
KEY=/root/.ssh/id_rsa
mkdir -p /root/.ssh
chmod 700 /root/.ssh
rm -f "$KEY" "$KEY.pub"
ssh-keygen -t ed25519 -N '' -f "$KEY" -q -C "zprivesc-test" >/dev/null 2>&1
chmod 0644 "$KEY"            # world-readable private key (the vulnerability)
cat "$KEY.pub" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "ssh_keys testbed ready: $KEY (mode 0644, world-readable root private key)"
