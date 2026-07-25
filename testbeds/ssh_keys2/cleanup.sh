#!/bin/sh
# testbeds/ssh_keys2/cleanup.sh - remove the world-readable root SSH private key.
set -e
rm -f /root/.ssh/id_ed25519 /root/.ssh/id_ed25519.pub
echo "ssh-keys2 removed"
