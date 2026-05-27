#!/bin/sh
# testbeds/ssh_keys/cleanup.sh - remove the world-readable SSH key.
set -e
rm -f /root/.ssh/id_rsa
echo "ssh_keys testbed removed"
