#!/bin/sh
# testbeds/groups/cleanup.sh - remove the user from the docker group.
set -e
U=$(id -un)
gpasswd -d "$U" docker 2>/dev/null || true
echo "groups testbed removed"
