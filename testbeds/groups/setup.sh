#!/bin/sh
# testbeds/groups/setup.sh - add the current user to the docker group.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
U=$(id -un)
groupadd -f docker
usermod -aG docker "$U" || true
id "$U"
echo "groups testbed ready: $U added to docker"
