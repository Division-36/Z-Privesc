#!/bin/sh
# testbeds/docker/cleanup.sh - remove the fake docker.sock.
set -e
rm -f /var/run/docker.sock
echo "docker testbed removed"
