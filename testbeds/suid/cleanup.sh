#!/bin/sh
# testbeds/suid/cleanup.sh - remove the SUID binary.
set -e
rm -f /tmp/bash-root-suid
echo "suid testbed removed"
