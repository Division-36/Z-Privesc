#!/bin/sh
# testbeds/suid/cleanup.sh - remove the SUID binary.
set -e
rm -f /home/ubuntu/zptest/bash-root-suid
rmdir /home/ubuntu/zptest 2>/dev/null || true
echo "suid testbed removed"
