#!/bin/sh
# testbeds/capabilities/cleanup.sh
set -e
rm -f /home/ubuntu/zptest/python3-cap
rmdir /home/ubuntu/zptest 2>/dev/null || true
echo "capabilities testbed removed"
