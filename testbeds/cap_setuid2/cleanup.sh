#!/bin/sh
# testbeds/cap_setuid2/cleanup.sh - remove the capability binary.
set -e
rm -f /home/ubuntu/zptest/python3-cap2
rmdir /home/ubuntu/zptest 2>/dev/null || true
echo "cap-setuid2 removed"
