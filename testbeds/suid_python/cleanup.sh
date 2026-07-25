#!/bin/sh
# testbeds/suid_python/cleanup.sh - remove the SUID python3 binary.
set -e
rm -f /home/ubuntu/zptest/python3-suid
rmdir /home/ubuntu/zptest 2>/dev/null || true
echo "suid-python removed"
