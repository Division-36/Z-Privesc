#!/bin/sh
# testbeds/service/cleanup.sh - remove the world-writable systemd unit.
set -e
rm -f /etc/systemd/system/zprivesc-weak.service
echo "service testbed removed"
