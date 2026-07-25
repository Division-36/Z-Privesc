#!/bin/sh
# testbeds/service2/cleanup.sh - remove the world-writable systemd unit.
set -e
rm -f /etc/systemd/system/zprivesc-svc2.service
echo "service2 removed"
