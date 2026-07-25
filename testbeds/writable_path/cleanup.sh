#!/bin/sh
# testbeds/writable_path/cleanup.sh - remove the evil PATH entry.
set -e
rm -rf /tmp/evil-path /tmp/evil-path.trojan
grep -v '^PATH=/tmp/evil-path' /etc/environment > /etc/environment.tmp 2>/dev/null && mv /etc/environment.tmp /etc/environment || rm -f /etc/environment.tmp
unset PATH
echo "writable_path testbed removed"
