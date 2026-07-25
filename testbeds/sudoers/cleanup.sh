#!/bin/sh
# testbeds/sudoers/cleanup.sh - remove the NOPASSWD sudoers drop-in.
set -e
rm -f /etc/sudoers.d/zprivesc-nopasswd
echo "sudoers testbed removed"
