#!/bin/sh
# testbeds/sudoers_cmd/cleanup.sh - remove the NOPASSWD command drop-in.
set -e
rm -f /etc/sudoers.d/zprivesc-cmd
echo "sudoers-cmd removed"
