#!/bin/sh
# testbeds/writable_etc/cleanup.sh
set -e
rm -f /etc/sudoers.d/zprivesc-weak
echo "writable_etc testbed removed"
