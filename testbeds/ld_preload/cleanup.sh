#!/bin/sh
# testbeds/ld_preload/cleanup.sh - remove the world-writable ld.so.conf drop-in.
set -e
rm -f /etc/ld.so.conf.d/zprivesc-weak.conf
echo "ld_preload testbed removed"
