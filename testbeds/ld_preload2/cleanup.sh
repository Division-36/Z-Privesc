#!/bin/sh
# testbeds/ld_preload2/cleanup.sh - remove the world-writable ld.so.conf drop-in.
set -e
rm -f /etc/ld.so.conf.d/zprivesc-pre2.conf
echo "ld-preload2 removed"
