#!/bin/sh
# testbeds/nfs/cleanup.sh - restore /etc/exports.
set -e
if [ -f /etc/exports.zprivesc-bak ]; then
  mv -f /etc/exports.zprivesc-bak /etc/exports
else
  rm -f /etc/exports
fi
echo "nfs testbed removed"
