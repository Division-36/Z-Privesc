#!/bin/sh
# testbeds/ssh_keys/cleanup.sh - remove the planted world-readable root key.
set -e
KEY=/root/.ssh/id_rsa
if [ -f "$KEY.pub" ]; then
  grep -v -F -x "$(cat "$KEY.pub")" /root/.ssh/authorized_keys > /tmp/zp_auth.tmp 2>/dev/null || true
  mv /tmp/zp_auth.tmp /root/.ssh/authorized_keys 2>/dev/null || true
fi
rm -f "$KEY" "$KEY.pub"
echo "ssh_keys testbed removed"
