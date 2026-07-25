#!/bin/sh
# testbeds/sudoers/setup.sh - add a NOPASSWD sudoers drop-in.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/zprivesc-nopasswd <<'EOF'
ALL ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 /etc/sudoers.d/zprivesc-nopasswd
echo "sudoers testbed ready: /etc/sudoers.d/zprivesc-nopasswd"
