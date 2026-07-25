#!/bin/sh
# testbeds/sudoers_cmd/setup.sh - add a NOPASSWD sudoers drop-in for ONE command.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/zprivesc-cmd <<'EOF'
ALL ALL=(ALL) NOPASSWD: /usr/bin/id
EOF
chmod 0440 /etc/sudoers.d/zprivesc-cmd
echo "sudoers-cmd testbed ready: /etc/sudoers.d/zprivesc-cmd"
