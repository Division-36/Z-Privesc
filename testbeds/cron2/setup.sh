#!/bin/sh
# testbeds/cron2/setup.sh - create a second world-writable cron job.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/cron.d
cat > /etc/cron.d/zprivesc-cron2 <<'EOF'
* * * * * root /tmp/cron2-pwn.sh
EOF
chmod 0666 /etc/cron.d/zprivesc-cron2
echo "cron2 testbed ready: /etc/cron.d/zprivesc-cron2"
