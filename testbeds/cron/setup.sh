#!/bin/sh
# testbeds/cron/setup.sh - create a world-writable cron job.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/cron.d
cat > /etc/cron.d/zprivesc-weak <<'EOF'
* * * * * root /tmp/cron-pwn.sh
EOF
chmod 0666 /etc/cron.d/zprivesc-weak
cat > /etc/cron.d/zprivesc-wild <<'EOF'
17 * * * * root tar czf /tmp/backup.tgz /var/log/*.log
EOF
chmod 0644 /etc/cron.d/zprivesc-wild
echo "cron testbed ready: /etc/cron.d/zprivesc-weak, /etc/cron.d/zprivesc-wild"
