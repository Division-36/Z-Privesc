#!/bin/sh
# testbeds/service/setup.sh - create a world-writable systemd unit.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/zprivesc-weak.service <<'EOF'
[Unit]
Description=Z-Privesc weak service

[Service]
Type=simple
User=root
ExecStart=/bin/sleep 9999

[Install]
WantedBy=multi-user.target
EOF
chmod 0666 /etc/systemd/system/zprivesc-weak.service
echo "service testbed ready: /etc/systemd/system/zprivesc-weak.service"
