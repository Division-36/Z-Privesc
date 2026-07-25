#!/bin/sh
# testbeds/service2/setup.sh - create a second world-writable systemd unit.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/zprivesc-svc2.service <<'EOF'
[Unit]
Description=Z-Privesc weak service 2

[Service]
Type=simple
User=root
ExecStart=/bin/sleep 9999

[Install]
WantedBy=multi-user.target
EOF
chmod 0666 /etc/systemd/system/zprivesc-svc2.service
echo "service2 testbed ready: /etc/systemd/system/zprivesc-svc2.service"
