#!/bin/sh
# testbeds/writable_path/setup.sh - inject a world-writable PATH entry.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /tmp/evil-path
chmod 0777 /tmp/evil-path
cat > /tmp/evil-path.trojan <<'EOF'
#!/bin/sh
id
EOF
chmod 0755 /tmp/evil-path.trojan
# Persist across shells by appending to /etc/environment
grep -v '^PATH=' /etc/environment > /etc/environment.tmp 2>/dev/null || true
echo "PATH=/tmp/evil-path:$PATH" >> /etc/environment
# Also export in the current shell for immediate effect
export PATH="/tmp/evil-path:$PATH"
echo "writable_path testbed ready: /tmp/evil-path (mode 0777) prepended to PATH"
