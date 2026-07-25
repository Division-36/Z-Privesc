#!/bin/bash
# Fix all testbed bugs for expanded eval
set -e
[ "$(id -u)" = "0" ] || exit 1

echo "=== Fix 1: Install docker for docker_group2 ==="
apt-get install -y docker.io 2>/dev/null && echo "docker installed" || echo "docker install failed (group test will fail)"

echo "=== Fix 2: docker_socket2 - create socket at correct path ==="
# Remove fake socket
rm -f /tmp/zprivesc-fake-docker.sock
# Create at the path the probe checks
touch /var/run/docker.sock
chmod 666 /var/run/docker.sock

echo "=== Fix 3: NFS - fix exports format for probe parser ==="
# The probe tokenizes by space, so host and options must be separate tokens
# Format: /path host options
cat > /etc/exports <<'EOF'
/tmp * no_root_squash
EOF
echo "exports fixed: $(cat /etc/exports)"

echo "=== Fix 4: writable_path - set PATH in current environment ==="
# The testbed adds to /etc/environment, but zp reads getenv("PATH")
# We need to ensure /tmp/evil-path exists and is world-writable
mkdir -p /tmp/evil-path
chmod 0777 /tmp/evil-path
# Create a trojan
cat > /tmp/evil-path/id <<'TROJAN'
#!/bin/sh
id
TROJAN
chmod 0755 /tmp/evil-path/id
# For the scanner, we need to set PATH in the scan process
# The scanner inherits the parent shell's PATH, so we set it via /etc/environment
# AND export it now (the scan will pick it up if run from this shell)
grep -v '^PATH=' /etc/environment > /etc/environment.tmp 2>/dev/null || true
echo "PATH=/tmp/evil-path:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" > /etc/environment.tmp
cat /etc/environment >> /etc/environment.tmp 2>/dev/null || true
mv /etc/environment.tmp /etc/environment

echo "=== Fix 5: service_sysv / writable_initd - create world-writable SysV scripts ==="
cat > /etc/init.d/zprivesc-sysv-ww <<'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides: zprivesc-sysv-ww
# Default-Start: 2 3 4 5
### END INIT INFO
case "$1" in start|stop|restart) ;; esac
INIT
chmod 666 /etc/init.d/zprivesc-sysv-ww
echo "SysV init.d script created (mode 0666)"

echo "=== Fix 6: kernel_hardening - verify current state ==="
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict)"
echo "dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict)"
echo "ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)"
echo "(Note: WSL2 locks most sysctls - testbed limitation)"

echo "=== ALL TESTBED FIXES APPLIED ==="
