#!/bin/bash
# Plant expanded testbeds in the RIGHT paths (not in /root/zp/testbeds/)
set -e
[ "$(id -u)" = "0" ] || exit 1

# SUID variants
cp /usr/bin/nmap /tmp/suid-nmap 2>/dev/null && chmod 4755 /tmp/suid-nmap && chown root:root /tmp/suid-nmap
cp /usr/bin/find /tmp/suid-find && chmod 4755 /tmp/suid-find && chown root:root /tmp/suid-find
cp /usr/bin/vim.tiny /tmp/suid-vim 2>/dev/null || cp /usr/bin/vi /tmp/suid-vim 2>/dev/null || cp /usr/bin/nano /tmp/suid-vim
chmod 4755 /tmp/suid-vim; chown root:root /tmp/suid-vim
cp /usr/bin/env /tmp/suid-env && chmod 4755 /tmp/suid-env && chown root:root /tmp/suid-env

# Capability variants
cp /usr/bin/python3 /tmp/python3-cap-dr 2>/dev/null || cp /usr/bin/cat /tmp/python3-cap-dr
setcap cap_dac_read_search+ep /tmp/python3-cap-dr 2>/dev/null || true
cp /usr/bin/python3 /tmp/python3-cap-sysadmin 2>/dev/null || cp /usr/bin/cat /tmp/python3-cap-sysadmin
setcap cap_sys_admin+ep /tmp/python3-cap-sysadmin 2>/dev/null || true

# Writable cron
echo "* * * * * root /tmp/evil-cron.sh" > /etc/cron.d/zprivesc-weak-cron3
chmod 666 /etc/cron.d/zprivesc-weak-cron3
echo '#!/bin/sh' > /tmp/evil-cron.sh; chmod 755 /tmp/evil-cron.sh

# Writable init.d
cat > /etc/init.d/zprivesc-weak-sysv << 'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides: zprivesc-weak-sysv
# Default-Start: 2 3 4 5
### END INIT INFO
case "$1" in start|stop|restart) ;; esac
INIT
chmod 666 /etc/init.d/zprivesc-weak-sysv

# Sudoers NOPASSWD
echo "ubuntu ALL=(ALL) NOPASSWD: /usr/bin/id" > /etc/sudoers.d/92-zprivesc-noauth
chmod 440 /etc/sudoers.d/92-zprivesc-noauth

# Docker group
usermod -aG docker ubuntu 2>/dev/null || usermod -aG docker kali 2>/dev/null || true

# Docker socket
cp /dev/null /tmp/zprivesc-fake-docker.sock 2>/dev/null || touch /tmp/zprivesc-fake-docker.sock
chmod 666 /tmp/zprivesc-fake-docker.sock 2>/dev/null || true

# LD_PRELOAD 3
mkdir -p /tmp/zprivesc-preload3-lib
echo '/tmp/zprivesc-preload3-lib' > /etc/ld.so.conf.d/zprivesc-preload3.conf
chmod 666 /etc/ld.so.conf.d/zprivesc-preload3.conf

# NFS export
echo "/tmp/zprivesc-nfs *(no_root_squash,rw,sync)" > /etc/exports
mkdir -p /tmp/zprivesc-nfs; chmod 777 /tmp/zprivesc-nfs

echo "=== Expanded testbeds planted in correct paths ==="
