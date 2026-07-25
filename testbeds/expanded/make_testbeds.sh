#!/bin/bash
# Create expanded testbeds for n=40+ corpus
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
TB=/root/zp/testbeds

# --- SUID variants (different binaries, different baselines) ---
mkdir -p $TB/suid_nmap
cp /usr/bin/nmap $TB/suid_nmap/nmap 2>/dev/null || cp /usr/bin/find $TB/suid_nmap/nmap
chmod 4755 $TB/suid_nmap/nmap
chown root:root $TB/suid_nmap/nmap
echo "suid_nmap ready"

mkdir -p $TB/suid_find
cp /usr/bin/find $TB/suid_find/find
chmod 4755 $TB/suid_find/find
chown root:root $TB/suid_find/find
echo "suid_find ready"

mkdir -p $TB/suid_vim
cp /usr/bin/vim.tiny $TB/suid_vim/vim 2>/dev/null || cp /usr/bin/vi $TB/suid_vim/vim 2>/dev/null || cp /usr/bin/nano $TB/suid_vim/vim
chmod 4755 $TB/suid_vim/vim
chown root:root $TB/suid_vim/vim
echo "suid_vim ready"

mkdir -p $TB/suid_env
cp /usr/bin/env $TB/suid_env/env
chmod 4755 $TB/suid_env/env
chown root:root $TB/suid_env/env
echo "suid_env ready"

# --- Capability variants ---
mkdir -p $TB/cap_dac_read
cp /usr/bin/python3 $TB/cap_dac_read/python3-cap-dr 2>/dev/null || cp /usr/bin/cat $TB/cap_dac_read/python3-cap-dr
setcap cap_dac_read_search+ep $TB/cap_dac_read/python3-cap-dr 2>/dev/null && echo "cap_dac_read ready" || echo "cap_dac_read skipped (setcap failed)"

mkdir -p $TB/cap_sys_admin
cp /usr/bin/python3 $TB/cap_sys_admin/python3-cap-sysadmin 2>/dev/null || cp /usr/bin/cat $TB/cap_sys_admin/python3-cap-sysadmin
setcap cap_sys_admin+ep $TB/cap_sys_admin/python3-cap-sysadmin 2>/dev/null && echo "cap_sys_admin ready" || echo "cap_sys_admin skipped"

# --- Writable paths ---
mkdir -p $TB/writable_cron
echo "* * * * * root /tmp/evil-cron.sh" > $TB/writable_cron/root.cron
chmod 666 $TB/writable_cron/root.cron
echo '#!/bin/sh' > /tmp/evil-cron.sh
chmod 755 /tmp/evil-cron.sh
echo "writable_cron ready"

mkdir -p $TB/writable_initd
cat > $TB/writable_initd/evil-service << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          evil-service
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Short-Description: evil
### END INIT INFO
echo "PWNED" > /tmp/pwned_initd
EOF
chmod 666 $TB/writable_initd/evil-service
echo "writable_initd ready"

# --- SSH variants ---
mkdir -p $TB/ssh_user_key
ssh-keygen -t ed25519 -f $TB/ssh_user_key/id_ed25519 -N "" -q 2>/dev/null || true
chmod 600 $TB/ssh_user_key/id_ed25519 2>/dev/null || true
chmod 644 $TB/ssh_user_key/id_ed25519.pub 2>/dev/null || true
echo "ssh_user_key ready"

# --- NFS ---
mkdir -p $TB/nfs_export
echo "/tmp/nfs_share *(no_root_squash,rw,sync)" > /etc/exports 2>/dev/null || true
mkdir -p /tmp/nfs_share
chmod 777 /tmp/nfs_share
echo "nfs_export ready"

# --- Sudoers variants ---
mkdir -p $TB/sudoers_noauth
echo "ubuntu ALL=(ALL) NOPASSWD: /usr/bin/vim" > /etc/sudoers.d/91-test-noauth 2>/dev/null || true
chmod 440 /etc/sudoers.d/91-test-noauth 2>/dev/null || true
echo "sudoers_noauth ready"

# --- Docker variants ---
mkdir -p $TB/docker_group2
usermod -aG docker ubuntu 2>/dev/null || usermod -aG docker kali 2>/dev/null || true
echo "docker_group2 ready"

mkdir -p $TB/docker_socket2
chmod 666 /var/run/docker.sock 2>/dev/null || true
echo "docker_socket2 ready"

# --- Service variants ---
mkdir -p $TB/service_sysv
cat > /etc/init.d/zztest-sysv << 'INITEOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          zztest-sysv
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: test sysv service
### END INIT INFO
case "$1" in
  start|stop|restart) ;;
esac
INITEOF
chmod 755 /etc/init.d/zztest-sysv
echo "service_sysv ready"

# --- Cron variants ---
mkdir -p $TB/cron_d
cat > /etc/cron.d/zztest-cron << 'CRONEOF'
* * * * * root /tmp/zztest-cron-d.sh
CRONEOF
chmod 644 /etc/cron.d/zztest-cron
echo '#!/bin/sh' > /tmp/zztest-cron-d.sh
chmod 755 /tmp/zztest-cron-d.sh
echo "cron_d ready"

# --- LD_PRELOAD variants ---
mkdir -p $TB/ld_preload3
cat > /etc/ld.so.conf.d/zztest-preload3.conf << 'LDEOF'
/tmp/zztest-preload3-lib
LDEOF
mkdir -p /tmp/zztest-preload3-lib
chmod 666 /etc/ld.so.conf.d/zztest-preload3.conf
echo "ld_preload3 ready"

# --- World writable ---
mkdir -p $TB/world_writable_dir
chmod 777 /tmp/ww-test-dir 2>/dev/null || mkdir -p /tmp/ww-test-dir
chmod 777 /tmp/ww-test-dir
echo "world_writable_dir ready"

# --- Kernel module loading ---
mkdir -p $TB/kernel_modprobe
echo "1" > /proc/sys/kernel/modules_disabled 2>/dev/null || true
echo "kernel_modprobe ready"

# --- Polkit variants ---
mkdir -p $TB/pkexec2
chmod 4755 /usr/bin/pkexec 2>/dev/null || true
echo "pkexec2 ready"

echo "=== All expanded testbeds created ==="
