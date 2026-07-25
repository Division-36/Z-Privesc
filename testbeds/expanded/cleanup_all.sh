#!/bin/bash
# Cleanup all expanded testbeds
set -e
TB=/root/zp/testbeds
rm -f $TB/suid_nmap/nmap $TB/suid_find/find $TB/suid_vim/vim $TB/suid_env/env
rm -f $TB/cap_dac_read/python3-cap-dr $TB/cap_sys_admin/python3-cap-sysadmin
rm -f $TB/writable_cron/root.cron /tmp/evil-cron.sh
rm -f $TB/writable_initd/evil-service /tmp/pwned_initd
rm -rf $TB/ssh_user_key/*
rm -f /etc/exports; rm -rf /tmp/nfs_share
rm -f /etc/sudoers.d/91-test-noauth
rm -f /etc/init.d/zztest-sysv
rm -f /etc/cron.d/zztest-cron /tmp/zztest-cron-d.sh
rm -f /etc/ld.so.conf.d/zztest-preload3.conf; rm -rf /tmp/zztest-preload3-lib
rm -rf /tmp/ww-test-dir
echo "=== Expanded testbeds cleaned ==="
