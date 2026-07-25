#!/bin/sh
# testbeds/kernel_hardening/cleanup.sh - restore the sysctls relaxed by setup.sh.
set -e
echo 2 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
echo 1 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
echo 1 > /proc/sys/fs/protected_hardlinks 2>/dev/null || true
echo 1 > /proc/sys/fs/protected_symlinks 2>/dev/null || true
echo 0 > /proc/sys/kernel/suid_dumpable 2>/dev/null || true
echo 3 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
echo "kernel_hardening testbed restored"
