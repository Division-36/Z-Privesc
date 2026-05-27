#!/bin/sh
# testbeds/kernel_hardening/cleanup.sh - restore kernel hardening sysctls.
set -e
echo 2 > /proc/sys/kernel/randomize_va_space 2>/dev/null || true
echo 1 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
echo 2 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
echo "kernel_hardening testbed restored"
