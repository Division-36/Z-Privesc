#!/bin/sh
# testbeds/kernel_hardening/setup.sh - relax kernel hardening sysctls.
# NOTE: WSL2 may not allow writing to all of these. Best effort.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null || true
echo 0 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
echo "kernel_hardening testbed ready (best effort)"
