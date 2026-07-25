#!/bin/sh
# testbeds/kernel_hardening/setup.sh - relax kernel hardening sysctls that are
# runtime-writable as root. Only sysctls that actually take effect are written,
# so the planted regression is real (and detectable by kernel_hardening.c) on
# this host. Locked sysctls are skipped (the host is already hardened there).
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
apply() {  # apply <sysctl> <value> -- write only if the kernel accepts it
  p="$1"; v="$2"
  cur=$(cat "$p" 2>/dev/null || echo "")
  [ "$cur" = "$v" ] && return 0
  if echo "$v" > "$p" 2>/dev/null; then
    got=$(cat "$p" 2>/dev/null || echo "")
    if [ "$got" = "$v" ]; then echo "relaxed $p -> $v"; return 0; fi
  fi
  echo "skip (locked) $p (current=$cur)"
}
apply /proc/sys/kernel/kptr_restrict 0
apply /proc/sys/kernel/dmesg_restrict 0
apply /proc/sys/kernel/yama/ptrace_scope 0
apply /proc/sys/fs/protected_hardlinks 0
apply /proc/sys/fs/protected_symlinks 0
apply /proc/sys/kernel/suid_dumpable 1
apply /proc/sys/kernel/perf_event_paranoid 0
echo "kernel_hardening testbed ready (writable sysctls relaxed)"
