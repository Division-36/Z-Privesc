#!/bin/bash
# Run Z-Privesc on all expanded targets (testbeds already planted)
set -e
ZP=/root/zp/build/bin/z_privesc
OUT=/tmp/eval_expanded
mkdir -p $OUT

echo "=== Running Z-Privesc on expanded corpus ==="

TARGETS=(
  "local-sudoers-nopasswd"
  "local-suid-root"
  "local-capabilities-setuid"
  "local-writable-etc-sudoers"
  "local-ssh-root-key"
  "local-groups-docker"
  "local-service-systemd"
  "local-cron-root"
  "local-ld-preload"
  "local-polkit-pkexec"
  "local-kernel-hardening"
  "local-writable-path-trojan"
  "local-process-root"
  "local-docker-socket"
  "local-sudoers-cmd"
  "local-suid-python"
  "local-cap-setuid2"
  "local-service2"
  "local-cron2"
  "local-ld-preload2"
  "local-ssh-root-key2"
  "local-suid-nmap"
  "local-suid-find"
  "local-suid-vim"
  "local-suid-env"
  "local-cap-dac-read"
  "local-cap-sys-admin"
  "local-writable-cron"
  "local-writable-initd"
  "local-ssh-user-key"
  "local-sudoers-noauth"
  "local-docker-group2"
  "local-docker-socket2"
  "local-service-sysv"
  "local-cron-d"
  "local-ld-preload3"
  "local-nfs-no-root-squash"
  "clean-host-baseline-1"
  "clean-host-baseline-2"
)

TOTAL=${#TARGETS[@]}
idx=0
for id in "${TARGETS[@]}"; do
  idx=$((idx+1))
  echo "[$idx/$TOTAL] $id..."
  WSLENV= $ZP --all --json > "$OUT/$id.json" 2>/dev/null || true
  sz=$(wc -c < "$OUT/$id.json" 2>/dev/null || echo 0)
  echo "  done (${sz} bytes)"
done

echo "=== All $TOTAL targets scanned ==="
echo "Results: $(ls $OUT/*.json 2>/dev/null | wc -l) files"
