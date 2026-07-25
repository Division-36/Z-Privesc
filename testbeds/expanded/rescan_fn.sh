#!/bin/bash
# Re-scan only the FN targets with proper setup
umount -l /mnt/c 2>/dev/null
umount -l /mnt/d 2>/dev/null
umount -l /mnt/wslg/distro 2>/dev/null

ZP=/root/zp/build/bin/z_privesc
OUT=/tmp/eval_expanded2
TB=/root/zp/testbeds
mkdir -p $OUT

# Targets that need re-scanning (the FN ones from batch1)
RESCAN="local-writable-etc-sudoers local-ssh-root-key local-groups-docker local-service-systemd local-kernel-hardening local-writable-path-trojan local-process-root local-docker-socket local-suid-python local-service2 local-cron2 local-ssh-root-key2 local-writable-cron local-writable-initd local-docker-group2 local-docker-socket2 local-service-sysv local-cron-d local-nfs-no-root-squash"

# Map target -> testbed dir name
declare -A TBMAP
TBMAP[local-writable-etc-sudoers]="writable_etc"
TBMAP[local-ssh-root-key]="ssh_keys"
TBMAP[local-groups-docker]="groups"
TBMAP[local-service-systemd]="service"
TBMAP[local-kernel-hardening]="kernel_hardening"
TBMAP[local-writable-path-trojan]="writable_path"
TBMAP[local-process-root]="process"
TBMAP[local-docker-socket]="docker"
TBMAP[local-suid-python]="suid_python"
TBMAP[local-service2]="service2"
TBMAP[local-cron2]="cron2"
TBMAP[local-ssh-root-key2]="ssh_keys2"
TBMAP[local-writable-cron]="writable_cron"
TBMAP[local-writable-initd]="writable_initd"
TBMAP[local-docker-group2]="docker_group2"
TBMAP[local-docker-socket2]="docker_socket2"
TBMAP[local-service-sysv]="service_sysv"
TBMAP[local-cron-d]="cron_d"
TBMAP[local-nfs-no-root-squash]="nfs"

for id in $RESCAN; do
  tb="${TBMAP[$id]}"
  echo "=== $id (testbed: $tb) ==="
  
  # Run setup
  if [ -f "$TB/$tb/setup.sh" ]; then
    bash "$TB/$tb/setup.sh" 2>/dev/null && echo "  setup OK" || echo "  setup failed"
  else
    echo "  no setup.sh found at $TB/$tb/setup.sh"
  fi
  
  # Scan
  WSLENV= $ZP --all --json > "$OUT/$id.json" 2>/dev/null || true
  sz=$(wc -c < "$OUT/$id.json" 2>/dev/null || echo 0)
  echo "  scan done ($sz bytes)"
  
  # Teardown
  if [ -f "$TB/$tb/cleanup.sh" ]; then
    bash "$TB/$tb/cleanup.sh" 2>/dev/null || true
  fi
done

echo "=== RESCAN DONE ==="
echo "Results: $(ls $OUT/*.json 2>/dev/null | wc -l) files"
