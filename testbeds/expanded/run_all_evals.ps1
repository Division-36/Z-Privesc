#!/usr/bin/env pwsh
# Run Z-Privesc on all expanded targets from Windows
$ErrorActionPreference = "Continue"
$outDir = "D:\Axioms\Z-Privesc\eval_results"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$targets = @(
    "local-sudoers-nopasswd", "local-suid-root", "local-capabilities-setuid",
    "local-writable-etc-sudoers", "local-ssh-root-key", "local-groups-docker",
    "local-service-systemd", "local-cron-root", "local-ld-preload",
    "local-polkit-pkexec", "local-kernel-hardening", "local-writable-path-trojan",
    "local-process-root", "local-docker-socket", "local-sudoers-cmd",
    "local-suid-python", "local-cap-setuid2", "local-service2",
    "local-cron2", "local-ld-preload2", "local-ssh-root-key2",
    "local-suid-nmap", "local-suid-find", "local-suid-vim",
    "local-suid-env", "local-cap-dac-read", "local-cap-sys-admin",
    "local-writable-cron", "local-writable-initd", "local-ssh-user-key",
    "local-sudoers-noauth", "local-docker-group2", "local-docker-socket2",
    "local-service-sysv", "local-cron-d", "local-ld-preload3",
    "local-nfs-no-root-squash", "clean-host-baseline-1", "clean-host-baseline-2"
)

$total = $targets.Count
Write-Host "Running Z-Privesc on $total targets..."

for ($i = 0; $i -lt $total; $i++) {
    $id = $targets[$i]
    $outFile = "$outDir\$id.json"
    Write-Host "[$($i+1)/$total] $id..."
    
    $result = wsl -d kali-linux -u root -e bash -c "WSLENV= /root/zp/build/bin/z_privesc --all --json" 2>$null
    $result | Out-File -FilePath $outFile -Encoding utf8
    $sz = (Get-Item $outFile).Length
    Write-Host "  done ($sz bytes)"
}

Write-Host "=== All $total targets scanned ==="
Write-Host "Results: $(($targets | ForEach-Object { "$outDir\$_.json" } | Where-Object { Test-Path $_ }).Count) files"
