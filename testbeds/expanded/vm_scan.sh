#!/bin/bash
set -e

echo "=== Setting up kernel_hardening testbed ==="
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
echo 0 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
echo 0 > /proc/sys/fs/protected_hardlinks 2>/dev/null || true
echo 0 > /proc/sys/fs/protected_symlinks 2>/dev/null || true

echo "=== Setting up process_root testbed ==="
cat > /tmp/ww-root-proc << 'EOF'
#!/bin/bash
sleep 3600
EOF
chmod 777 /tmp/ww-root-proc
chown root:root /tmp/ww-root-proc
setsid /tmp/ww-root-proc &
sleep 1
pgrep -f ww-root-proc && echo "process running" || echo "process NOT running"

echo "=== Scanning ==="
/tmp/zp --all --json > /tmp/vm_scan.json 2>/dev/null
echo "scan done"

echo "=== kernel_hardening probe ==="
python3 -c "
import json
d=json.load(open('/tmp/vm_scan.json'))
for p in d['probes']:
    if p['name']=='kernel_hardening':
        print(f'verdict={p[\"verdict\"]} findings={len(p.get(\"findings\",[]))}')
        for f in p.get('findings',[]):
            print(f'  {f[\"id\"]}: {f[\"target\"]}: {f[\"description\"][:100]}')
"

echo "=== process probe ==="
python3 -c "
import json
d=json.load(open('/tmp/vm_scan.json'))
for p in d['probes']:
    if p['name']=='process':
        print(f'verdict={p[\"verdict\"]} findings={len(p.get(\"findings\",[]))}')
        for f in p.get('findings',[]):
            print(f'  {f[\"id\"]}: {f[\"target\"]}: {f[\"description\"][:100]}')
"

echo "=== ALL DONE ==="
