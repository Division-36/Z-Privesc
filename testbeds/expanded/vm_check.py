#!/usr/bin/env python3
import json, subprocess, sys

result = subprocess.run(
    ["/tmp/zp/build/bin/z_privesc", "--all", "--json", "--quiet"],
    capture_output=True, text=True, timeout=180
)

print(f"rc={result.returncode}")
print(f"stdout len={len(result.stdout)}")
print(f"stderr len={len(result.stderr)}")

if result.stdout:
    try:
        d = json.loads(result.stdout)
        for p in d["probes"]:
            if p["name"] in ("kernel_hardening", "process"):
                print(f'{p["name"]}: verdict={p["verdict"]} findings={len(p.get("findings",[]))}')
                for f in p.get("findings", []):
                    print(f'  {f["id"]}: {f["target"]}: {f["description"][:100]}')
    except json.JSONDecodeError as e:
        print(f"JSON error: {e}")
        print(f"First 500 chars: {result.stdout[:500]}")
else:
    print("No stdout")

if result.stderr:
    print(f"stderr: {result.stderr[:500]}")
