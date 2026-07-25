#!/usr/bin/env python3
import json
d = json.load(open("/tmp/vm_scan2.json"))
for p in d["probes"]:
    if p["name"] in ("kernel_hardening", "process"):
        print(f'{p["name"]}: verdict={p["verdict"]} findings={len(p.get("findings",[]))}')
        for f in p.get("findings", []):
            print(f'  {f["id"]}: {f["target"]}: {f["description"][:120]}')
