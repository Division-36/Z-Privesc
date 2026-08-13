# benchmarks/data

Raw, machine-readable benchmark captures for Z-Privesc. Every number in
[`../benchmarks.md`](../benchmarks.md) is sourced from a file here.

All captures were taken on a clean **multipass** VM
(`zp-2204`, Ubuntu 22.04 LTS, kernel 5.15.0-185-generic, 1 vCPU)
on 2026-07-14. See `environment.json` for the exact environment.

## Files

| File                | Contents                                                       |
|---------------------|----------------------------------------------------------------|
| `environment.json`  | Host/OS/kernel/GCC/CPU/date of the run.                        |
| `build.json`        | Dynamic vs static build time + binary sizes, full-scan time.   |
| `test-results.json` | Test-suite totals (cases / pass / fail / skip / runtime).     |
| `probe-timings.json`| Per-probe wall-clock time and finding count (real, multipass). |
| `summary.json`      | One-line rollup of the headline metrics.                       |
| `comparison.json`   | Lynis 3.1.6 and LinPEAS real runtimes vs Z-Privesc.           |
| `lynis-sample.txt`  | First lines of a sample Lynis run (size/noise reference).      |
| `linpeas-sample.txt`| First lines of a sample LinPEAS run (size/noise reference).    |

### Accuracy study (`data/accuracy/`)

`data/accuracy/accuracy.json` records the 37-category expanded detection study: **37/37 true positives,
0 false positives on planted targets**. Detection recall 1.0000, precision 1.0000 (macro).
Path recall 0.9429 (33/35), path precision 0.9714 (33/34).
Brier seed: 0.109 (353 observations). Clean-host FP baseline: 47 ambient findings per host.

35 targets evaluated on Kali WSL2; 2 targets (kernel_hardening, process_root) evaluated on
Ubuntu 22.04 LTS (multipass VM) due to WSL2 limitations (locked sysctls, background process
lifecycle). Multi-distro evaluation across kernel 6.18.33 (WSL2) and kernel 5.15.0 (Ubuntu 22.04).

GTFOBins baseline: knowledge coverage 0.8649 (32/37 techniques), automated scan recall = 0.

## Regenerating

```bash
# from the project root, inside the multipass VM
bash scripts/bench_mp.sh        # writes JSON into benchmarks/data/
```

`scripts/bench_mp.sh` times `make`, `make test`, a full `--all` scan,
and each probe individually, then writes the JSON files above. It also
installs and times Lynis and LinPEAS on the same host for the
comparison table.
