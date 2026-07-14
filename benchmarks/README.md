# benchmarks/data

Raw, machine-readable benchmark captures for Z-Privesc. Every number in
[`../benchmarks.md`](../benchmarks.md) is sourced from a file here.

All captures were taken on a clean **multipass** VM
(`primary`, Ubuntu 26.04 LTS, kernel 7.0.0-27-generic, 1 vCPU, 891 MB)
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

## Regenerating

```bash
# from the project root, inside the multipass VM
bash scripts/bench_mp.sh        # writes JSON into benchmarks/data/
```

`scripts/bench_mp.sh` times `make`, `make test`, a full `--all` scan,
and each probe individually, then writes the JSON files above. It also
installs and times Lynis and LinPEAS on the same host for the
comparison table.
