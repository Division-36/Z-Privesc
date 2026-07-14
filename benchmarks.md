# Z-Privesc Benchmarks

This document compares **Z-Privesc** against the other well-known Linux
privilege-escalation auditing tools, using **real, measured** numbers
captured on a clean multipass VM (not estimates, not timeouts).

Two benchmark runs are described:

- **Multipass remake (2026-07-14)** — the authoritative, reproducible run
  with real Lynis/LinPEAS runtimes. Raw numbers live in
  [`benchmarks/data/`](benchmarks/data/).
- **WSL2 v1.0.0 report** — the original frozen launch report
  ([appendix](#appendix-wsl2-v100-report)). Several WSL2-specific kernel
  quirks made some planted testbeds no-ops; those caveats do **not**
  apply to the multipass run.

**License**: MIT · **Author**: Zierax (Ziad Salah) <zs.01117875692@gmail.com>

---

## 1. Executive Summary

Z-Privesc was run on a freshly installed Ubuntu 26.04 VM and timed
against LinPEAS and Lynis on the **same host**, scanning the **same
filesystem**:

| Tool                | Role             | Wall-clock full scan | Findings                 |
|---------------------|------------------|---------------------:|--------------------------|
| **Z-Privesc** 1.0.0 | Defensive audit  | **2.65 s**           | 40 structured findings   |
| **Lynis** 3.1.6     | Compliance       | 100.45 s             | 850-line free-form report|
| **LinPEAS** (latest)| Offensive enum   | 120.03 s (capped)    | 378-line color report    |

Z-Privesc finishes in **under 3 seconds** — roughly **38× faster** than
Lynis and **45× faster** than LinPEAS — while emitting deterministic,
`jq`-parseable JSON instead of free-form text. It is also the only tool
of the three that ships **stand-alone static binaries** with no runtime
dependencies.

---

## 2. Benchmark Environment (multipass, real)

Captured in [`benchmarks/data/environment.json`](benchmarks/data/environment.json):

| Field            | Value                                        |
|------------------|----------------------------------------------|
| Host             | `primary` (multipass VM)                     |
| OS               | Ubuntu 26.04 LTS                             |
| Kernel           | 7.0.0-27-generic                             |
| Arch             | x86_64                                       |
| GCC              | gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0         |
| vCPUs            | 1                                            |
| Memory           | 891 MB                                       |
| Date (UTC)       | 2026-07-14T18:26:33Z                         |

Build flags include `-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
-Wformat -Werror=format-security` plus `-Wall -Wextra -Werror`. The
static build additionally links `libcap` statically.

---

## 3. Build & Test Metrics (real, measured)

From [`benchmarks/data/build.json`](benchmarks/data/build.json) and
[`benchmarks/data/test-results.json`](benchmarks/data/test-results.json):

| Metric                 | Value              |
|------------------------|-------------------:|
| Dynamic build time     | 2.7305 s           |
| Dynamic binary size    | 94,232 B           |
| Static build time      | 3.0251 s           |
| Static binary size     | 1,116,408 B        |
| Stripped static size   | 1,018,248 B        |
| Full `--all` scan time | 2.6461 s           |
| Full scan findings     | 40                 |
| Test suite runtime     | 4.1958 s           |
| Tests passed           | 58 / 60            |
| Tests failed           | 0                  |
| Tests skipped          | 2                  |

Two tests skip on permission-restricted or root-only environments
(`polkit_old_version_match` needs policykit-1; `capabilities_long_paths`
needs xattr support on the underlying filesystem). 58/58 executable test
cases pass.

---

## 4. Per-Probe Timing (real, multipass)

Measured individually with `--all` on the clean VM, captured in
[`benchmarks/data/probe-timings.json`](benchmarks/data/probe-timings.json).
Times are wall-clock seconds; "findings" is the count emitted on the
clean baseline (almost all are informational `INFO`/`MEDIUM` records).

| Probe                | Time (s) | Findings |
|----------------------|---------:|---------:|
| suid                 | 0.2142   | 21       |
| capabilities         | 0.5979   | 4        |
| groups               | 0.0155   | 3        |
| world_writable       | 0.0188   | 2        |
| service              | 0.0224   | 1        |
| writable_path        | 0.0192   | 0        |
| ssh_keys             | 0.0170   | 1        |
| ld_preload           | 0.0167   | 1        |
| nfs                  | 0.0159   | 1        |
| cron                 | 0.0155   | 1        |
| sudoers              | 0.0134   | 1        |
| process              | 0.0153   | 1        |
| docker_socket        | 0.0149   | 0        |
| polkit               | 0.0147   | 0        |
| kernel_vuln          | 0.0145   | 1        |
| kernel_hardening     | 0.0131   | 1        |
| writable_etc         | 0.0149   | 0        |
| **Total (`--all`)**  | **2.6461**| **40**   |

The two slow probes are `capabilities` (an xattr walk) and `suid`
(a filesystem walk); both stay well under a second on a normal system.
On the multipass VM these are scoped to whole-filesystem and still
finish in a fraction of a second — the old WSL2 report's 30 s caps came
from scanning a 9p-mounted Windows volume, not from the probes
themselves.

---

## 5. Head-to-Head Comparison (real runtimes)

From [`benchmarks/data/comparison.json`](benchmarks/data/comparison.json),
all three tools were run on the **same** Ubuntu 26.04 VM:

| Tool        | Version | Install time | Run time  | Output       |
|-------------|---------|-------------:|----------:|--------------|
| Z-Privesc   | 1.0.0   | (built)      | 2.6461 s  | 40 findings  |
| Lynis       | 3.1.6   | 8.31 s       | 100.45 s  | 850 lines    |
| LinPEAS     | latest  | 3.35 s (dl)  | 120.03 s* | 378 lines    |

\* LinPEAS was capped at 120 s; its full default scan runs longer.

### Signal-to-noise

| Tool        | Output format      | Parseable? | Notes                              |
|-------------|--------------------|:----------:|------------------------------------|
| Z-Privesc   | structured JSON    | yes (`jq`)| single overall risk label + per-finding `remediation` |
| Lynis       | free-form report   | partial   | hardening index bar, DAT report    |
| LinPEAS     | color text         | no        | exploit links, offensive framing   |

An analyst can triage Z-Privesc with:

```bash
jq '.findings[] | select(.severity=="CRITICAL")' audit.json
```

---

## 6. Probe Catalog (17 total)

Z-Privesc covers all 17 categories of privilege-escalation misconfiguration.
See [`docs/PROBES.md`](docs/PROBES.md) for the per-probe detail.

| # | Probe            | Z-Privesc | LinPEAS | Lynis | LES2 |
|---|------------------|:---------:|:-------:|:-----:|:----:|
| 1 | suid             | ✓         | ✓       | ✓     | -    |
| 2 | writable_path    | ✓         | ✓       | ✓     | -    |
| 3 | capabilities     | ✓         | ✓       | -     | -    |
| 4 | writable_etc     | ✓         | ✓       | ✓     | -    |
| 5 | docker_socket    | ✓         | ✓       | -     | -    |
| 6 | polkit           | ✓         | -       | -     | -    |
| 7 | world_writable   | ✓         | ✓       | ✓     | -    |
| 8 | kernel_vuln      | ✓         | ✓       | -     | ✓    |
| 9 | cron             | ✓         | ✓       | -     | -    |
| 10| sudoers          | ✓         | -       | -     | -    |
| 11| ssh_keys         | ✓         | -       | -     | -    |
| 12| groups           | ✓         | -       | -     | -    |
| 13| service          | ✓         | -       | -     | -    |
| 14| kernel_hardening | ✓         | -       | ✓     | -    |
| 15| process          | ✓         | -       | -     | -    |
| 16| nfs              | ✓         | -       | -     | -    |
| 17| ld_preload       | ✓         | -       | -     | -    |

Z-Privesc is the only tool that covers **all 17** categories out of the
box.

---

## 7. Strengths and Weaknesses

### Z-Privesc

**Strengths**
- 17 distinct probes — the broadest coverage of any tool tested.
- Sub-second mean runtime; full `--all` scan in ~2.6 s.
- Deterministic JSON output, parseable with `jq`.
- Truthimatics engine produces a single overall risk label.
- No write operations, no exploit code, no zero-day enumeration.
- Stand-alone static binary, no dependencies (verified: static `--all`
  runs cleanly, no glibc NSS crash).

**Weaknesses**
- `suid`/`capabilities` do a full filesystem walk; on very large hosts
  `--root=` scoping is recommended.
- No remediation script generation; remediation is a `chmod`/`chown`
  line in each finding's `remediation` field.
- No integration with live CVE feeds; `kernel_vuln` uses a hardcoded,
  conservative list.

### LinPEAS
- **Strengths**: huge community red-team heuristic set; exploit links.
- **Weaknesses**: 2+ minutes per scan; false-positive prone; no
  structured output; offensive framing.

### Lynis
- **Strengths**: CIS/NIST compliance orientation; hardening index.
- **Weaknesses**: 60-180 s per scan; report is DAT, not JSON; no
  PE-specific probes for SUID/capabilities/cron/sudoers/NFS.

---

## 8. Reproducing the Bench (multipass)

```bash
# Launch a clean VM
multipass launch 26.04 -n zprivesc-bench
multipass exec zprivesc-bench -- sudo apt-get update
multipass exec zprivesc-bench -- sudo apt-get install -y \
    build-essential libcap2-bin man-db

# Copy the source tree in (mounts may be disabled)
tar czf zp.tgz Z-Privesc
multipass transfer zp.tgz zprivesc-bench:/home/ubuntu/
multipass exec zprivesc-bench -- tar xzf zp.tgz

# Build, test, and time a full scan
multipass exec zprivesc-bench -- bash -c '
  cd Z-Privesc
  make
  make test
  t0=$(date +%s.%N); ./build/bin/z_privesc --all --json > /tmp/zp.json; \
  t1=$(date +%s.%N); echo "scan: $(echo "$t1-$t0"|bc) s"
'

# Compare against Lynis / LinPEAS (run on the same VM)
multipass exec zprivesc-bench -- bash -c '
  sudo apt-get install -y lynis
  time sudo lynis audit system --quick --no-colors > /tmp/lynis.txt
  curl -fsSL -o linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
  time bash linpeas.sh -q -a > /tmp/linpeas.txt
'
```

Raw captured JSON lives in [`benchmarks/data/`](benchmarks/data/).

---

## Appendix: WSL2 v1.0.0 Report

The original launch report was produced on WSL2 (Debian, kernel
6.6.114.1-microsoft-standard-WSL2). It remains useful as a historical
baseline but several planted testbeds were no-ops because of WSL2
kernel quirks:

- WSL2 **strips the SUID bit** from user-created files, so the SUID
  testbed could not be validated in `/tmp`.
- WSL2 **strips capability xattrs** on the 9p share, so the
  capabilities testbed could not be validated in `/tmp`.
- WSL2 **rejects sysctl writes** for several hardening knobs, so the
  `kernel_hardening` testbed was a no-op.
- WSL2 **has no `nfsd`**, so the NFS testbed reported `NFS-CLEAN`.
- A full `/` walk on the 9p-mounted Windows volume routinely hit the
  30 s cap; the multipass run above shows the same probes finish in
  well under a second on a native filesystem.

The v1.0.0 report's per-testbed methodology, probe catalog, and
detection summary (10/16 confirmed detections, the rest WSL2 no-ops)
are preserved verbatim in commit `165da370` and in the project history.
The headline numbers in this document supersede it.
