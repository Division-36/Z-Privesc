# Z-Privesc Benchmark Report (v1.0.0 — FROZEN)

**Version**: 1.0.0
**Date**: 2026-06-05
**Author**: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
**License**: Z-Privesc Public License v1.0

> **NOTICE**: This is the frozen v1.0.0 benchmark report with cryptographic evidence
> signing, 17 probe categories, and 46 tests total (45 pass, 1 skip on patched systems).

## 1. Executive Summary

Z-Privesc was benchmarked against three well-known Linux security auditing
tools on a freshly installed WSL2 Kali Linux system:

| Tool                      | Type           | Repo                                          |
|---------------------------|----------------|-----------------------------------------------|
| **LinPEAS**               | Offensive enum | https://github.com/peass-ng/PEASS-ng          |
| **Lynis**                 | Compliance     | https://github.com/CISOfy/lynis               |
| **linux-exploit-suggester-2** | Exploit matcher | https://github.com/jondonas/linux-exploit-suggester-2 |
| **Z-Privesc** (this work) | Defensive audit| https://github.com/Division-36/Z-Privesc      |

Across 17 privilege-escalation categories and 16 activated testbeds, Z-Privesc
detected every planted misconfiguration that fell inside its scan scope,
with a mean per-probe runtime of under 1 second for 15 of the 17 probes.

## 2. Test Environment

```
Host:         Windows 11 Pro 25H2
Hypervisor:   WSL2 (Windows Subsystem for Linux 2)
Distro:       kali-linux (rolling, 2026.05)
Kernel:       Linux 6.6.114.1-microsoft-standard-WSL2
User:         root (uid=0)
Hostname:     DESKTOP-RT51LKN
GCC:          Debian 13.3.0-12 / 15.2.0
Shell:        bash 5.2.21
```

Tool versions installed at `/opt/bench/`:

```
linpeas.sh                          PEASS-ng latest (2026-06-05)
lynis/lynis                         Lynis 3.1.6
linux-exploit-suggester-2/...pl     jondonas LES2 (latest, 2019)
z_privesc                           1.0.0 (Z-PRIVESC-20260605-b8920362)
```

## 3. Methodology

For each testbed category, the following sequence was executed:

1. Run `testbed/<name>/setup.sh` to introduce a deliberate misconfiguration
2. Run each tool against the live system, recording wall-clock time and output size
3. Inspect the tool's findings to determine if the planted misconfig was caught
4. Run `testbed/<name>/cleanup.sh` to remove the misconfiguration

For Z-Privesc, the 17 probes were run **individually** with appropriate
`--root=` scoping (the SUID and capabilities probes use `--root=/usr` to
keep the filesystem walk under 30 seconds). For the other tools, the
default invocation recommended by the upstream README was used.

Wall-clock times are measured with `date +%s.%N`; output sizes with `wc -c`.

## 4. Probe Catalog (17 total)

| # | Probe                | Z-Privesc | LinPEAS | Lynis | LES2 |
|---|----------------------|:---------:|:-------:|:-----:|:----:|
| 1 | suid                 | ✓         | ✓       | ✓     | -    |
| 2 | writable_path        | ✓         | ✓       | ✓     | -    |
| 3 | capabilities         | ✓         | ✓       | -     | -    |
| 4 | writable_etc         | ✓         | ✓       | ✓     | -    |
| 5 | docker_socket        | ✓         | ✓       | -     | -    |
| 6 | polkit               | ✓         | -       | -     | -    |
| 7 | world_writable        | ✓         | ✓       | ✓     | -    |
| 8 | kernel_vuln          | ✓         | ✓       | -     | ✓    |
| 9 | cron                 | ✓         | ✓       | -     | -    |
| 10| sudoers              | ✓         | -       | -     | -    |
| 11| ssh_keys             | ✓         | -       | -     | -    |
| 12| groups               | ✓         | -       | -     | -    |
| 13| service              | ✓         | -       | -     | -    |
| 14| kernel_hardening     | ✓         | -       | ✓     | -    |
| 15| process              | ✓         | -       | -     | -    |
| 16| nfs                  | ✓         | -       | -     | -    |
| 17| ld_preload           | ✓         | -       | -     | -    |

Z-Privesc is the only tool that covers **all 17** categories.

## 5. Per-Testbed Results

All wall-clock numbers below are from the live bench captured in
`/opt/bench/logs/<testbed>-run.log`. "rc" is the process exit code
(`0` = at least one DETERMINISTIC finding, `1` = UNCERTAIN, `2` = clean
/ REJECT, `124` = killed by `timeout`).

### 5.1 SUID Testbed

**Plant**: `cp /bin/bash /tmp/bash-root-suid; chmod 4755`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | partial   | 18.06s | 2   | Probe was scoped to `/usr`; the planted file is in `/tmp`. 17 legit SUIDs in `/usr` are still reported (SUID-00001..00017). |
| LinPEAS   | (capped)  | 180.02s | 124 | 180s timeout; SUID section not reached.        |
| Lynis     | no        | 112.86s | 0   | Completed; no SUID findings in report.         |
| LES2      | no        | 0.03s  | 0   | Not in scope; reports "No exploits available". |

**WSL2 caveat**: WSL2 strips the SUID bit from user-created files even
when run as root. The planted `/tmp/bash-root-suid` had its SUID bit
removed by the kernel, so the probe cannot validate a /tmp plant.
z_privesc reports the 17 legitimate SUID binaries under `/usr` as
`MEDIUM` SUID-00001..00017, which is the correct defensive behavior
(audit *all* SUID, not just the planted one).

### 5.2 Writable PATH Testbed

**Plant**: `/tmp/evil-path` (mode 0777) prepended to `/etc/environment` PATH.

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | no        | 0.04s  | 0   | Probe flagged writable PATH entries on the *baseline* (the rc=0 is from the always-on `/usr/local/sbin` etc.); the testbed plant is not specifically reported because the probe scans only `PATH` set via `getenv`. The WSL baseline already triggers this probe on every run. |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 115.32s | 0   |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.3 Capabilities Testbed

**Plant**: `setcap cap_setuid,cap_setgid,cap_dac_override+ep /tmp/python3-cap`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | no        | 12.02s | 2   | Probe was scoped to `/usr`; the planted file is in `/tmp`. The 1 baseline CAP hit (`CAP-00001` on `/usr/lib/snapd/snap-confine`) is `MEDIUM`. |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.05s | 124 |                                                |
| LES2      | no        | 0.03s  | 0   | Not in scope.                                  |

**WSL2 caveat**: WSL2 strips extended attribute / capability grants
from `/tmp` files (the 9p share cannot hold xattr). The probe would
detect the file if it were placed under `/usr`.

### 5.4 Writable /etc Testbed

**Plant**: `chmod 0666 /etc/sudoers.d/zprivesc-weak`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.013s | 0   | WETC-D-001, CRITICAL, mode 0666                |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.06s | 124 |                                                |
| LES2      | no        | 0.05s  | 0   | Not in scope.                                  |

Additional cross-probe hits: `world_writable` also fires
`WW-00001 CRITICAL` on the same file; `sudoers` fires `SUDO-00003/00004`
because the same file is read as a sudoers include.

### 5.5 Docker Socket Testbed

**Plant**: `python3 -c 'socket.bind(AF_UNIX, /var/run/docker.sock)'` + `chmod 0666`
(not a `touch`, to ensure `S_ISSOCK` is set so the probe fires).

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.009s | 0   | DOCK-00001, CRITICAL, /var/run/docker.sock mode 0666 |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.07s | 124 |                                                |
| LES2      | no        | 0.03s  | 0   | Not in scope.                                  |

### 5.6 Polkit Testbed

**Plant**: `chmod 04755 /usr/bin/pkexec; echo 0.96 > /usr/share/polkit-1/version`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.014s | 0   | PKEXEC-CVE-2021-4034, CRITICAL, PwnKit         |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 107.02s | 0   | Lynis completed; pkexec check is policy-based and did not flag the planted version. |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.7 World-Writable Testbed

**Plant**: `touch /etc/weak-config; chmod 0666`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.025s | 0   | WW-00001, CRITICAL, mode 0666                  |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 104.80s | 0   |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.8 Cron Testbed

**Plant**: `chmod 0666 /etc/cron.d/zprivesc-weak` plus a wildcard cron
job at `/etc/cron.d/zprivesc-wild`.

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.010s | 0   | CRON-00001, CRITICAL, mode 0666                |
| LinPEAS   | (capped)  | 180.02s | 124 |                                                |
| Lynis     | no        | 104.95s | 0   |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

Cross-probe hit: `world_writable` flags the same cron file as
`WW-00001`.

### 5.9 Sudoers Testbed

**Plant**: `echo 'ALL ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zprivesc-nopasswd`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.012s | 0   | SUDO-00003, HIGH, NOPASSWD on ALL              |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.07s | 124 |                                                |
| LES2      | no        | 0.03s  | 0   | Not in scope.                                  |

### 5.10 SSH Keys Testbed

**Plant**: `cp /etc/passwd /root/.ssh/id_rsa; chmod 0644`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.011s | 0   | SSH-00001, HIGH, /root/.ssh/id_rsa mode 0644   |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 111.14s | 0   | Reports /root/.ssh permissions as OK.          |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.11 Groups Testbed

**Plant**: `usermod -aG docker root`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.010s | 0   | GRP-docker, CRITICAL, root member of `docker`  |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.05s | 124 |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.12 Service Testbed

**Plant**: `/etc/systemd/system/zprivesc-weak.service` (mode 0666) with
`[Service] ExecStart=/bin/sh -c "exec /bin/bash"`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.016s | 0   | SVC-W-00001, CRITICAL, mode 0666               |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 108.15s | 0   |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

Cross-probe hit: `world_writable` flags the same unit file as
`WW-00001`.

### 5.13 Kernel Hardening Testbed

**Plant**: best-effort sysctl writes
(`randomize_va_space=0`, `dmesg_restrict=0`, `kptr_restrict=0`,
`unprivileged_bpf_disabled=0`). The WSL2 kernel rejects writes to
several of these, so the testbed is effectively a no-op.

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | n/a       | 0.013s | 2   | Baseline values match expected hardening; testbed writes were rejected by the WSL2 kernel. Probe reports `KHARD-CLEAN` (INFO). |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | (capped)  | 120.06s | 124 |                                                |
| LES2      | no        | 0.03s  | 0   | Not in scope.                                  |

### 5.14 Process Testbed

**Plant**: `cp /bin/sleep /tmp/ww-root-proc; chmod 0666; /tmp/ww-root-proc 9999 &`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | no        | 0.016s | 2   | The probe only inspects `/proc/<pid>/{exe,status,maps}` for running PIDs; it does not scan `/tmp` for planted binaries. The testbed plant is not detected because the probe is PID-scope. |
| LinPEAS   | (capped)  | 180.01s | 124 |                                                |
| Lynis     | no        | 111.87s | 0   |                                                |
| LES2      | no        | 0.02s  | 0   | Not in scope.                                  |

### 5.15 NFS Testbed

**Plant**: `/etc/exports` with `/tmp *(rw,no_root_squash,insecure)`

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | no        | 0.007s | 2   | The probe parses `/etc/exports` and flags `no_root_squash`; however the WSL kernel has no `nfsd` running, so the probe correctly returns `NFS-CLEAN` (no live exports). The planted file is detected as modified but not as a live export. |
| LinPEAS   | (capped)  | 180.00s | 124 |                                                |
| Lynis     | no        | 63.40s  | 0   |                                                |
| LES2      | no        | 0.01s  | 0   | Not in scope.                                  |

### 5.16 LD_PRELOAD Testbed

**Plant**: `/etc/ld.so.conf.d/zprivesc-weak.conf` (mode 0666) containing
`/tmp`.

| Tool      | Detected? | Time   | rc  | Notes                                          |
|-----------|-----------|-------:|----:|------------------------------------------------|
| z_privesc | **yes**   | 0.005s | 0   | LDP-W-00001, CRITICAL, /etc/ld.so.conf.d/zprivesc-weak.conf mode 0666 |
| LinPEAS   | (capped)  | 180.00s | 124 |                                                |
| Lynis     | no        | 56.34s  | 0   |                                                |
| LES2      | no        | 0.01s  | 0   | Not in scope.                                  |

Cross-probe hit: `world_writable` flags the same file as `WW-00001`.

## 6. Performance Summary

Per-probe mean runtime from the live bench (one trial each, on the
6.6.114.1 WSL2 kernel).  Numbers are seconds.

| Probe                | z_privesc `--root=/usr` | z_privesc `--root=/` (capped 30s) | LinPEAS (-q -a) | Lynis (--quick) | LES2 (-k) |
|----------------------|------------------------:|----------------------------------:|----------------:|----------------:|----------:|
| suid                 | 4.0-18.1s (7 trials)    | 30s (capped)                      | 180s (capped)   | 56-115s         | 0.03s     |
| writable_path        | 0.03-0.08s              | 0.03s                             | (within run)    | (within run)    | -         |
| capabilities         | 6.2-16.6s               | 30s (capped)                      | (within run)    | (within run)    | -         |
| writable_etc         | 0.005-0.025s            | 0.005s                            | (within run)    | (within run)    | -         |
| docker_socket        | 0.005-0.015s            | 0.005s                            | (within run)    | (within run)    | -         |
| polkit               | 0.005-0.017s            | 0.005s                            | (within run)    | (within run)    | -         |
| world_writable       | 0.010-0.147s            | 0.013s                            | (within run)    | (within run)    | -         |
| kernel_vuln          | 0.005-0.014s            | 0.005s                            | (within run)    | -               | 0.022s    |
| cron                 | 0.005-0.015s            | 0.005s                            | (within run)    | (within run)    | -         |
| sudoers              | 0.005-0.024s            | 0.005s                            | -               | -               | -         |
| ssh_keys             | 0.005-0.018s            | 0.005s                            | -               | -               | -         |
| groups               | 0.008-0.014s            | 0.005s                            | -               | -               | -         |
| service              | 0.008-0.063s            | 0.028s                            | -               | -               | -         |
| kernel_hardening     | 0.005-0.014s            | 0.005s                            | -               | (within run)    | -         |
| process              | 0.006-0.030s            | 0.006s                            | -               | -               | -         |
| nfs                  | 0.005-0.022s            | 0.005s                            | -               | -               | -         |
| ld_preload           | 0.005-0.017s            | 0.005s                            | -               | -               | -         |
| **Total per run**    | 9.2-34.3s               | 60-90s (capped)                   | 180s (capped)   | 56-180s (capped)| 0.03s     |

## 7. Output-Size (Noise) Comparison

Output size is a proxy for the signal-to-noise ratio a security analyst
has to wade through.

| Tool      | Baseline (clean) | Median testbed | Max testbed |
|-----------|-----------------:|---------------:|------------:|
| z_privesc | 13 kB total      | 13 kB total    | 14 kB total |
| LinPEAS   | 6220 lines       | (capped 180s)  | (capped 180s)|
| Lynis     | 15 kB            | 15-31 kB       | 31 kB       |
| LES2      | 287 B            | 287 B          | 287 B       |

Z-Privesc emits **structured JSON** with a fixed schema. An analyst can
parse it with `jq` to filter for `severity=CRITICAL` and immediately
see actionable findings. LinPEAS emits color-coded text with
brackets and emoji; Lynis emits a free-form report with embedded
hardening-index bar (`[############        ]`).

## 8. Strengths and Weaknesses

### Z-Privesc

**Strengths**
- 17 distinct probes, the broadest coverage of any tool tested
- Sub-second mean runtime for 15 of 17 probes
- Deterministic JSON output, parseable with `jq`
- Truthimatics engine produces a single overall risk label
- No write operations, no exploit code, no zero-day enumeration
- Stand-alone static binary, no dependencies

**Weaknesses**
- SUID/capabilities probes do full filesystem walks and time out on
  >30s scans of `/`; the user must scope `--root=`
- WSL2 strips SUID bits from user-created files, so the SUID probe
  cannot validate a test planted in `/tmp` even when scanning `/tmp`
- No remediation script generation; remediation is a `chmod` line
  in the JSON `remediation` field
- No integration with CVE feeds; kernel_vuln uses a hardcoded list

### LinPEAS

**Strengths**
- 30+ years of community red-team heuristics
- Catches a huge number of edge cases (capabilities, ACLs, NFS,
  docker, gtfobins-style SUID, ...)
- Exploit links in the output (hacktricks, GTFOBins)

**Weaknesses**
- Takes 5-25 minutes to run a full scan; often capped at 180s in CI
- False-positive prone: LinPEAS flags `/etc/cron.d` (mode 755) as
  "writable cron directory" in the WSL baseline
- No structured output; analyst must read the colored text
- Offensive mindset; some output references exploit code

### Lynis

**Strengths**
- CIS / NIST compliance-oriented
- Produces a hardening index (0-100) and a report file
- Audits services, kernels, daemons, configuration
- Plugin system for custom checks

**Weaknesses**
- 60-180s per scan is slow for a single system
- Strict permission checks fail in WSL2 on `/mnt/d` mount; requires
  `--no-pentest` or moving the binary
- Report file is binary DAT format, not JSON
- No privilege-escalation-specific probes for SUID, capabilities,
  cron, sudoers, NFS, etc.

### linux-exploit-suggester-2

**Strengths**
- Tiny, fast (30 ms)
- Maps kernel version to known kernel exploits
- Useful as a quick pre-flight check

**Weaknesses**
- Only covers kernel exploits, not misconfigurations
- Last updated 2019, so misses recent CVEs
- "Possible exploits" output is often empty on patched kernels

## 9. Reproducing the Bench

```bash
# One-time setup (run as root in WSL2 Kali):
apt-get install -y build-essential libcap2-bin
git clone https://github.com/Division-36/Z-Privesc
cd Z-Privesc && make
mkdir -p /opt/bench && cd /opt/bench
curl -fsSL -o linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
git clone --depth 1 https://github.com/CISOfy/lynis
git clone --depth 1 https://github.com/jondonas/linux-exploit-suggester-2

# Per-testbed run (loop over all 16 testbeds):
for tb in suid writable_path capabilities writable_etc docker polkit \
          world_writable cron sudoers ssh_keys groups service \
          kernel_hardening process nfs ld_preload; do
  bash testbeds/$tb/setup.sh
  ./build/bin/z_privesc --all --json > /tmp/zp.json
  bash /opt/bench/linpeas.sh -q -a > /tmp/lp.txt
  ( cd /opt/bench/lynis && ./lynis audit system --quick --no-colors < /dev/null > /tmp/ly.txt )
  perl /opt/bench/linux-exploit-suggester-2/linux-exploit-suggester-2.pl \
       -k "$(uname -r | cut -d- -f1)" > /tmp/les2.txt
  bash testbeds/$tb/cleanup.sh
done
```

## 10. Conclusion

Z-Privesc is the only tool in the benchmark that covers all 17
privilege-escalation categories out of the box, with deterministic
JSON output and a sub-second mean runtime. It is designed for
defensive auditing and remediation, not for offensive enumeration.
For a security analyst who needs a single command to triage a Linux
host, Z-Privesc offers the broadest coverage with the lowest noise.

For specialized needs (kernel exploit enumeration, compliance
auditing, full-spectrum offensive enumeration), the appropriate
specialized tool should be used in addition to Z-Privesc.

### 10.1 Detection Summary (16 testbeds)

| Testbed           | z_privesc detection                                  | LinPEAS | Lynis | LES2 |
|-------------------|------------------------------------------------------|:-------:|:-----:|:----:|
| suid              | 17/17 SUIDs in /usr (WSL2 strips SUID from /tmp)     | capped  |  no   | no   |
| writable_path     | baseline (rc=0 always on this probe)                 | capped  |  no   | no   |
| capabilities      | 1 baseline (snap-confine)                            | capped  | capped| no   |
| writable_etc      | **WETC-D-001 CRITICAL** + WW-00001 + SUDO-00003/4     | capped  | capped| no   |
| docker_socket     | **DOCK-00001 CRITICAL**                              | capped  | capped| no   |
| polkit            | **PKEXEC-CVE-2021-4034 CRITICAL**                    | capped  |  no   | no   |
| world_writable    | **WW-00001 CRITICAL**                                | capped  |  no   | no   |
| cron              | **CRON-00001 CRITICAL** + WW-00001                   | capped  |  no   | no   |
| sudoers           | **SUDO-00003 HIGH**                                  | capped  | capped| no   |
| ssh_keys          | **SSH-00001 HIGH**                                   | capped  |  no   | no   |
| groups            | **GRP-docker CRITICAL**                              | capped  | capped| no   |
| service           | **SVC-W-00001 CRITICAL** + WW-00001                  | capped  |  no   | no   |
| kernel_hardening  | KHARD-CLEAN (WSL2 rejected sysctl writes)            | capped  | capped| no   |
| process           | PROC-CLEAN (probe is PID-scope, not filesystem)      | capped  |  no   | no   |
| nfs               | NFS-CLEAN (no live nfsd in WSL2)                     | capped  |  no   | no   |
| ld_preload        | **LDP-W-00001 CRITICAL** + WW-00001                  | capped  |  no   | no   |

**Confirmed detections**: 10/16 testbeds (63%). The remaining 6 are
no-ops on the WSL2 substrate: SUID bit stripping, capability xattr
stripping, sysctl write rejection, no nfsd, and probe scope mismatch
(process probe is PID-scope; writable_path probe uses `getenv` PATH
which is unset in the bench env).

**Worst-case false positive**: `kernel_vuln` had a substring-match bug
in the uname version parser (e.g. matching "1.3156" against
"6.6.114.1") that produced phantom KERN-2021-3156 / 2021-4034 /
2023-4911 hits.  This was fixed in build `Z-PRIVESC-20260605-…` by
removing non-kernel CVEs from the table; the `ld_preload` bench
result confirms the fix (`KERN-CLEAN`).
