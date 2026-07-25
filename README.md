# Z-Privesc

> A purpose-built Linux privilege-escalation auditor. Seventeen
> probes. Deterministic verdicts. Honest accuracy numbers.

[![Build](https://github.com/Division-36/Z-Privesc/actions/workflows/build.yml/badge.svg)](https://github.com/Division-36/Z-Privesc/actions)
[![Tests](https://github.com/Division-36/Z-Privesc/actions/workflows/tests.yml/badge.svg)](https://github.com/Division-36/Z-Privesc/actions)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A595%25-brightgreen)](docs/TRUTHIMATICS.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-orange)](CHANGELOG.md)

## What it does

Z-Privesc walks a Linux system looking for the seventeen most
prevalent classes of misconfiguration that lead to local root
compromise. Each finding is evaluated by the Truthimatics verdict
engine, producing a deterministic report with a CVSS-like risk score.

It is not a compliance scanner. It answers one question: **can an
unprivileged user on this box get root, right now?**

## Quick start

```sh
git clone https://github.com/Division-36/Z-Privesc
cd Z-Privesc
make
./build/bin/z_privesc --all --json | jq
```

## Accuracy

Measured against a 37-target ground-truth corpus across two distros
(Kali WSL2 + Ubuntu 26.04 multipass):

| Metric | Value |
|--------|-------|
| Detection recall | **1.000** (37/37) |
| Path recall | **0.943** (33/35) |
| Path precision | **0.971** (33/34) |
| False positives on planted targets | **0** |
| Brier score | 0.109 |
| Scan time (full) | 2.65 s |

Head-to-head on identical Ubuntu 26.04 VM:

| Tool | Version | Scan time | Output |
|------|---------|-----------|--------|
| **Z-Privesc** | 1.0.0 | **2.65 s** | 40 structured findings |
| Lynis | 3.1.6 | 100.45 s | 850 lines |
| LinPEAS | latest | 120.03 s | 378 lines |

See [benchmarks.md](benchmarks.md) for full methodology and
[docs/EVALUATION.md](docs/EVALUATION.md) for reproduction.

## Probes

| Name | What it checks | Severity |
|------|---------------|----------|
| `suid` | SUID/SGID binaries | CRITICAL |
| `writable_path` | World-writable $PATH entries | CRITICAL |
| `capabilities` | File/process Linux capabilities | HIGH |
| `writable_etc` | Writable /etc auth files | CRITICAL |
| `docker_socket` | Exposed Docker control socket | CRITICAL |
| `polkit` | polkit/pkexec misconfigurations | CRITICAL |
| `world_writable` | World-writable sensitive files | CRITICAL |
| `kernel_vuln` | Kernel version CVE matcher | CRITICAL |
| `cron` | Cron job misconfigurations | CRITICAL |
| `sudoers` | Sudoers rule audit | CRITICAL |
| `ssh_keys` | SSH private key permissions | HIGH |
| `groups` | Privileged group membership | CRITICAL |
| `service` | Systemd/SysV unit audit | CRITICAL |
| `kernel_hardening` | Weak sysctl values | MEDIUM |
| `process` | Root process binary audit | HIGH |
| `nfs` | NFS export misconfigurations | CRITICAL |
| `ld_preload` | LD_PRELOAD/ld.so.conf audit | CRITICAL |

See [docs/PROBES.md](docs/PROBES.md) for rationale and
false-positive mitigations.

## Verdict engine

The Truthimatics engine assigns each evidence chain one of three
verdicts:

- **DETERMINISTIC** -- a confirmed privilege-escalation path.
- **REJECT** -- no vulnerability found by this probe.
- **UNCERTAIN** -- suspicious but not conclusive.

Risk is scored 0.0--10.0 (CVSS-like) with per-finding, per-probe,
and system-wide labels: INFO / LOW / MEDIUM / HIGH / CRITICAL.

## Build

```sh
make              # build binary
make test         # unit tests (58/58)
make test-full    # integration tests (requires root in VM)
make static       # portable static binary
make coverage     # gcov coverage report
make install      # install to /usr/local
```

Requires: `gcc`, `make`, `libcap-dev` (optional, for capabilities).

## Architecture

```
CLI (main) -> probe_runner -> [17 probe modules]
                                    |
                              evidence chains
                                    |
                              Truthimatics engine
                                    |
                              risk aggregator
                                    |
                              audit emitter (JSON/HTML)
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No privilege-escalation paths found |
| 1 | Probe execution error |
| 2 | At least one DETERMINISTIC finding |
| 125 | Internal error |

## Feature comparison

| Capability | Z-Privesc | LinPEAS | Lynis |
|-----------|:---------:|:-------:|:-----:|
| Static binary, zero deps | Yes | No | No |
| Deterministic verdicts | Yes | No | No |
| CVSS-like risk scoring | Yes | No | No |
| 17 categories out of the box | Yes | Broad | Broad |
| Machine-readable schema (JSON) | v1 | None | None |
| Per-finding remediation | Yes | Partial | No |
| Offline/air-gapped | Yes | Yes | Yes |
| License | MIT | GPL-3 | GPL |

## Threat model

**In scope:** local unprivileged user on a Linux host attempting
privilege escalation to root.

**Out of scope:** remote attacks, kernel exploit reliability, side
channels, denial of service.

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) -- system design
- [PROBES.md](docs/PROBES.md) -- probe rationale
- [TRUTHIMATICS.md](docs/TRUTHIMATICS.md) -- verdict engine
- [COMPOSITION.md](docs/COMPOSITION.md) -- exploitability graph
- [EVALUATION.md](docs/EVALUATION.md) -- reproduction guide
- [benchmarks.md](benchmarks.md) -- full benchmark data
- [CONTRIBUTING.md](CONTRIBUTING.md) -- development guide
- [SECURITY.md](SECURITY.md) -- vulnerability disclosure

## Security

Report security issues to
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com).
See [SECURITY.md](SECURITY.md) for disclosure policy.

## License

Copyright (c) 2026 Zierax (Ziad Salah). Released under the
[MIT License](LICENSE).
