# Z-Privesc

> A Linux privilege-escalation auditor that fuses eight security probes
> with the Truthimatics evidence engine and emits a CVSS-styled risk
> report.

[![Build](https://github.com/Division-36/Z-Privesc/actions/workflows/build.yml/badge.svg)](https://github.com/Division-36/Z-Privesc/actions)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A595%25-brightgreen)](docs/TRUTHIMATICS.md)
[![License: Z-Privesc v1.0](https://img.shields.io/badge/license-Z--Privesc%20v1.0-blue)](LICENSE)
[![Platform: Linux x86_64](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey)](docs/ARCHITECTURE.md)
[![Language: C17](https://img.shields.io/badge/language-C17-00599C)](https://en.cppreference.com/w/c/17)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-orange)](CHANGELOG.md)

## What is Z-Privesc?

Z-Privesc is a self-contained, zero-dependency privilege-escalation
audit tool written in C17. It walks a Linux system looking for the
eight most prevalent classes of misconfiguration that have historically
led to local root compromise. Each finding is recorded as a piece of
evidence and adjudicated by the [Truthimatics Public Version](docs/TRUTHIMATICS.md)
verdict engine. A CVSS-like risk score is computed per finding, per
probe, and for the system as a whole, then serialised to JSON and HTML.

The tool was written for one reason: a defensive administrator should be
able to find these problems before an attacker does.

## Architecture

```
                +----------------+
                |   CLI (main)   |
                +-------+--------+
                        |
                        v
                +----------------+
                | probe_runner   |
                +-------+--------+
                        |
        +-------+-------+-------+-------+-------+-------+-------+-------+
        v       v       v       v       v       v       v       v
    +------+ +-------+ +--------+ +-------+ +------+ +------+ +-----+ +------+
    | suid | | wpATH | | caps   | | wEtc  | | dock | | polk | | ww  | | kern |
    +--+---+ +---+---+ +----+---+ +---+---+ +---+--+ +---+--+ +---+-+ +---+--+
       |        |           |          |         |        |        |       |
       v        v           v          v         v        v        v       v
              +-------------------------------------------------------+
               |            zp_evidence_chain (per probe)              |
              +---------------------------+---------------------------+
                                          |
                                          v
                                +---------------------+
                                |  Truthimatics       |
                                |  verdict engine     |
                                +----------+----------+
                                           |
                                           v
                                +---------------------+
                                |  risk aggregator    |
                                +----------+----------+
                                           |
                                           v
                                +---------------------+
                                |  audit emitter      |
                                |  (JSON / HTML)      |
                                +---------------------+
```

## Quick start

```sh
git clone https://github.com/Division-36/Z-Privesc
cd Z-Privesc
make
./build/bin/z_privesc --all --json | jq
```

Build, test, and install:

```sh
make test           # unit tests
make test-full      # integration tests on real testbeds (root)
make coverage       # gcov coverage report
make install        # install to /usr/local
man z_privesc       # read the man page
```

## Probes

| Name             | Category                          | Severity ceiling |
|------------------|-----------------------------------|------------------|
| `suid`           | SUID / SGID binary scan           | CRITICAL         |
| `writable_path`  | World-writable $PATH entries      | CRITICAL         |
| `capabilities`   | File / process Linux capabilities| HIGH             |
| `writable_etc`   | Writable /etc authentication files| CRITICAL         |
| `docker_socket`  | Exposed Docker control socket     | CRITICAL         |
| `polkit`         | polkit / pkexec misconfigurations | CRITICAL         |
| `world_writable` | World-writable sensitive files    | CRITICAL         |
| `kernel_vuln`    | Kernel version CVE matcher        | CRITICAL         |

See [docs/PROBES.md](docs/PROBES.md) for the rationale behind each
probe, the evidence weighting strategy, and the false-positive
mitigations applied.

## Verdict and risk

The Truthimatics engine assigns each evidence chain one of three
verdicts:

- **DETERMINISTIC** - a confirmed privilege-escalation path.
- **REJECT**        - no vulnerability found by this probe.
- **UNCERTAIN**     - the evidence is suspicious but not conclusive.

Risk is computed separately on a 0.0 to 10.0 scale (CVSS-like), with a
per-probe and a per-system label (`INFO` / `LOW` / `MEDIUM` / `HIGH` /
`CRITICAL`).

## Exit codes

| Code | Meaning                                                |
|------|--------------------------------------------------------|
| 0    | No privilege-escalation paths found                    |
| 1    | Probe execution error                                  |
| 2    | At least one DETERMINISTIC finding (vulnerable)        |
| 125  | Internal error (out of memory, argument failure)       |

## Feature comparison

| Capability                                       | Z-Privesc | LinPEAS | Lynis | linux-exploit-suggester |
|--------------------------------------------------|:---------:|:-------:|:-----:|:-----------------------:|
| Static binary, zero dependencies                 |    Yes    |   No    |  No   |           No            |
| Deterministic evidence-based verdicts            |    Yes    |   No    |  No   |           No            |
| CVSS-like risk aggregation                       |    Yes    |   No    |  No   |           No            |
| 8 categories out of the box                      |    Yes    |  Yes (broad) | Yes (broad) | Yes (broad) |
| Documented Threat Model                          |    Yes    | Partial |  No   |           No            |
| Stable machine-readable output schema            |  v1 (JSON) |  None  |  None |          None           |
| Per-finding remediation guidance                 |    Yes    |  Partial |  No   |          No            |
| Adversarial-resistant reporting                  |    Yes    |   No    |  No   |           No            |
| Runs in offline air-gapped environments          |    Yes    |   Yes   |  Yes  |          Yes            |
| License                                         | Z-Privesc v1.0 |  GPL-3  |  GPL  |          GPL-2          |

## Threat model

The defender is assumed to control a Linux host on which they have
non-root shell access. The attacker is a local unprivileged user who
has landed a shell, terminal, or script-execution primitive on the
same host. The attacker is **not** assumed to have prior root, kernel
memory corruption primitives, or physical access. The attacker's goal
is to escalate to a root-level security context.

Out of scope: remote network attacks, kernel exploit reliability
guarantees, side-channel attacks on shared hardware, denial of service.

## Sample output

```json
{
  "schema": "z-privesc.audit/v1",
  "build_id": "Z-PRIVESC-20260604-XXXXXXXX",
  "timestamp": 1717459200,
  "duration_ns": 123456789,
  "hostname": "victim-box",
  "kernel": "5.15.0-113-generic",
  "user": "bob",
  "uid": 1000,
  "overall_risk": 7.4,
  "risk_label": "HIGH",
  "probes": [
    {
      "name": "suid",
      "verdict": "DETERMINISTIC",
      "evidence_count": 3,
      "risk_score": 8.2,
      "findings": [
        {
          "id": "SUID-001",
          "target": "/tmp/bash-root-suid",
          "weight": 0.95,
          "severity": "CRITICAL",
          "description": "Root-owned SUID binary 'bash-root-suid' (dangerous basename)",
          "remediation": "Remove the SUID bit: chmod u-s /tmp/bash-root-suid"
        }
      ]
    }
  ]
}
```

## Security disclosure

Please report security issues to
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com).  See
[SECURITY.md](SECURITY.md) for our coordinated disclosure policy.

## License

Copyright (c) 2026 Zierax (Ziad Salah). Released under the
[Z-Privesc Public License v1.0](LICENSE).

