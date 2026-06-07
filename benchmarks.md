# Z-Privesc Benchmark Report (v1.0.0)

**Build ID**: Z-PRIVESC-20260607-165da370
**Git SHA**: 165da370
**Date**: 2026-06-07

## System

```
OS:   Linux DESKTOP-RT51LKN 6.6.114.1-microsoft-standard-WSL2
GCC:  gcc (Debian 15.2.0-17) 15.2.0
Dist: Debian (WSL2)
```

## Build

| Metric              | Value       |
|---------------------|------------:|
| Compile time        | 5.348s      |
| Dynamic binary size | 89,960 B    |
| Static build time   | 14.225s     |
| Static binary size  | 1,209,448 B |
| Stripped static     | 1,087,984 B |

## Test Suite (60 cases)

| Metric     | Count    |
|------------|---------:|
| Passed     | 58       |
| Failed     | 0        |
| Skipped    | 2        |
| Total time | 16.520s  |

Two tests skip on permission-restricted or root-only environments
(`polkit_old_version_match` needs policykit-1; `capabilities_long_paths`
needs xattr support on the underlying filesystem).

## Probe Coverage (17 probes)

Z-Privesc implements 17 distinct privilege-escalation probes:

1.  suid
2.  writable_path
3.  capabilities
4.  writable_etc
5.  docker_socket
6.  polkit
7.  world_writable
8.  kernel_vuln
9.  cron
10. sudoers
11. ssh_keys
12. groups
13. service
14. kernel_hardening
15. process
16. nfs
17. ld_preload

## Runtime vs. Other Tools

| Tool      | Typical full-scan time | Output format  | Structured JSON |
|-----------|----------------------:|----------------|:---------------:|
| Z-Privesc | 5-30s (configurable)  | JSON + terminal | yes             |
| LinPEAS   | 60-300s               | color text      | no              |
| Lynis     | 60-180s               | binary DAT      | no              |
| LES2      | <0.1s                 | text            | no              |

## Weaknesses

- SUID/capabilities probes do full filesystem walks
- kernel_vuln uses a hardcoded CVE table (no live feed)
- No remediation script generation
- WSL2 strips SUID/xattr from /tmp files, limiting testability on WSL

## Reproducing

```bash
make clean && make test
```
