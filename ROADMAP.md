# Roadmap

This document sketches the planned trajectory of Z-Privesc.  Dates
and exact feature lists are aspirational; only the `v1` column is
committed.

## v1 - shipped (2026-06-06)

- 17 probes covering SUID, capabilities, writable paths, cron, sudoers,
  NFS, SSH, LD_PRELOAD, groups, docker, polkit, kernel vulns, services,
  processes, and kernel hardening.
- Truthimatics Public Version verdict engine with majority-weighted voting.
- CVSS-like risk aggregator (0.0-10.0 with severity bands).
- JSON and HTML audit emitters, schema `z-privesc.audit/v1`.
- BLAKE2b-256 + HMAC cryptographic evidence signing.
- Per-build identifier, minisign-signed releases.
- Unit and integration tests, gcov coverage.

## Future

- **Probe runtime: WASM** - allow third-party probes to be shipped
  as WebAssembly modules and loaded at start-up, with the same
  evidence-chain contract enforced.
- **Distributed audit** - aggregate findings from many hosts into a
  single dashboard-friendly document.
- **Plugin model: signature updates** - signed probe-rule updates
  that can be applied without rebuilding the binary.
- **Educational mode** - an interactive walk-through that explains
  *why* a particular finding is dangerous, in addition to *what*
  it is.

## Non-goals

Z-Privesc will not:

- Become a remote network scanner.  It audits the local host only.
- Attempt to **exploit** any finding.  The tool's job is to report,
  not to demonstrate.
- Be rewritten in another language.  The C17 implementation is a
  deliberate design constraint and a security feature.
