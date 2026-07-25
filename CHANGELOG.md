# Changelog

All notable changes to Z-Privesc are recorded in this file.  Versions
follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-06-06

### Added
- 17 probes: `suid`, `writable_path`, `capabilities`,
  `writable_etc`, `docker_socket`, `polkit`, `world_writable`,
  `kernel_vuln`, `cron`, `sudoers`, `nfs`, `ssh_keys`,
  `ld_preload`, `groups`, `process`, `service`, `kernel_hardening`.
- Truthimatics Public Version verdict engine with majority-weighted
  chain adjudication and dominant-link override.
- CVSS-like risk aggregator (per-finding, per-probe, overall) with
  five-band label mapping (INFO / LOW / MEDIUM / HIGH / CRITICAL).
- JSON and HTML audit emitters conforming to schema
  `z-privesc.audit/v1`.
- BLAKE2b-256 + HMAC cryptographic evidence signing and verification.
- Per-build identifier surfaced in `--version`, JSON output, and log banner.
- Real, root-driven integration testbed for every probe category.
- 44+ unit tests covering the verdict engine, risk aggregator, audit
  emitter, crypto, util layer, and every probe in isolation.
- Man page (`man/z_privesc.1`), README, four ADRs, and full
  architecture / probes / truthimatics documentation set.
- GitHub Actions workflows for build, tests, and coverage.
- minisign-signed release tarball workflow with documented verification.
- CLI flags: `--quiet`, `--verbose`, `--probe=NAME`.

### Changed
- Initial public release; no prior versions exist.

### Security
- All filesystem probes are read-only by default.  The Docker socket
  probe performs a non-destructive `GET /_ping` over the socket when
  one is detected.
- Evidence chains are signed with HMAC-BLAKE2b to guarantee integrity.

## [0.9.0] - 2026-05-28

### Added
- Candidate release used for the v1.0.0 security review.
- Truthimatics engine extracted into a standalone module
  (`truthimatics/{engine,evidence}.c`).

## [0.5.0] - 2026-05-12

### Added
- Initial probe scaffold: every probe in `src/probes/` produces a
  well-formed evidence chain on a clean Ubuntu 22.04 VM.
- CLI argument parser.

## [0.1.0] - 2026-04-08

### Added
- Project bootstrap.  `make` produces a binary that prints
  `--version` and exits.
