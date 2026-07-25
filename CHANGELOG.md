# Changelog

All notable changes to Z-Privesc are recorded in this file.  Versions
follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-25

### Expanded evaluation
- 37-target ground-truth corpus: 35 targets on Kali WSL2, 2 on
  Ubuntu 26.04 multipass VM. Detection recall **1.000** (37/37),
  path recall **0.943** (33/35), zero false positives on planted
  targets.
- Multi-distro verification across kernel 6.18 (WSL2) and kernel
  7.0 (Ubuntu 26.04).
- Head-to-head benchmark against LinPEAS and Lynis on identical VM.
  Z-Privesc: 2.65s full scan. Lynis: 100.45s. LinPEAS: 120.03s.
- Full accuracy data: benchmarks/data/accuracy/accuracy.json.
- Reproduction guide: docs/EVALUATION.md.

### Probe improvements
- NFS probe rewritten: standard host(options) export format parsing.
- Service probe enhanced: SysV init.d directory scanning alongside
  systemd unit files.
- Writable_path probe hardened: PATH injection via relative entries.
- Kernel_hardening probe fixed: /proc/ path prefix handling.
- Process probe fixed: compiled binary testbed (shell script exe
  symlink pointed to interpreter, not the script).

### CI/CD
- Release workflow: tag-triggered, multi-arch (x86_64 + aarch64),
  tests gate, GitHub Release with SHA-256 checksums.
- CodeQL security scanning (schedule-only for private repo).
- Dependabot: weekly GitHub Actions version updates.
- Build workflow: hardening verification (RELRO, stack canary).
- Coverage workflow: runs on PRs, suppresses -O0-only warnings.

### Fixed
- RELRO check regex for ubuntu-22.04 linker output.
- test_integration.c: block comment contained */ in glob pattern.
- Release aarch64: skip smoke test (can't execute cross-compiled
  binary on x86_64 runner).
- Coverage build: format-truncation warning at -O0 + -Werror.
- Documentation contradictions: kernel versions and OS references
  aligned with actual benchmark data.

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
