# History

Z-Privesc is a spin-out of the Z-Jail project: a forensic jail
framework that needed a way to detect the misconfigurations its
defenders would care about most.  Once the probe set stabilised, it
made sense to release it as a standalone tool with its own release
cadence.

## Development timeline

- **2026-05-15** — Project bootstrap. Initial commit (MIT), and
  project scaffolding.
- **2026-05-16** — Build system (Makefile), CI workflow, core type
  definitions and CLI argument struct.
- **2026-05-17** — Public API headers: util, log, truthimatics
  (evidence chain + verdict engine), and probe interface/registry.
- **2026-05-18** — Remaining headers: risk aggregator, audit context
  and emitter, crypto (BLAKE2b-256, HMAC).
- **2026-05-19** — Core implementation batch: util (path joining,
  file stat, hex encode), log (leveled logger with timestamp/color),
  truthimatics (evidence chain linked list).
- **2026-05-20** — Core implementation continued: truthimatics
  (weighted-majority engine), risk (CVSS-like scoring), audit
  (JSON and HTML emitters).
- **2026-05-21** — Core implementation continued: crypto, probe
  runner (registry and dispatch), main (CLI parser and loop).
- **2026-05-22** — All 17 probes implemented: suid, capabilities,
  writable_path, writable_etc, docker_socket, polkit,
  world_writable, kernel_vuln, cron, sudoers, ssh_keys, groups,
  service, kernel_hardening, process, nfs, ld_preload.
- **2026-05-24** — Test suites for all components: util,
  truthimatics, risk, audit, suid, capabilities, writable_path,
  writable_etc, docker_socket, polkit, world_writable, kernel_vuln,
  test_main runner, integration tests.
- **2026-05-26** — Documentation: ARCHITECTURE.md, PROBES.md,
  TRUTHIMATICS.md, ADRs, man page.
- **2026-05-27** — Testbeds (harness scripts) for all 17 probes.
- **2026-05-30** — Reports and remaining project files.
- **2026-05-31** — Feature batch 1: suid dangerous basename matching,
  writable_path priority scoring, capabilities critical filter,
  writable_etc security file scanning, docker_socket HTTP ping test.
- **2026-06-01** — Feature batch 2: polkit CVE-2021-4034 detection,
  world_writable sticky bit check, kernel_vuln CVE database expansion,
  cron wildcard injection detection, sudoers NOPASSWD/ALL detection.
- **2026-06-02** — Feature batch 3: ssh_keys key name patterns,
  groups privileged group list, nfs no_root_squash parsing,
  ld_preload ld.so.conf scan, process deleted binary detection,
  service .d directory recursion, kernel_hardening sysctl checks.
- **2026-06-03** — Feature batch 4: audit HTML badge styling,
  main --quiet/--verbose flags, risk multi-chain bonus,
  truthimatics severity string conversion.
- **2026-06-04** — Feature batch 5: main --probe=NAME selective
  execution, probe_runner hostname/kernel/username, util helpers
  (monotonic clock, hostname), audit timestamps, log progress
  indicator.
- **2026-06-05** — Bug fixes: buffer overflow in path_join,
  permission denied in suid scan, risk score clamping, test fixes
  (WSL2 SUID skip, umask, polkit skip on patched systems).
- **2026-06-06** — Pre-release cleanup, version bumps
  (1.0.0-rc1 → rc2 → 1.0.0), final release commit.
- **2026-06-07** — Post-release fixes: audit_ctx_release memory
  leak, capabilities buffer overflow, dead code removal.
- **2026-07-14** — Expanded evaluation framework: 37-target ground-truth
  corpus with multi-distro verification (Kali WSL2 + Ubuntu 22.04 LTS
  multipass). 35 targets on WSL2, 2 on multipass (kernel_hardening,
  process_root require real sysctl/process access).
- **2026-07-14** — Benchmarks remade with head-to-head comparison against
  LinPEAS and Lynis. Timing runs used an Ubuntu 26.04 multipass VM
  (kernel 7.0.0-27-generic); the accuracy data in benchmarks/data/accuracy/
  was captured on the Ubuntu 22.04 LTS VM.
- **2026-07-14** — NFS probe rewritten to handle standard
  host(options) export format. Service probe enhanced with SysV init.d
  scanning. Writable_path probe hardened against PATH injection.
- **2026-07-15** — Documentation overhaul: docs/COMPOSITION.md
  (exploitability composition engine), docs/EVALUATION.md (reproduction
  guide), docs/PROBES.md (17 probe rationales), four ADRs.
- **2026-07-20** — Bug fixes: kernel_hardening path prefix bug
  (stripped leading / instead of keeping proc/), process probe compiled
  binary testbed (shell scripts' exe symlink pointed to interpreter).
- **2026-07-25** — CI/CD overhaul: release.yml (multi-arch x86_64 +
  aarch64), codeql.yml (security scanning), dependabot.yml (actions
  updates), hardening verification in build workflow. All 5 workflows
  passing on GitHub Actions.
- **2026-07-25** — Technical debt cleanup: deleted ~22 redundant
  scripts, rewrote .gitignore, fixed all documentation contradictions
  (kernel versions, OS references), updated man page and --help for all
  17 probes.

## Notable design pivots

- The original `truthimatics` module planned to support
  Bayesian-network evidence propagation; this was simplified to a
  pure weighted-majority engine after the first review cycle
  showed the Bayesian model was over-engineered for the small early
  probe set.
- The audit output was originally planned as YAML; JSON won on
  tooling availability (`jq`, GitHub Actions, GitLab CI all
  consume it natively).
- The world-writable probe originally scanned the entire
  filesystem; the SUID_MAX_FINDINGS / WW_MAX_FINDINGS cap and the
  curated SENSITIVE_DIRS list were added after a CI run hit the
  10-minute test timeout.
