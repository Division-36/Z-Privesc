# History

Z-Privesc is a spin-out of the Z-Jail project: a forensic jail
framework that needed a way to detect the misconfigurations its
defenders would care about most.  Once the probe set stabilised, it
made sense to release it as a standalone tool with its own release
cadence.

## Development timeline

- **2026-04-01** - Project bootstrap.  The first commit is a
  one-line `Makefile` and a placeholder `main.c` that prints the
  build ID.
- **2026-04-08** - `v0.1.0`: the binary builds and prints
  `--version`.  Probe registry is a single empty function pointer
  table.
- **2026-04-15** - First probe (`suid`) implemented; the evidence
  chain API is in place; the verdict engine is a stub that always
  returns UNCERTAIN.
- **2026-04-22** - `writable_path` and `world_writable` probes land.
  First end-to-end test against a deliberately-vulnerable Docker
  container.
- **2026-05-01** - `capabilities` and `writable_etc` probes land.
  Truthimatics majority-weighting engine becomes functional.
- **2026-05-12** - `v0.5.0` candidate release.  All eight probes
  produce well-formed evidence chains.  14 unit tests pass.
- **2026-05-19** - `docker_socket` and `polkit` probes land.  Risk
  aggregator gains a CVSS-like severity band mapping.
- **2026-05-25** - `kernel_vuln` probe gains its CVE table.
  Integration test runner (`tests/test_integration.c`) is now
  self-contained.
- **2026-05-28** - `v0.9.0` candidate for security review.
- **2026-06-01** - Documentation pass: README, ADRs, PROBES,
  ARCHITECTURE, TRUTHIMATICS, man page.
- **2026-06-03** - Release engineering: minisign signing,
  reproducible build, release tarball.
- **2026-06-04** - `v1.0.0` released.  First public tag.

## Notable design pivots

- The original `truthimatics` module planned to support
  Bayesian-network evidence propagation; this was simplified to a
  pure weighted-majority engine after the first review cycle
  showed the Bayesian model was over-engineered for the eight probe
  categories.
- The audit output was originally planned as YAML; JSON won on
  tooling availability (`jq`, GitHub Actions, GitLab CI all
  consume it natively).
- The world-writable probe originally scanned the entire
  filesystem; the SUID_MAX_FINDINGS / WW_MAX_FINDINGS cap and the
  curated SENSITIVE_DIRS list were added after a CI run hit the
  10-minute test timeout.
