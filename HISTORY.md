# History

Z-Privesc is a spin-out of the Z-Jail project: a forensic jail
framework that needed a way to detect the misconfigurations its
defenders would care about most.  Once the probe set stabilised, it
made sense to release it as a standalone tool with its own release
cadence.

## Development timeline

- **2026-06-04** - Project bootstrap. Initial commit, `main.c`,
  `Makefile`, and project scaffolding.
- **2026-06-04** - `feat: initial MVP` — core probes (suid,
  writable_path) operational with evidence chain API.
- **2026-06-04** - `fix: edge cases` and `test: enhanced tests`.
- **2026-06-04** - `init: truthimatics engine`, `feat: probes`,
  `feat: risk model` — all probes self-contained with risk
  aggregation.
- **2026-06-05** - Extensive improvement batch: audit output, logging,
  risk model, probes, util functions, config, groups, Makefile,
  integration tests, man page, README.
- **2026-06-06** - `init: version: release 1.0.0` — first tagged
  release.

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
