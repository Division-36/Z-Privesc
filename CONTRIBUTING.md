# Contributing to Z-Privesc

Z-Privesc is a security tool; the patch review bar is correspondingly
high.  Bug fixes and probe improvements are always welcome; new probes
are reviewed case-by-case against the existing chain architecture.

## Process

1. Fork the repository.
2. Create a feature branch from `main`.  Use a descriptive name such
   as `probe/sudoers-nopasswd` or `fix/suid-snap-skip`.
3. Make your changes.  See "Code style" below.
4. Add or update tests.  For new probes, also add a real
   `testbeds/<name>/setup.sh` and `cleanup.sh`.
5. Run `make test` and (if you have root in a VM) `make test-full`.
6. Push the branch and open a pull request against `main`.

## Code style

Z-Privesc follows K&R bracing, 4-space indentation (no tab characters),
80-character line limit, and a no-comments-in-implementation-files
policy.  Public API documentation lives in the headers, not in the
implementations.

- Function names use `zp_<module>_<action>()` - for example,
  `zp_probe_suid` or `zp_engine_decide()`.
- Type names use `zp_<thing>` - for example,
  `zp_evidence_chain`.
- Macros use `ZP_UPPER_CASE`.
- Every heap allocation is checked; OOM calls `abort()` after logging
  the failing allocation.
- External dependencies are forbidden.  POSIX libc and Linux kernel
  headers only.
- New code must compile cleanly with `-Wall -Wextra -Wpedantic
  -Werror`.
- All public functions must have a header doc comment describing
  purpose, parameters, return value, and ownership semantics.
- All public functions must validate their inputs and return a
  documented error code on failure.

## Tests

- Unit tests live in `tests/test_*.c` and are registered in
  `tests/test_cases.inc`.
- Integration tests live in `tests/test_integration.c` and depend on
  the `testbeds/<name>/setup.sh` and `cleanup.sh` scripts.
- Target coverage is >= 95% lines on probes and >= 90% on the engine.

## Reporting security issues

Please do **not** file public issues for security bugs.  Email
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com) instead.
See [SECURITY.md](SECURITY.md) for the full policy.
