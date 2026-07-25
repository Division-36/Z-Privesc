# ADR 002 - Probe design: real, bounded, read-only

- **Status**: Accepted.
- **Date**: 2026-04-12.
- **Authors**: Zierax.

## Context

Privilege-escalation auditing tools must balance coverage
(catch every relevant misconfiguration) against
predictability (don't accidentally trigger kernel panics, don't
exhaust disk, don't open network connections).  Tools that
default to broad filesystem walks can take many minutes on a
modest system, which is incompatible with CI usage.

## Decision

Every probe must satisfy three properties:

1. **Real** - it inspects the actual host.  It does not consult
   a static database.  When a new polkit version ships, the
   probe sees it on the next run; no DB update required.
2. **Bounded** - it caps its work with a depth limit and a
   findings cap.  The default depth is 8 for filesystem walks;
   the default findings cap is 4096 per probe.  These limits
   are tuneable per probe, not globally.
3. **Read-only** - it never modifies the host.  The single
   exception is the Docker socket probe, which performs a
   non-destructive `GET /_ping` HTTP request; this is the
   Docker daemon's own health-check, and is safe by design.

## Consequences

- Tests run quickly enough to be invoked from `make test` on
  every commit.
- An entire-`/` scan completes in seconds on a typical 1 TB
  filesystem.
- The findings cap means that a system with > 4096 SUID
  binaries will not be exhaustively audited; the report will
  contain a sampling.  The SUID_MAX_FINDINGS constant in
  `src/probes/suid.c` documents this trade-off.
- The read-only property means a system operator can run the
  tool in production without a change-window.
