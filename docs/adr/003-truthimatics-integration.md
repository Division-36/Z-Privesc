# ADR 003 - Truthimatics integration: simple engine, separate risk

- **Status**: Accepted.
- **Date**: 2026-04-30.
- **Authors**: Zierax.

## Context

The Truthimatics engine must produce a *verdict* (a categorical
decision) for each probe.  Independently, Z-Privesc must produce
a *risk score* (a numeric 0.0 - 10.0) for the audit report.
These are two different concerns.  Some early designs conflated
them - the verdict was the score, or the score was the verdict.
In practice that produced awkward outputs: a chain with one
MEDIUM finding and a chain with five CRITICAL findings were
both "DETERMINISTIC" but had very different operational
implications.

## Decision

Keep the verdict and the risk score in two separate modules:

- `src/truthimatics/engine.c` decides the verdict.  The output is
  one of `DETERMINISTIC`, `REJECT`, `UNCERTAIN`.
- `src/risk.c` computes the score.  The output is a float in
  `[0.0, 10.0]` plus a band label.

The two modules are independent: the engine does not look at
severity, and the risk module does not look at the verdict.

## Consequences

- The JSON output carries both a `verdict` (string) and a
  `risk_score` (float) per probe and per finding.  Operators can
  triage on the score and explain the decision on the verdict.
- The risk module is unit-testable without standing up the
  engine.
- The two modules can be evolved independently.  A future release
  could adopt a different risk formula (e.g. CVSS 4.0) without
  touching the engine.
- A reader of the source may notice the two modules use
  overlapping but not identical severity bands.  This is
  intentional; the engine treats severity as a tie-breaker hint,
  while the risk module treats it as the dominant variable.
