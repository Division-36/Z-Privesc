# ADR 001 - Layered architecture with explicit contracts

- **Status**: Accepted.
- **Date**: 2026-04-04.
- **Authors**: Zierax.

## Context

The first Z-Privesc prototype was a single 600-line `main.c` that
walked the filesystem, made verdicts, and printed output.  Within
two weeks of development it had become impossible to reason
about.  False-positive debugging crossed module boundaries; unit
testing required standing up the entire binary; adding a new
probe meant editing the runner, the engine, the risk aggregator,
and the JSON emitter at once.

## Decision

Adopt a four-layer architecture (probes / engine / risk /
audit).  Each layer exposes a narrow, explicit contract with the
layer below.  A probe knows nothing about the engine, the engine
knows nothing about the risk aggregator, and so on.

## Consequences

- Probes are individually unit-testable without standing up the
  rest of the binary.  A test can construct a chain, run a
  probe, and assert on the chain contents.
- Adding a new probe requires editing exactly one file in
  `src/probes/` and one line in `src/probe_runner.c`.
- The audit emitter is decoupled from the engine; the JSON
  schema can evolve without touching the verdict logic.
- The total binary is larger than a tightly-coupled alternative
  would be.  We accept this; clarity and testability are worth
  more than a few kilobytes of code.

## Alternatives considered

- **Single-translation-unit design** - rejected because of the
  rapid entropy of the prototype.
- **Plugin model** - rejected for v1; plugin loading adds
  significant complexity (ABI stability, signature
  verification) and the probe surface is small enough to be
  statically known.
