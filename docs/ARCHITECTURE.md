# Architecture

Z-Privesc is structured as four layers.  Each layer has a narrow,
explicit contract with the one below it; nothing crosses the
boundary.

## Layer overview

```
+------------------------------------------------------+
|  L4 - Audit emitter  (JSON / HTML)                  |
+------------------------------------------------------+
|  L3 - Risk aggregator (per-finding, per-probe,      |
|                         overall)                    |
+------------------------------------------------------+
|  L2 - Truthimatics verdict engine                    |
+------------------------------------------------------+
|  L1 - Probe registry  (eight probes)                |
+------------------------------------------------------+
|  L0 - Host filesystem (/proc, /etc, /usr/bin, ...)  |
+------------------------------------------------------+
```

### L0 - Host

The Linux host.  Z-Privesc talks to it through POSIX `stat`,
`getxattr`, `opendir`, `/proc/self/status`, and `/proc/version`.
There is no kernel module, no `ptrace`, no `LD_PRELOAD` - the tool
runs as an ordinary userland binary.

### L1 - Probe registry

`include/probes.h` declares a single function-pointer type,
`zp_probe_fn`, and `src/probe_runner.c` exposes a static table of
probe entries.  A probe is a black box: it takes a
zero-initialised `zp_evidence_chain *` and a root path, runs
forever, and returns a status code.  The probe does not know
anything about the engine, the risk aggregator, or the audit
emitter.  This isolation is the project's most important
architectural property: probes are independent, individually
testable, and may be added or removed without touching the rest of
the binary.

### L2 - Truthimatics verdict engine

`src/truthimatics/evidence.c` implements the singly-linked evidence
chain.  `src/truthimatics/engine.c` walks the chain and applies a
majority-weighted verdict algorithm.  The algorithm is described in
detail in [TRUTHIMATICS.md](TRUTHIMATICS.md).

### L3 - Risk aggregator

`src/risk.c` converts each evidence link into a 0.0-10.0 score
based on its severity and weight, takes the worst finding per probe,
and emits an overall score with a five-band label.

### L4 - Audit emitter

`src/audit.c` walks the runtime's chains, builds an in-memory audit
context, and serialises it to JSON or HTML.  The schema
`z-privesc.audit/v1` is the public contract for downstream tooling.

## Control flow

1. `main.c` parses the CLI, initialises the runtime, and creates the
   audit context.
2. `probe_runner.c` walks the registered probes in order, calling
   each with a fresh chain.  The probe populates the chain.
3. For each probe, the engine decides the chain verdict, the risk
   aggregator computes the per-probe risk score, and the audit
   emitter records a `audit_probe_record` with the verdict, the
   evidence count, the risk score, and each finding.
4. After all probes have run, the runtime computes the overall risk
   and label, then emits the final document.

## Memory model

- The runtime and chains are allocated on the heap and released in
  reverse order of allocation.
- All allocations are checked; `zp_malloc` and `zp_calloc`
  abort on OOM after logging the failing request.
- No global mutable state is shared between probes.

## Concurrency

Z-Privesc is single-threaded by design.  Each probe runs to
completion before the next is dispatched, and the verdict
computation is deterministic given the chain contents.  The
internal logger is mutex-protected only because it writes to a
shared `FILE *` for the diagnostic stream.

## What deliberately is not in scope

- No persistent daemon, no remote control surface.
- No automatic remediation.  The tool reports and recommends; a
  human or an upstream patch must act.
- No integration with system package managers.  Updates are
  released as a tarball.
- No telemetry.  The tool does not phone home.
