# Truthimatics Public Version

The verdict engine in Z-Privesc is the **Truthimatics Public
Version** - the same design used in the Z-Jail project, made
public.  It is intentionally simple, deterministic, and easy to
reason about.

## Concepts

### Evidence

A single observation about the host.  An evidence link carries:

- `id`         - a unique identifier within the chain (e.g.
                 `SUID-001`).
- `target`     - the filesystem path, process, or config key the
                 evidence pertains to.
- `description` - a human-readable summary.
- `remediation` - a human-readable fix recommendation.
- `weight`     - a float in `[0.0, 1.0]`, the engine's confidence
                 in this single piece of evidence.
- `verdict`    - the per-evidence verdict:
  - `DETERMINISTIC` - this evidence, on its own, confirms a
    vulnerability.
  - `REJECT`        - this evidence, on its own, refutes a
    vulnerability.
  - `UNCERTAIN`     - this evidence is suspicious but not
    conclusive.
- `severity`   - one of `INFO`, `LOW`, `MEDIUM`, `HIGH`,
  `CRITICAL`.  Drives risk scoring, not the verdict.
- `next`       - next link in the chain (singly linked).

### Chain

A singly linked list of evidence links, owned by a single probe.
The chain maintains running totals of the per-verdict weight sums
so the engine can decide in a single pass.

## Decision algorithm

Given a chain with `N` links and total weight `W`:

1. If the chain is empty -> `UNCERTAIN`.
2. If the sum of `REJECT` weights exceeds `0.5 * W` -> `REJECT`.
3. Otherwise, take the verdict with the largest weighted share.
4. Tie-breakers: `REJECT` beats `UNCERTAIN`; `UNCERTAIN` beats
   `DETERMINISTIC` (we under-report rather than over-report).
5. **Dominant link override**: if any single link's weight is
   greater than `0.5 * W`, that link's verdict is adopted.  This
   is the most consequential rule: a single high-confidence
   finding can dominate a chain that also contains weak
   contradictory evidence.

The algorithm is implemented in
`src/truthimatics/engine.c` (`zp_engine_decide`).

## Worked examples

### Example 1 - SUID scan of a clean box

The SUID probe finds `/usr/bin/sudo`, `/usr/bin/passwd`,
`/usr/bin/mount`, etc. - all medium-confidence, all
DETERMINISTIC.  Sum of REJECT weights is zero.  Sum of
DETERMINISTIC weights is non-zero and dominates UNCERTAIN.  No
single link is > 0.5 * W, so the engine's plurality pick is
DETERMINISTIC.  The probe reports DETERMINISTIC.

### Example 2 - Single bad apple

The SUID probe finds `/usr/bin/sudo` at weight 0.5 and
`/tmp/bash-root-suid` at weight 0.95.  Total `W = 1.45`.  The
dominant link rule fires because `0.95 > 0.5 * 1.45 = 0.725`.
The engine adopts the dominant link's verdict (DETERMINISTIC).

### Example 3 - Sticky-bit violation in a hardened box

The `world_writable` probe finds one missing sticky bit on
`/dev/shm` (HIGH, weight 0.85) and 30 stale reject findings from
policy templates (REJECT, weight 0.05 each).  Sum REJECT = 1.5,
sum DETERMINISTIC = 0.85.  Total `W = 2.35`.  The dominant link
override does not fire (`0.85 < 0.5 * 2.35 = 1.175`).  The
engine picks DETERMINISTIC by plurality, but the report's
overall risk is just HIGH - the per-finding severity is what
the auditor should read, not the chain verdict.

## Why not bayes?

The early prototype modelled evidence as a Bayesian network.  In
review, the marginal accuracy improvement over weighted plurality
was small (within the testbed noise floor), and the model added
significant cognitive overhead for reviewers reading the source.
The current engine is auditable in a single sitting.

## Risk score

A separate concern from the verdict.  The risk aggregator in
`src/risk.c` maps each evidence link to a 0.0 - 10.0 score
based on its severity and weight:

```
score = severity_base + (weight * severity_range)
```

severity_base and severity_range are tuned per severity band so
that INFO findings are small, MEDIUM findings sit around 5, and
CRITICAL findings saturate near 10.  The per-probe score is the
worst finding in the chain.  The overall score is the worst
probe score plus a small bonus for additional DETERMINISTIC
probes (capped at +1.5).
