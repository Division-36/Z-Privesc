# Exploitability Composition Engine

The Exploitability Composition Engine is the research contribution that
distinguishes Z-Privesc from a flat privilege-escalation *scanner*. Where a
classic tool emits N independent findings ("writable sudoers file", "docker
group membership", "world-writable ld.so.conf"), Z-Privesc asks and answers a
different question:

> Given the misconfigurations this unprivileged user actually has, can they
> reach **root**, and with what **calibrated confidence**?

It does this by treating every finding as evidence in a small *capability
graph* and running a forward-chaining reachability analysis from the evidence
up to the `ROOT` sink.

---

## 1. Model

The engine is a Horn-clause privilege graph:

- **Tokens** — privilege states. Each is a single bit in a `uint32_t` mask,
  e.g. `WRITE_SUDOERS`, `EXEC_AS_ROOT`, `CONTAINER_ESCAPE`, `READ_ROOT_KEY`,
  `KERNEL_LPE`, `POLKIT_LPE`, `ROOT`. See `enum { ... }` in `src/compose.c`.

- **Rules** — `precondition token(s) -> result token`, each annotated with a
  calibrated exploit-reliability weight `p ∈ (0,1]`:

  | rule | precondition | result | p | technique |
  |------|--------------|--------|---|-----------|
  | R0 | `EXEC_AS_ROOT` | `ROOT` | 0.97 | execute code as root |
  | R1 | `WRITE_SUDOERS` | `EXEC_AS_ROOT` | 0.95 | append NOPASSWD to sudoers |
  | R2 | `WRITE_SYSTEMD` | `EXEC_AS_ROOT` | 0.95 | hijack a root-run systemd unit |
  | R3 | `WRITE_CRON` | `EXEC_AS_ROOT` | 0.95 | hijack a root-run cron job |
  | R4 | `INJECT_PRELOAD` | `EXEC_AS_ROOT` | 0.90 | `LD_PRELOAD` into root processes |
  | R5 | `WRITE_PATH_TROJAN` | `EXEC_AS_ROOT` | 0.85 | plant trojan in writable `PATH` |
  | R6 | `CONTAINER_ESCAPE` | `ROOT` | 0.85 | escape container to host root |
  | R7 | `READ_ROOT_KEY` | `ROOT` | 0.95 | SSH in as root with stolen key |
  | R8 | `WRITE_DISK` | `ROOT` | 0.90 | read/write raw disk for root secrets |
  | R9 | `SETUID_CAP` | `EXEC_AS_ROOT` | 0.93 | use file capability to setuid |
  | R10 | `KERNEL_LPE` | `ROOT` | 0.90 | run kernel LPE exploit |
  | R11 | `POLKIT_LPE` | `ROOT` | 0.95 | exploit polkit/pkexec |

  Rules are currently single-precondition; multi-precondition conjunctions
  are a planned extension (AND/OR of token sets).

- **Fixpoint** — forward-chaining. Starting from the *initial* token mask
  (tokens directly implied by evidence), repeatedly apply every rule whose
  precondition is already satisfied, adding its result token, until no new
  token appears. `der[t]` records the rule that derived token `t`
  (first derivation wins, for a deterministic, actionable chain).

- **`ROOT` sink** — if `ROOT` is reachable in the fixpoint mask, at least one
  escalation path exists.

## 2. From findings to tokens

`map_link()` in `src/compose.c` walks the same per-probe evidence chains the
JSON emitter already reads and maps each evidence link to zero or more
*initial* tokens. Examples:

- `writable_etc` / `world_writable` link whose target contains `sudoers`
  → `WRITE_SUDOERS`; `systemd` → `WRITE_SYSTEMD`; `cron` → `WRITE_CRON`;
  `ld.so`/`preload` → `INJECT_PRELOAD`.
- `groups` containing `docker`/`lxd` → `CONTAINER_ESCAPE`; `disk` →
  `WRITE_DISK`.
- `sudoers` (NOPASSWD) / dangerous `suid` / `process` → `EXEC_AS_ROOT`.
- `ssh_keys` → `READ_ROOT_KEY`; `kernel_vuln` → `KERNEL_LPE`; `polkit` →
  `POLKIT_LPE`; `docker_socket` → `CONTAINER_ESCAPE`; `nfs`
  (`no_root_squash`) → `ROOT`.

The original finding id and target are retained as the *source evidence* of
the deepest (initial) token in each reconstructed path.

## 3. Path reconstruction

For every `ROOT`-producing rule whose precondition is reachable, the engine
*backchains* from the precondition token through `der[]` to the initial
evidence token, then appends the final `precondition -> ROOT` hop. The result
is an ordered list of edges `(from, to, rule)` that is the concrete
misconfiguration chain composing into root.

Paths are de-duplicated by their deepest (initial) token so that, e.g., the
several ways to obtain `EXEC_AS_ROOT` collapse into the single most
actionable chain (`WRITE_SUDOERS -> EXEC_AS_ROOT -> ROOT`) rather than
spamming the report.

## 4. Calibrated confidence

Each step carries the exploit-reliability `p` of its rule. A path's
**confidence** is the product of the `p` values along its edges:

```
confidence(path) = ∏_{e ∈ path} p(e)
```

This is a conservative (multiplicative) composition: a chain is only as strong
as its weakest, most uncertain link. Example:

```
WRITE_SUDOERS -> EXEC_AS_ROOT (0.95)
EXEC_AS_ROOT  -> ROOT          (0.97)
confidence = 0.95 × 0.97 = 0.9215
```

### Calibration source

`p` is **not** a magic constant. Seeds are initialised from the ground-truth
study in `benchmarks/data/accuracy/` (detection/exploit rate as a first-order
proxy) and are refined by the larger evaluation harness (the CTF / Docker / CVE
corpus). They are explicit, auditable parameters in `RULES[]` and are intended
to be fitted against measured base rates as the evaluation corpus grows. The
combination with Truthimatics dominance/risk scoring is described in
`docs/TRUTHIMATICS.md`.

## 5. Output format

The engine emits the `escalation_paths` member of the audit JSON:

```json
"escalation_paths": [
  {
    "confidence": 0.922,
    "technique": "WRITE_SUDOERS -> root",
    "steps": [
      {"from":"WRITE_SUDOERS","to":"EXEC_AS_ROOT","reliability":0.95,
       "technique":"append NOPASSWD to sudoers",
       "finding":"WETC-D-004","target":"/etc/sudoers.d/zprivesc-weak"},
      {"from":"EXEC_AS_ROOT","to":"ROOT","reliability":0.97,
       "technique":"execute code as root","finding":null,"target":null}
    ]
  }
]
```

- `confidence` — multiplicative chain reliability (§4).
- `technique` — label of the deepest initial token composing into root.
- `steps[]` — the ordered edge chain; the first step carries the source
  `finding` id and `target` (the concrete evidence), later steps carry
  `null` because the intermediate state is derived, not directly evidenced.

If no `ROOT`-reachable token exists, the engine emits `"escalation_paths":[]`.

## 6. Implementation notes

- `src/compose.c` — token enum, `RULES[]`, `map_link()`, `backchain()`,
  `zp_compose_json()`.
- `include/compose.h` — public API (`zp_compose_json`).
- Invoked from `src/audit.c` inside the JSON emitter, after the per-probe
  findings are written.
- Complexity is linear in (findings × rules × graph depth); the graph is
  shallow (depth ≤ 2), so composition is effectively O(1) per audit.

## 7. Limitations & roadmap

- **First-derivation-wins** yields one representative chain per initial token;
  enumerating *all* distinct chains (e.g. both `sudoers` and `suid` routes to
  `EXEC_AS_ROOT`) is future work.
- Multi-precondition rules (AND/OR) are not yet expressed.
- `p` values are seed-calibrated, not yet fitted to a large corpus.
- Known evidence gaps (see `benchmarks.md` §9) in `kernel_hardening`,
  `process` and `nfs` reduce recall until those probes are hardened.
