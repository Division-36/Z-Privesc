# Related Work — Positioning the Exploitability Composition Engine

This document maps Z-Privesc's research contribution — *probabilistic,
evidence-composed privilege-escalation reachability on Linux* — against the
literature, and states precisely the gap the paper occupies. It is written to
support a system-security venue submission (e.g. SEC-T main or tool/practice
track) and must be kept honest: every claim below is either a citable,
well-established body of work or an explicit gap statement, never a fabricated
metric.

---

## 1. Attack-graph and vulnerability-analysis research

The composition engine is, formally, a **forward-chaining Horn-clause
reachability analyser over a privilege-state graph**. That puts it in the
attack-graph lineage:

- **Model-based attack graphs.** MulVAL (Ou, Boyer & McQueen, 2005) is the
  canonical logic-programming approach: Datalog rules over system
  configuration facts derive attack states. Our `RULES[]` are the same shape
  (precondition token → result token) but specialised to *local* Linux
  privilege state and compiled to C for inline, low-overhead execution.
- **Topological vulnerability analysis (TVA).** Noel, Jajodia and colleagues
  framed network attack graphs as reachability over a condition graph; the
  "can the attacker reach a goal condition" question is exactly ours, scoped
  to a single host rather than a network.
- **Surveys.** Kaynar's "A Survey of Attack Graph Analysis" (2016) and the
  earlier Lippmann & Ingols MITRE work catalogue the field and its
  evaluation weakness: attack-graph research is historically **network- and
  enterprise-centric**, and its "exploit probability" edges are almost always
  *assumed*, not *measured*. That assumption gap is the single biggest
  vulnerability of the whole subfield — and the exact thing this paper's
  calibration protocol is designed to close.

**Gap we occupy:** attack-graph research has never been operationalised as a
*fast, local, host-resident* analyser for Linux privilege escalation with
*empirically calibrated* edge probabilities. It is either network-scale and
uncalibrated, or theoretical.

---

## 2. Graph-based privilege escalation in practice (the BloodHound analogue)

The closest *deployed* analogue is **BloodHound / SharpHound** (OTRF / SpecterOps)
for Active Directory: it ingests state, builds a graph, and finds
privilege-escalation *paths* to Domain Admin with confidence ratings. This is
the mental model reviewers will reach for, which is useful — but the
differences are the contribution:

- BloodHound reasons about **AD object relationships** (membership, ACLs,
  delegation). Z-Privesc reasons about **Linux kernel/OS privilege state**
  (file writability, capabilities, sudoers, capabilities, containers).
- BloodHound's edge weights are largely **analyst-assigned**; Z-Privesc's are
  **fitted from observed exploit outcomes** (see calibration protocol).
- There is **no BloodHound equivalent for local Linux PE composition** — the
  Linux side has enumeration tools but no path-composition-with-confidence.

**Positioning sentence:** *Z-Privesc is the local-Linux, calibrated
counterpart to BloodHound's AD attack graph.*

---

## 3. Linux / Unix privilege-escalation tooling

These are the deployment-relevant baselines the evaluation must beat on equal
footing:

- **LinPEAS / PEASS-ng** — the de-facto standard enumerator; exhaustive,
  colour-coded, and extremely noisy (high recall, very low precision, no
  composition, no confidence).
- **LinEnum, unix-privesc-check, linux-smart-enumeration (lse)** — older
  enumerators with the same "list everything" philosophy.
- **Lynis** — a hardening/runtime auditor; detects *some* misconfigurations
  but is oriented to hardening benchmarks, not escalation paths, and produces
  no root-reachability claim.
- **GTFOBins** — the canonical *knowledge base* of "how to abuse a binary for
  privesc" (sudo, SUID, LOLBIN abuse). It is reference data, not a tool; the
  composition engine's `RULES[]` are a machine-readable analogue restricted to
  *automatable, evidence-backed* techniques.

**Gap we occupy:** every one of these is an **enumerator**, not a
**composer**. None answers "given *this* set of findings, can an unprivileged
user reach root, and with what confidence?" That question is the paper's core.

---

## 4. Container escape and kernel-LPE research

Two of our `RULES[]` targets are independently studied:

- **Container escape** is a mature research area (runtime breakouts via
  mounted sockets, privileged containers, kernel bugs; e.g. the well-known
  `docker.sock` and `--privileged` escape classes). Z-Privesc treats
  `CONTAINER_ESCAPE` as a single composed edge rather than re-deriving escape
  primitives — a deliberate scope choice, and a calibration point.
- **Kernel LPE / CVE exploitation** is the largest, most volatile category.
  There is no stable, version-independent detector; version-pattern matching
  (our `kernel_vuln` probe) is inherently recall-limited. The evaluation must
  report kernel-LPE detection *separately* and never let it mask the
  composition result.

---

## 5. Probabilistic / calibrated security metrics

The "calibrated confidence" claim only has meaning relative to a measurement
discipline:

- **Brier score** (Brier, 1950) — mean squared error of probabilistic
  forecasts; the standard calibration loss.
- **Reliability diagrams** — bin predicted probabilities, plot observed
  frequency; the canonical calibration visual.
- **Cyber-risk quantification** frameworks (e.g. FAIR) treat likelihood as a
  measured, uncertainty-bearing quantity. Our calibration protocol adopts
  that stance: `p` is a *measured base rate with Laplace smoothing*, not a
  constant.

**Gap we occupy:** security tooling that *reports* probabilities (risk
scores, CVSS-style vectors) almost never *validates* them. Bringing Brier
score + reliability diagrams into a PE-tool evaluation is, to our knowledge,
unpublished for this domain.

---

## 6. Benchmark corpora

A striking absence: **there is no standard Linux privilege-escalation
benchmark.** CTF platforms (HackTheBox, VulnHub, OffSec), Docker "vuln"
images, and CVE-specific environments exist, but none is assembled as a
labelled corpus with known escalation vectors. The evaluation framework
shipped in `evaluation/` exists to fill exactly this gap: a schema-driven
corpus of provisioned targets with explicit ground truth, so results are
reproducible and comparable.

---

## 7. Contribution statement (what makes this a paper, not a tool note)

1. A **host-resident, calibrated privilege-escalation composition engine**
   (local-Linux analogue of AD attack graphs), implemented in portable C.
2. A **reproducible, schema-driven evaluation corpus** with explicit ground
   truth — the missing Linux-PE benchmark.
3. **Empirical calibration** of exploit-reliability edges via observed
   outcomes, reported with **Brier score and reliability diagrams** — closing
   the field's oldest criticism of attack graphs.
4. **Head-to-head comparison** against LinPEAS/Lynis on the same corpus with
   explicit recall / precision / false-positive / runtime metrics.

The honest current limitation (to be stated in the paper's Limitations): the
corpus must be large and diverse (many distros/kernels/CTF boxes), and the `p`
values are seed-calibrated until fitted on that corpus. The framework makes
reaching that state a mechanical, repeatable process rather than a research
obstacle.
