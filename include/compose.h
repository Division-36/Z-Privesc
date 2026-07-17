/*
 * compose.h - Exploitability Composition Engine
 *
 * Consumes the per-probe evidence chains already collected by the
 * probes and composes them into privilege-escalation PATHS:
 * "given these independent misconfigurations, can the current
 * (unprivileged) user actually reach root, and with what calibrated
 * confidence?"
 *
 * This is the research contribution that distinguishes Z-Privesc from
 * a flat probe list: instead of emitting N unrelated findings, it
 * performs a reachability analysis over a capability graph and reports
 * the concrete chain of misconfigurations that composes into root.
 *
 * The model is a small Horn-clause privilege graph:
 *   - tokens   : privilege states (e.g. WRITE_SUDOERS, EXEC_AS_ROOT)
 *   - rules    : precondition token(s) -> result token, each with a
 *                calibrated exploit-reliability p (see calibration[]).
 *   - fixpoint : forward-chaining until no new token is derived.
 *   - ROOT     : the sink. If reachable, an escalation path exists.
 *
 * Calibration: p is the empirically-grounded probability that the
 * privilege granted by a rule actually yields the next state. Seeds
 * are initialised from the ground-truth study (detection rate as a
 * first-order proxy) and are refined by the larger evaluation harness
 * (benchmarks/data/accuracy + the CTF/Docker corpus). They are
 * explicit, auditable parameters, not magic constants.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 * License: MIT
 */

#ifndef Z_PRIVESC_COMPOSE_H
#define Z_PRIVESC_COMPOSE_H

#include <stdio.h>
#include "z_privesc.h"

/* Emit the "escalation_paths" JSON fragment for the runtime's chains.
 * Prints `"escalation_paths":[ ... ]` (no leading/trailing comma). */
int zp_compose_json(const struct zp_runtime *rt, FILE *out);

#endif
