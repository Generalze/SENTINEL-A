# Directive WP-22 - Milestone 2 Live Regression, Hardening & Sign-off

**Issued by:** Lead (/root) - **Lane:** Core with adversarial review - **Wave:** 11
**Depends:** WP-15 .. WP-21 (all complete)
**Frozen base:** `e779a454` (WP-21B closure boundary)
**Branch:** `wp-22-m2-live-regression-signoff`
**Status:** Implementation pass delivered. **MERGE HOLD** pending the
whole-effective-diff audit and hosted CI.

## Purpose

WP-22 adds no feature. Its job is to prove that the Field capabilities
accumulated through WP-15→WP-21 remain correct **when exercised together**, to
turn known test-harness weakness into deterministic regression coverage, to
produce the Milestone-2 evidence record, and to make the final technical
sign-off possible.

The integration invariant this work package exists to defend:

> **Milestone 2 must remain correct when its parts coexist: replay must not
> duplicate action, realtime must not widen knowledge, recovery must not
> rewrite history, Whisper recognition must not become approval, and a
> background scheduler must not make correctness depend on lucky test timing.**

## Locked rulings

### W22-01 — Freeze and closure record

WP-21B is COMPLETE at `e779a454`: 75 Whisper tests, 1,071 workspace tests,
post-main run green, 20 migrations from zero. The roadmap and the WP-21
directive record that closure **append-only** — no earlier finding is
rewritten.

### W22-02 — The patrol sweeper flake, eliminated deterministically

Fixed at the **scheduler boundary**, never in patrol semantics.

`PatrolMissedSweeper` hard-wired a five-second `setInterval` plus an immediate
boot sweep. Correctness never depended on that cadence — MISSED is decided per
checkpoint under the run lock against the database clock — but the ambient
timer could fire *between* a test's own actions and change the counts that test
was about to assert. That is a harness problem wearing a correctness costume.

The cadence moves behind a **test-only dependency-injection seam**
(`PATROL_SWEEP_SCHEDULER`), and the interval stays hard-wired at 5000 ms.

**C13-01 correction.** The first attempt made the cadence an env-validated
setting where `0` disabled the sweep. That was a production kill-switch for a
safety-critical, server-owned judgement: an operator could silently stop
missed-checkpoint detection through configuration, which is exactly what WP-19
exists to prevent. Worse, the disable branch returned *before* the boot sweep,
so a `0` deployment also skipped catch-up on restart — precisely when a server
has the most overdue checkpoints to judge. The setting is removed from the env
schema entirely; there is now no env var, no config field and no runtime API
that can stop the sweep in production. Only a test may substitute a scheduler
that never fires, through Nest provider override, and the boot sweep sits
outside the seam so no double can skip it either.

Specs drive `sweep()` explicitly, so what a test asserts is what that test
caused. No sleeps were lengthened, no retry-until-green was added, no timeout
was enlarged and no assertion was weakened — the sweep logic itself is
byte-identical.

**Evidence required:** 50 consecutive executions of the previously flaky file.

### W22-03 — The integrated Milestone-2 Field loop

One live-stack suite, one tenant/site fixture, an ordered narrative covering:
assignment lifecycle; authoritative Field operative state; incident-scoped
named-recipient messaging and acknowledgement; patrol route/run/checkpoint
including an explicitly driven missed sweep; offline replay through **only**
the WP-20-admitted operations; and a signed Whisper recognition entering the
existing SILENT path.

Patrol and Field-state operations are **not** smuggled into the offline
allowlist to make the scenario convenient — the suite instead asserts that
those kinds fail to parse the V2 contract and that the admitted set is still
exactly six, so any future widening is a visible diff.

The Whisper step ends by proving **zero response approvals and zero dispatch
handoff**, then that two distinct commanders produce exactly one handoff.

### W22-04 — Isolation and need-to-know matrix

Foreign organisation, wrong site, unassigned operative and non-recipient
adversaries are all exercised against the assignment, the message, the patrol
run, the Whisper signal and the Whisper-raised incident. Each refusal is
**byte-identical** to the same request for a nonexistent id — status parity and
body parity — so a refusal cannot be read as confirmation. The shared Field
realtime channel keeps the C7-08 rule: `kind` + `organisation_id` + `site_id`
and nothing else.

### W22-05 — Effectively-once, integrated

Exact duplicate replay yields one domain effect and the stored outcome; a
changed request under a consumed identity is refused with no second effect; a
duplicate Whisper recognition creates no second incident. WP-20's focused
tests continue to carry the stale-generation, UNKNOWN-recovery and
sequence-exhaustion cases. The term "exactly once" is deliberately not used.

### W22-06 — Whisper Crucible, permanent

Invalid signature consumes no nonce; a substituted principal is refused before
the verifier or the signal lookup is reached (proved by spies, using an actor
who genuinely lacks the capability so it proves authority cannot be
*borrowed*); one ACTIVE family version is refused by the database itself; and
there is **no public Whisper recognition HTTP endpoint**.

**C13-02 correction.** Probing three guessed paths for 404 proved nothing about
a fourth path added later. The guard now enumerates the application's **live
route table** and asserts the registered whisper routes equal exactly the seven
Studio routes, that no path anywhere in the table matches
`/recogni|invoke|device-action/i`, and — so an empty enumeration cannot pass
forever — that the table was genuinely read. A real recognition route added to
the controller fails this guard; it did not fail the old probe.

### W22-07 — Schema and migration integrity

**No migration.** The chain remains at **20**, deployed from zero.

### W22-08 — Evidence and proof accounting

`docs/execution/MILESTONE-2-EVIDENCE.md` maps each capability to the exact test
that proves it, and separates **implemented**, **tested** and **not yet
proven**. Proof C and Proof D are recorded **UNCLAIMED**. A simulator, a
dev-auth principal and a server-constructed `AuthenticatedWhisperDeviceContext`
are none of them real-device proof, and no wording converts them into one.

### W22-09 — Full quality gate

Strict typecheck, lint, the real security-source gate, a clean 20-migration
deployment from zero, the whole workspace suite, Proof A, the patrol stress
run and the new M2 regression. Baseline 1,071 tests must rise, not fall.

### W22-10 — Final sign-off

One PR against exact accepted `main`, one whole-effective-diff audit, one
consolidated correction batch if needed, then merge-commit semantics and a
green post-main run. The tag `milestone-2-field-workflow` is created only at
the accepted post-main merge commit, and it makes **no Proof C or Proof D
claim**.

## Prohibitions observed

No public Whisper device endpoint. No fake certificate or device-auth
facility. No voice/gesture/camera/AI modality. No new offline operation kinds.
No weakening of Constitution or two-person SILENT approval. No patrol semantic
change to stabilise a test. No UI expansion. No Proof C claim. No Proof D
claim. The original repository remains frozen at `bd6076e`.
