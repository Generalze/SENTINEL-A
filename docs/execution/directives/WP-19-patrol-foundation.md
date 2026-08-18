# Directive WP-19 - Patrol Foundation

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 8
**Depends:** WP-15 Field Contracts, WP-16 Field Domain, WP-17 Field Realtime, WP-17A Field Site Integrity, WP-18 Incident Field Messaging
**Review chain:** Cipher adversarial review -> Lead merge gate
**Status:** Contract **PASS** (C9-01..C9-06). Implementation pass delivered
(C9-07..C9-09). Whole-system audit returned **one consolidated correction
batch** (five corrections, below), now applied with its regression set.
**MERGE HOLD** until the final effective-diff audit and hosted CI at the
corrected head.

## Objective

An auditable patrol loop: a route definition, an execution of that route by a
named operative, ordered checkpoints, verification evidence, and — the part that
makes it worth building — **server-owned missed and late determination** that
nobody in the field can talk their way out of.

## The contract gap this directive closes

WP-15 already defines `PatrolRoute` (a versioned definition), ordered
`PatrolCheckpoint`, and `CheckpointVerification` (evidence that someone reached
one). Nothing joined them into a single execution.

That left no object able to answer:

> which operative is walking which version of which route right now, and by when
> was each checkpoint due?

Without that anchor there is no server-owned basis for LATE or MISSED at all —
only a client assertion, which the roadmap explicitly forbids as the source of
truth. WP-19's roadmap entry requires missed-checkpoint state, so the anchor has
to exist before any persistence is designed.

**Resolved in this change** by adding `PatrolRun` and `PatrolRunCheckpoint` to
`packages/contracts/src/field.ts`, together with the two pure functions that
express the timing decision once.

## Locked design decisions

### 1. Route versus execution are different objects

`PatrolRoute` is a **definition**; `PatrolRun` is an **execution**. A run pins
the exact `route_version` it began under and materialises its own checkpoint
instants at start.

**C9-04 — version identity is structural, not decorative.** `route_version` now
lives on `PatrolCheckpoint`, so `(patrol_route_id, route_version)` is a real
version key and every run checkpoint must originate from the one version its run
pinned. A published version is immutable: changing a patrol standard means
publishing a **new** version, never editing version N in place. That is what
makes "later route edits cannot rewrite historical patrol truth" enforceable
rather than conventional.

### 2. Scheduling authority: the route version owns the standard

**Lead ruling.** Timing policy belongs to the versioned checkpoint definition:

```text
route-version checkpoint:      window_open_offset_ms
                               late_after_offset_ms
                               missed_after_offset_ms

at server-owned run start:     window_opens_at = started_at + window_open_offset_ms
                               late_after      = started_at + late_after_offset_ms
                               missed_after    = started_at + missed_after_offset_ms
```

There is **no per-run commander or dispatcher cadence in WP-19**. Otherwise a
scheduler could quietly weaken a patrol standard for one shift without changing
the approved definition. A different standard requires a new route version. An
override mechanism would need its own authorization, reason, audit and policy —
not WP-19.

Materialisation uses the **server-owned actual `started_at`**, never a client
time and never `scheduled_start_at`. The two are stored separately so a late
start remains visible as evidence rather than being absorbed into the schedule.

### 3. The timing model: materialised absolute instants

```text
received  <  window_opens_at              -> TOO_EARLY   (no mutation)
window_opens_at <= received <= late_after -> VERIFIED
late_after   <  received <= missed_after  -> LATE
received  >  missed_after                 -> EXPIRED     (no verification transition)
now       >  missed_after, still PENDING  -> MISSED      (server sweep only)
```

**C9-02 — `TOO_EARLY` closes an early-arrival hole.** The first draft counted
*any* receipt before `late_after` as VERIFIED, so a patrol could have been
"completed" the moment it started. `window_opens_at` replaces the vaguer
`expected_at` and names what it actually governs.

**Absolute instants rather than offsets on the run, deliberately.** An offset
must be re-evaluated against a start time every time it is read, so drift, clock
disagreement or an edit to the start would silently change historical
judgements. A materialised instant is a fact.

### 4. Checkpoint state must never contradict itself

**C9-02.** `PENDING`, `MISSED` and `CANCELLED` carry no `resolved_at` and no
verification id; `VERIFIED` and `LATE` require both. Beyond that, a resolved
row's recorded state must **equal** what the timing rule says about its own
`resolved_at` — a row can no longer claim VERIFIED while its resolution sits
inside the LATE window. The contract enforces this; it is not left to the
service.

### 5. Run termination is fully specified

**C9-03.**

```text
SCHEDULED   -> IN_PROGRESS | CANCELLED
IN_PROGRESS -> COMPLETED   | ABANDONED
```

`EXPIRED` is **removed**: it existed with no rule defining what expiry meant, and
an unspecified terminal state is where ambiguity hides. `started_at` exists only
for runs that started; `ended_at` only for runs that ended. A run may become
COMPLETED only when no checkpoint remains PENDING (`canCompletePatrolRun`).

**Abandonment cannot launder an overdue obligation.** On abandonment, a pending
checkpoint already past `missed_after` becomes **MISSED**; only a still-future
expectation is withdrawn as **CANCELLED** (`resolveAbandonedCheckpointState`).

### 6. Ordering is server-authoritative

**C9-02/C9-05.** A checkpoint may be verified only once every **lower** sequence
number has left PENDING. An earlier checkpoint that is VERIFIED, LATE, MISSED or
CANCELLED permits progression; one still PENDING blocks it. A later verification
never auto-resolves an earlier checkpoint — that belongs to the missed sweep
alone (`canVerifySequence`).

A device may not nominate a checkpoint outside its own run, invent a sequence,
or reorder one.

### 7. Verification input versus authoritative record

**C9-01.** The verification record is bound to its execution: it carries both
`patrol_run_id` and `patrol_run_checkpoint_id`. Without them, one route executed
twice — or twice concurrently — yields indistinguishable evidence and no audit
can say which patrol a verification belonged to.

```text
the device may supply              the server DERIVES
---------------------              ------------------
run / run-checkpoint reference     route and checkpoint identity
source time (telemetry)            organisation and site
verification method                authenticated operative identity
device evidence                    authoritative recorded_at
idempotency key                    ordering and resulting state
```

The old `recorded_at >= source_at` constraint is **removed**. A device clock five
minutes fast must not veto a valid server receipt; `source_at` is telemetry and
`recorded_at` is authority, stored side by side so skew is visible rather than
decisive.

### 8. Authorization and incident eligibility

**C9-05.** Locked matrix for WP-19:

```text
                      read routes   manage routes   schedule/manage runs   verify
site.commander             y              y                  y              -
dispatcher                 y              -                  y              -
field.operative       own run only        -                  -          own run only
operator / investigator / admin:  no patrol capability from existing roles
```

`dispatcher` may schedule runs but **may not redefine patrol standards** — that
is the whole point of ruling scheduling authority onto the route version. A
`field.operative` may act only on their own run and verify only their own
`IN_PROGRESS` checkpoint.

For an incident-linked patrol, **scheduling** eligibility additionally requires
the operative to satisfy exact organisation + site + incident Field-assignment
eligibility; **starting or verifying** additionally requires that assignment to
be `ACCEPTED` or `IN_PROGRESS`. An eligible same-site operative who is not
assigned this run gets **404** on the run object, per the WP-18 precedent that
existence is itself need-to-know.

### 9. Deadline race and idempotency

**C9-06.** Verification and the MISSED sweep will eventually contend for the
same row. Both serialize on the run-checkpoint row, and the authoritative
`recorded_at` is taken from the database **inside the transaction, after
acquiring that serialization boundary** — so the outcome can never depend on a
client clock or a stale application timestamp. Exactly one PENDING terminal
transition wins, producing exactly one audit and timeline effect.

Carrying the WP-18/C8-05 lesson forward: **idempotency namespaces must include
the authoritative actor and run scope**, so another actor's key collision can
never return their verification record.

Permanent regressions required at implementation: concurrent sweep-versus-
verification, and duplicate verification.

### 10. Site and incident integrity

Patrol live state is database-bound to a real `(site_id, organisation_id)` tuple
per WP-17A. An incident-linked patrol additionally binds the exact
`(incident_id, organisation_id, site_id)` tuple per WP-18. Neither boundary is
weakened, and `Incident`/`Event` scalar site semantics stay unchanged — that
remains the WP-22 prerequisite.

### 11. Audit

Run lifecycle transitions, checkpoint verifications and missed/late transitions
each write durable Field or incident timeline/audit records with trace ids. No
client-authored timestamp is ever stored as authoritative.

### 12. Realtime

Socket notifications are identifier and state-change signals only; REST and the
database remain authoritative. **A socket acknowledgement is not a checkpoint
verification** — WP-18/C8-01 established that transport receipt and human action
are different evidence, and patrol must not blur them.

## Implementation-pass requirements (ruled with the consolidated GO)

**C9-07 — the tuple is enforced below the service layer.** A run checkpoint
carries route + version identity, and persistence binds it twice: to its run on
`(patrol_run_id, organisation_id, site_id, patrol_route_id, route_version)` and
to its definition checkpoint on
`(patrol_checkpoint_id, patrol_route_id, route_version)`. A row that disagrees
with its run about tenant, site, route or pinned version cannot exist, even for
a writer that bypasses the service. The verification record is bound the same
way to `(patrol_run_checkpoint_id, patrol_run_id, organisation_id)`.

**C9-08 — completion fails closed.** `canCompletePatrolRun` accepts only a
non-empty set in which every checkpoint is VERIFIED, LATE or MISSED. An empty
set proves no patrol happened; a PENDING checkpoint is unfinished business; a
CANCELLED checkpoint only exists on runs that were themselves cancelled or
abandoned. None may COMPLETE.

**C9-09 — explicit action vocabulary.**

```text
patrol.route.read    patrol.route.manage
patrol.run.read      patrol.run.manage
patrol.run.act       patrol.checkpoint.verify

START            assigned operative              (patrol.run.act)
SCHEDULE/CANCEL  commander or dispatcher         (patrol.run.manage)
ABANDON          operative on own run, or command intervention
                 with a mandatory audited reason
COMPLETE         system-owned: no action, no endpoint — it happens
                 inside the transaction resolving the final checkpoint
VERIFY           assigned operative only         (patrol.checkpoint.verify)
```

Verification idempotency stays namespaced as ruled:
`organisation_id + patrol_run_id + patrol_run_checkpoint_id +
operative_user_id + idempotency_key`.

## Whole-system audit — correction batch (applied)

The lead's adversarial audit accepted the architecture and returned five
corrections in one batch, each now applied with a permanent regression:

1. **Verification evidence tuple completed (P1).** The evidence record gains
   `route_version`, the run checkpoint contract carries its route identity,
   and the verification binds the run checkpoint's COMPLETE authoritative
   identity — run + tenant + site + route + version + definition checkpoint —
   through one composite FK (additive migration
   `20260819160000_wp19a_verification_evidence_tuple`). Direct-DB regressions
   prove a forged site, route, version or checkpoint cannot be inserted.
2. **Idempotency is request-bound (P1).** Across verification, route
   creation, version publish, run scheduling and abandonment: same identity +
   key + same semantic request replays; materially different input is a
   generic 409 with zero mutation. `trace_id` is not semantic. A route-create
   replay returns the representation the ORIGINAL creation established, not
   the route's current version.
3. **Mutable dependencies are locked (P1).** Incident-linked START, VERIFY and
   SCHEDULE read the operative's Field-assignment rows locked inside the
   patrol transaction (deterministic order: run → assignment rows by id → run
   checkpoint; schedule/publish lock the route row first), and schedule pins
   `currentVersion` from the locked route row. Deterministic concurrent
   regressions cover assignment-termination vs START and VERIFY, and
   publish vs schedule version pinning.
4. **START fails closed (P1).** A pinned version that materialises no
   checkpoints — or fewer rows than definitions — aborts the transaction with
   a generic version-integrity conflict; no status change, audit, timeline or
   outbox row survives.
5. **Bounded JSON at the boundary (P1).** The contract's 16 KiB budget for
   checkpoint `location` and `verification_context` is enforced at the request
   boundary with the contract's own exported predicate; oversized input is a
   400 before any transaction.

One documentation truth fix rode along: the schema commentary now names the
replay-guard exception — `patrol_run_action_idempotency -> patrol_runs` is
deliberately ON DELETE CASCADE per the WP-16/WP-18 replay-guard precedent;
every EVIDENCE relation remains RESTRICT. The applied WP-19 migration was not
edited; the correction is recorded in the WP-19A migration's preamble.

The inherited C7-08 wire protection is now also a permanent WP-19 regression:
a same-site peer's received WebSocket payload carries `kind`,
`organisation_id` and `site_id` only — never `patrol_run_id` — while REST
answers that peer 404 for the same run.

## Delivered implementation

- `packages/contracts/src/field.ts` — patrol contracts with C9-01..C9-04 and
  the C9-08 fail-closed completion rule, plus the pure timing/ordering
  functions used by the service.
- `services/core-api/prisma/schema/patrol.prisma` and additive migration
  `20260819090000_wp19_patrol_foundation` — seven tables with the C9-07
  composite bindings, the WP-17A site relation and the WP-18 incident tuple.
- `services/core-api/src/modules/patrol/` — repository (run-lock
  serialization, database-clock receipt via `clock_timestamp()` after the
  lock, materialisation at start, missed sweep, system-owned completion),
  service (C9-05 authorization and 404 non-probing), controller (one action
  per route), and the sweeper.
- Audit to `FieldAuditLog`, incident timeline entries for incident-linked
  runs, and content-free realtime signals over the existing WP-17 Field
  outbox path.
- 34 patrol tests (4 eligibility unit, 20 live-stack API, 10 audit-batch
  regressions including the realtime projection pin) plus the contract suites.

## Acceptance criteria (implementation stage)

1. A run snapshots its route version; editing the route afterwards changes no
   historical run.
2. Checkpoint expectations are materialised once at start and never recomputed.
3. On-time, late and missed follow the three timestamps exactly, at boundaries.
4. A verification for a checkpoint outside the caller's own active run is
   refused; cross-tenant and cross-site are refused and indistinguishable.
5. Client source time never affects state; only server receipt time does.
6. A checkpoint never becomes missed because a later one was verified.
7. Replayed verification produces no second record or effect.
8. Patrol rows cannot reference a fictional or cross-tenant site or incident,
   enforced below the service layer.
9. Hosted CI green including the real security source gate and Proof A.

## Out of scope

Explicitly **not** in WP-19 unless separately authorized: GPS geofence proof,
NFC/QR cryptographic checkpoint proof, biometric recognition, a native mobile
offline queue, the WP-20 replay engine, Whisper, and any patrol UI polish.

## Previously open question — now ruled

> Where do the per-checkpoint durations come from at run start?

**Answered: the route version owns them** (section 2). The alternative — a
per-run cadence supplied at scheduling time — is rejected for WP-19 because it
would let a scheduler weaken an approved patrol standard for one shift without
changing the definition anyone reviewed.

No open questions remain. The contract is locked, the implementation pass is
delivered, and the package is on MERGE HOLD pending the lead's whole-system
adversarial audit and hosted CI.
