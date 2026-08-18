# Directive WP-19 - Patrol Foundation

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 8
**Depends:** WP-15 Field Contracts, WP-16 Field Domain, WP-17 Field Realtime, WP-17A Field Site Integrity, WP-18 Incident Field Messaging
**Review chain:** Cipher adversarial review -> Lead merge gate
**Status:** Directive and contract design only. **Implementation is HOLD** until
the lead reviews and locks the patrol-execution and missed/late contract below.

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

`PatrolRoute` remains a **definition**: versioned, editable, describing intent.
`PatrolRun` is an **execution**: it snapshots the exact `route_version` it began
under and materialises its own checkpoint expectations at start time.

Editing a route afterwards therefore cannot rewrite what a completed patrol was
required to do. The historical truth of a patrol lives on the run, never on the
definition — the same instinct as WP-18's immutable message and WP-17A's
recorded-at-the-time site identifier.

### 2. The timing model: materialised absolute instants

**This is the design decision the checkpoint asked to be posed and resolved.**

Each `PatrolRunCheckpoint` carries three server-computed absolute timestamps,
written once when the run starts:

```text
expected_at    when the operative should reach it
late_after     the end of the on-time window
missed_after   the deadline, after which it can no longer be verified
```

and the decision is exactly:

```text
received_at <= late_after                  -> VERIFIED
late_after  <  received_at <= missed_after -> LATE
now         >  missed_after, still PENDING -> MISSED
```

**Absolute instants rather than offsets, deliberately.** An offset must be
re-evaluated against a start time every time it is read, so any later drift,
clock disagreement, or edit to the run's start would silently change historical
judgements. A materialised instant is a fact; an offset is a recomputation.

**Materialised on the run, not written back onto the route.** Starting a patrol
must never mutate a shared definition — two concurrent runs of the same route
would otherwise fight over the same rows, and a route edit would retroactively
move a finished patrol's deadlines.

The two functions `resolveCheckpointState` and `isCheckpointMissed` are pure and
live in the contract package so no call site can reinvent the rule.

### 3. Ordering is authoritative on the server

`sequence_number` is snapshotted onto the run's checkpoints from the route
version. A device may not nominate a checkpoint outside its own run, invent a
sequence, or reorder one.

### 4. Verification input versus authoritative record

```text
the device may supply          the server DERIVES
------------------            -------------------
checkpoint reference          tenant/site validity
source time (telemetry)       authenticated operative identity
verification method           route/run membership
device evidence               authoritative receipt time
idempotency key               ordering and resulting checkpoint state
```

Client source time is **telemetry only**, exactly as WP-16 established for Field
state freshness. Only server receipt time may be passed to
`resolveCheckpointState`.

### 5. Missed is never a client claim, and never a side effect

A checkpoint must not become MISSED because a device said so, and must not
become MISSED merely because a **later** checkpoint was verified. Both would let
field behaviour rewrite the record. MISSED arises only from the run's own
schedule and the server clock, via a sweep, and must be auditable.

`isCheckpointMissed` therefore reads only that checkpoint's own state and
deadline — it is structurally incapable of consulting a sibling.

### 6. Idempotency and immutability

A replayed verification must create no second verification record, no second
timeline effect, and no second missed-checkpoint effect. Run, checkpoint and
verification facts are append-only or state-transition controlled; nothing is
silently rewritten (§61).

### 7. Site and incident integrity follow the established precedents

Patrol live state must be database-bound to a real `(site_id, organisation_id)`
tuple per WP-17A. A patrol associated with an incident must additionally bind
the exact `(incident_id, organisation_id, site_id)` tuple per WP-18. **Do not
weaken either boundary**, and do not change `Incident`/`Event` scalar site
semantics — that remains the WP-22 prerequisite.

### 8. Audit

Run lifecycle transitions, checkpoint verifications, and missed/late transitions
each create durable Field or incident timeline/audit records carrying trace ids.
No client-authored timestamp is ever stored as authoritative.

### 9. Realtime

Socket notifications are identifier and state-change signals only; REST and the
database remain authoritative. **A socket acknowledgement is not a checkpoint
verification** — WP-18/C8-01 established that transport receipt and human action
are different evidence, and patrol must not blur them.

## Deliverables (implementation stage, not yet authorized)

- Prisma models and an additive migration for patrol runs and run checkpoints,
  with the WP-17A composite site relation and the WP-18 incident tuple relation
  where an incident is present.
- Run lifecycle service (schedule, start, complete, abandon) with CAS.
- Checkpoint verification endpoint deriving everything in section 4 server-side.
- A missed-checkpoint sweep, idempotent and auditable.
- Realtime notification of run/checkpoint state changes, content-free.
- Unit and live-stack tests including cross-tenant, cross-site, wrong-run,
  out-of-order, replayed verification, deadline boundary, and missed-sweep
  cases.

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

## Open question for the lead

One decision is deliberately left open rather than guessed:

> **Where do the per-checkpoint durations come from at run start?**

The contract fixes the *shape* (three absolute instants per checkpoint) without
fixing their *source*. Two candidates:

- **(a) Route-level cadence.** `PatrolRoute` gains an expected duration per
  checkpoint, and a run materialises instants from it. Consistent scheduling,
  but it is a WP-15 contract change.
- **(b) Run-level schedule input.** The commander/dispatcher supplies the
  cadence when scheduling the run. No WP-15 change, more flexible per shift, but
  the same route can be walked to different standards.

Both satisfy every locked rule above; the difference is where scheduling
authority lives. This needs a lead ruling before persistence is designed.
