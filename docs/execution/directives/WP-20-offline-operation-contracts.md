# Directive WP-20 - Offline Operation Contracts & Replay Foundation

**Issued by:** Lead (/root) - **Lane:** Sonnet/Core under lead-owned contract decisions - **Wave:** 9
**Depends:** WP-15 Field Contracts, WP-16 Field Domain, WP-18 Incident Field Messaging, WP-19 Patrol Foundation
**Review chain:** Opus adversarial review -> Lead merge gate
**Accepted base:** `e4092e2` (WP-19 closure boundary)
**Status:** Checkpoint A contract lock **ACCEPTED** and merged (`eb5e0cf`,
post-main run green). Checkpoint B server replay harness **delivered** on
`wp-20-offline-replay-harness` under the lead's consolidated release,
incorporating the three locked integration rules and the inherited WP-18
aggregate-size correction. **MERGE HOLD** pending the lead's audit and hosted
CI. Any public HTTP/mobile replay API remains **HOLD** until a genuine
server-authenticated device identity exists.

## Objective

An honest server-side offline replay protocol for Field clients:

```text
client operates while disconnected
  -> ordered local operation queue
  -> connectivity restored
  -> authenticated user + authenticated device context
  -> durable server inbox
  -> strict sequence classification
  -> request-bound duplicate protection
  -> existing domain service / existing authorization
  -> APPLIED or deterministically REJECTED
  -> cursor advances exactly once
```

**The invariant:** a reconnect may delay an authorised operation. It must
never duplicate it, reorder it, weaken its authorization, backdate server
authority, or let a changed request hide behind an old idempotency identity.

The architecture requires Edge/Field synchronisation queues with ordering and
idempotency, and Proof D requires queued Field communications to recover after
WAN failure without duplicate incident actions. §62.1 keeps organisation,
site, purpose and device state inside the authorization decision. The WP-15
scaffold (free-form `operation_kind`, generic bounded `payload`,
`isNewerOfflineOperation()` testing only `next > previous`) is not an
executable security contract; WP-20 replaces it with one.

## Locked rulings

### C10-01 — Do not silently mutate the existing V1 contract

`FieldOfflineOperationSchema` V1 remains parseable as legacy contract history,
clearly marked superseded for executable replay. Wire meaning of
`schema_version: 1` never changes silently. A new strict
`FieldOfflineOperationV2Schema` (`schema_version: 2`) carries
`offline_operation_id`, `organisation_id`, `site_id`, `device_id`,
`device_sequence`, `idempotency_key`, `operation_kind`, `payload`,
`created_at` (client telemetry, never server authority) and `trace_id`
(non-semantic — a legitimate retry may carry a new trace). The V2 schema is a
**discriminated union**: an arbitrary string plus arbitrary JSON is forbidden
from the replay executor.

### C10-02 — Device identity is a trusted server context, not a body field

WP-20 has no authority to fake production device authentication. It creates
the internal, non-wire seam a later trusted identity will populate:

```ts
interface AuthenticatedFieldDeviceContext {
  organisationId: string;
  userId: string;
  deviceId: string;
  authorisedSiteIds: readonly string[];
}
```

Before any receipt lookup or replay result is returned, ALL of the following
bind, fail-closed on mismatch: principal organisation == context organisation;
principal user == context user; operation organisation == context
organisation; operation device == context device; operation site ∈ context
authorised sites; operation site ∈ principal's current site scope; principal
currently holds the action required by the operation kind.

**No HTTP endpoint may accept `device_id` from JSON and call that
"authenticated device identity."** If a genuine device-authentication
facility is discovered in the repository, STOP and report before changing
this ruling.

### C10-03 — Sequence is contiguous, not merely increasing

Replay namespace: `organisation + site + authenticated user + authenticated
device`. Sequence begins at **0**.

```text
no cursor yet + sequence 0                     -> FRESH
last_finalized = N, incoming = N + 1           -> FRESH
incoming > N + 1                               -> SEQUENCE_GAP     (no effect)
incoming <= N, receipt exists, same request    -> REPLAY recorded outcome (no effect)
incoming <= N, receipt exists, different req   -> SEQUENCE_REUSED  (no effect)
incoming <= N, no receipt                      -> SEQUENCE_STALE   (no effect)
```

A queue entry at N+1 must never leapfrog N. There is **no sequence-reset
endpoint**: a device reinstall/re-provision requiring a fresh namespace
requires a new authenticated device identity, not a reset-to-zero button.

### C10-04 — Idempotency is request-bound (the WP-19 lesson carried forward)

The semantic request comprises the authenticated organisation/user/device
namespace, `offline_operation_id`, `device_sequence`, `idempotency_key`,
`operation_kind`, the normalised payload and `created_at`; it excludes
`trace_id`. Canonical JSON sorts object keys recursively but **preserves array
order by default**. Operation-specific normalisation is permitted only where
semantics require it (e.g. `recipient_user_ids` is a set and may be
deterministically normalised after uniqueness validation; an ordered array is
never generically sorted). A SHA-256 fingerprint of the canonical semantic
request is stored. Same sequence + different fingerprint is a conflict even if
the downstream domain service would regard the idempotency key as duplicate.

### C10-05 — The initial replay allowlist is deliberately narrow

Checkpoint A admits only operations whose meaning remains honest when
execution is delayed until reconnection:

| Operation kind | Payload authority |
|---|---|
| `FIELD_ASSIGNMENT_ACCEPT` | `assignment_id`, `expected_status` |
| `FIELD_ASSIGNMENT_DECLINE` | `assignment_id`, `expected_status` |
| `FIELD_ASSIGNMENT_START` | `assignment_id`, `expected_status` |
| `FIELD_ASSIGNMENT_COMPLETE` | `assignment_id`, `expected_status` |
| `INCIDENT_FIELD_MESSAGE_SEND` | `incident_id` + existing strict WP-18 send fields, except server-injected replay idempotency/trace |
| `INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE` | `message_id` |

Existing authorization surfaces are preserved, never replaced; message
bounds/recipients/body/media/retention reuse WP-18 semantics exactly.

**Explicitly not admitted yet:** `FIELD_STATE_UPDATE`, patrol run
start/checkpoint verify, patrol route create/publish, patrol schedule/cancel,
command abandonment, assignment creation/cancellation, commander oversight,
incident creation/closure, Whisper, evidence upload, Constitution approvals.

Not arbitrary scope reduction: WP-19 established SERVER receipt time as the
authoritative checkpoint timing input, with client `source_at` as telemetry
only — an offline patrol verification arriving late with a pretend-
authoritative device timestamp would silently destroy a C9 invariant just
closed. `FIELD_STATE_UPDATE` is deferred because the current implementation
upserts the arriving value into current state; an old offline sample arriving
after a newer live sample could regress current state unless a
historical-vs-current merge rule is designed first. **We will not solve
offline behavior by lying about time.**

### C10-06 — Delayed client time is telemetry only

`created_at` never backdates a Field assignment transition, never becomes a
message's authoritative `sent_at`, never overrides server receipt time, never
manufactures an earlier acknowledgement, never overrides current
policy/authorization. A queued message whose `expires_at` is already invalid
when the server attempts the send is deterministically rejected under the
existing domain rule — not backdated into success.

### C10-07 — Durable replay architecture (Checkpoint B)

Two persistence concepts:

- **`FieldOfflineDeviceCursor`** — mutable synchronisation state, unique by
  organisation + site + user + device, tracking **`last_finalized_sequence`**
  (not "last applied"; a deterministic rejection consumes a queue position
  exactly as an application does — binding).
- **`FieldOfflineOperationReceipt`** — durable reliability record, unique by
  organisation + site + user + device + `device_sequence`, additionally
  protecting `offline_operation_id` reuse across another sequence. Stores the
  operation identity, namespace, kind, request fingerprint, client
  `created_at`, first `received_at`, processing/final status, a safe bounded
  result snapshot/reference, safe conflict code, `finalized_at`, and
  first-trace/attempt audit linkage. **Never stores incident-message body or
  media again in the generic inbox** — the fingerprint covers sensitive
  payload semantics; the encrypted client queue resubmits the exact payload if
  an unresolved receipt needs recovery. Receipt/history relations are
  RESTRICT, never cascade-erased with mutable domain state.

### C10-08 — Crash semantics: effectively once, not fictional exactly-once

```text
1. Validate current principal + authenticated device context.
2. Validate V2 operation.
3. Acquire/establish durable sequence receipt.
4. COMMIT the request fingerprint before invoking downstream effect.
5. Claim receipt for processing using CAS/lease semantics.
6. Invoke the existing domain service with a deterministic downstream
   idempotency key derived server-side from the offline operation identity.
7. Finalize receipt as APPLIED or REJECTED.
8. Atomically advance last_finalized_sequence.
```

Internal lifecycle: `RECEIVED -> APPLYING -> APPLIED | REJECTED | UNKNOWN`.
APPLIED and deterministic REJECTED advance the cursor; UNKNOWN does not. If
the process dies after the downstream effect commits but before receipt
finalization, retry reacquires the same receipt and invokes the same
deterministic downstream idempotency identity — the domain converges instead
of double-firing (§76 duplicate/retry discipline).

### C10-09 — No client-controlled downstream idempotency key

The client's `idempotency_key` stays part of semantic identity, but the
executor derives the actual downstream key deterministically:

```text
offline:<SHA-256(organisation + site + user + device
                 + offline_operation_id + operation_kind)>
```

Exact encoding is part of the contract tests. Two client queue entries can
therefore never steer unrelated server-domain calls into one downstream
idempotency namespace.

### C10-10 — Domain rules remain authoritative

The offline layer is not a second Field implementation. It calls the existing
domain services and preserves their RBAC/ABAC, tenant/site boundaries,
assignee restrictions, incident eligibility, recipient entitlement,
expected-status transitions, retention/expiry, idempotency, audit/timeline
and outbox behavior — none duplicated inside the replay service. The replay
layer owns only: device-context binding, queue sequencing, request
fingerprinting, receipt lifecycle, safe conflict translation, and recovery
orchestration.

### C10-11 — Machine-readable safe outcomes

A finalized result carries safe synchronisation metadata:
`offline_operation_id`, `device_sequence`, `operation_kind`,
`outcome: APPLIED | REJECTED`, `replayed`, `finalized_at`,
`next_expected_sequence`, bounded `result_ref`/`result_snapshot`, `trace_id`.

Unfinalized/conflict codes include at least: `DEVICE_CONTEXT_MISMATCH`,
`SITE_SCOPE_MISMATCH`, `SEQUENCE_GAP`, `SEQUENCE_REUSED`, `SEQUENCE_STALE`,
`OPERATION_ID_REUSED`, `OPERATION_NOT_ALLOWED`, `OPERATION_IN_PROGRESS`,
`DOMAIN_REJECTED`, `UNKNOWN_OUTCOME` (with `expected_sequence` /
`received_sequence` where relevant).

Foreign-tenant/non-entitled target detail never surfaces through these codes:
a domain 404/403 must not become "exists but belongs to another user." A
replay of a previously rejected operation returns the SAME stored rejection
with `replayed: true` — a deterministic rejection is not retried forever.

## Privacy and wire discipline

No generic offline machinery emits message bodies, recipient lists,
need-to-know briefs, hidden target identifiers, verification evidence or
sensitive Field state into logs, metrics, shared socket signals or generic
sync audit records. Offline audit carries sequence/operation identity, safe
kind, disposition, trace and fingerprint — never content.

## Checkpoint A — CONTRACT LOCK (the only authorised implementation work)

Permitted scope: `packages/contracts/src/field-offline.ts` (preferred new
file), `field-offline.test.ts`, barrel exports as required, and `field.ts`
only for legacy V1 documentation/re-export compatibility. No database, NestJS
service, migration or HTTP changes.

Deliverables: the V2 discriminated union; strict payloads for all six
admitted kinds; sequence/result/conflict contracts; a pure canonical
semantic-request normalizer; pure sequence-classification helpers; explicit
legacy V1 treatment; bounds on every string/list/object.

Mandatory Crucible tests: sequence 0 fresh; N+1 fresh; N+2 gap; old sequence
with receipt -> replay/reuse; old sequence without receipt -> stale; new trace
keeps the semantic request identical; object key order does not change the
request; ordered arrays stay ordered; recipient-set normalisation is
deterministic; same sequence + changed payload fingerprints differently; same
`offline_operation_id` on another sequence is conflict-capable; unknown kind
refused; wrong payload for a known kind refused; all six allowed kinds parse;
all explicitly forbidden kinds fail; message bounds at least as strict as
WP-18; `created_at` present but never represented as authoritative server
time.

At completion: **STOP.** Return exact branch head, base SHA, changed files,
contract diff, test count, typecheck/lint/test result. Prisma work does not
start automatically.

## Checkpoint B — SERVER REPLAY HARNESS (HOLD until Checkpoint A passes)

Expected scope when authorized: Prisma cursor + receipt persistence, additive
migration, offline module/repository/service, internal operation executor
registry, the authenticated device-context seam, direct integration against
existing Field/FieldMessaging services, crash/recovery harness, **no public
endpoint**. A public mobile replay API remains outside WP-20 until a genuine
server-authenticated device identity can populate
`AuthenticatedFieldDeviceContext`.

#### Locked integration rules (issued at the Checkpoint A gate)

1. **Aggregate message size (inherited WP-18 hardening).** Before
   `INCIDENT_FIELD_MESSAGE_SEND` is admitted by the replay executor, the
   canonical 64 KiB aggregate message validation moves BEFORE the mutating
   repository transaction, with a regression proving an oversized aggregate
   produces zero message, recipient, timeline and outbox rows. WP-18 is not
   reopened generally.
2. **Receipt-before-FRESH.** At `device_sequence == next_expected`, an
   existing durable receipt from a crashed attempt (RECEIVED/APPLYING/
   UNKNOWN) is examined before any new execution: same fingerprint resumes
   per receipt status, different fingerprint conflicts. The cursor alone
   never authorizes a second effect.
3. **Snapshot allowlists.** `result_snapshot` is populated only from
   per-operation safe allowlists (assignment: id + status; send: message id +
   incident id + recipient count; acknowledge: message id) — never by
   serializing a domain object. No message body, recipient list or
   need-to-know content enters the generic receipt, result, audit or logs.

## Checkpoint B acceptance tests (locked now)

Same device + concurrent same sequence -> exactly one domain effect. Same
sequence + changed request -> conflict, zero second effect. Sequence gap ->
zero effect. Device A seq0 and device B seq0 -> independently valid. Same
device string under another user -> cannot inherit cursor/receipt. Cross-site
outside authenticated device scope -> fail before replay. N+1 racing
unresolved N -> cannot leapfrog. Crash after downstream commit, before receipt
finalization -> retry converges, zero duplicates. Assignment replay -> zero
duplicate audit/outbox. Message send replay -> exactly one message and
recipient set. Acknowledgement replay -> no duplicate effect. Finalized
rejection -> advances sequence exactly once; duplicate returns the same
rejection. Unknown outcome -> does not advance. Duplicate response -> original
bounded result metadata, not the current mutable domain object. Generic
inbox/logs/socket -> no message content.

## Out of scope / milestone accounting

Whisper offline replay is OUT OF SCOPE. WP-20 proves the central
ordering/idempotency/recovery foundation; it does **not** by itself complete
architecture Proof D — that is the later integrated WAN-loss demonstration
where actual Field/Edge clients queue and recover.

## Gate state (issued with this directive)

```text
WP-20 architecture               GO
WP-20 directive branch           GO
WP-20 housekeeping docs          GO
WP-20 Checkpoint A contracts     GO after directive acceptance

WP-20 persistence                HOLD
WP-20 replay executor            HOLD
WP-20 HTTP/mobile sync endpoint  HOLD
Field state offline replay       HOLD
Patrol start/verify replay       HOLD
Whisper offline replay           OUT OF SCOPE
```
