# Milestone 3 — Sign-off Record

```text
WP-26 PHYSICAL ACCEPTANCE      DEFERRED — NOT WAIVED
WP-28                          BLOCKED — NOT STARTED
Proof C                        UNCLAIMED
Proof D                        UNCLAIMED

MILESTONE 3                    OPEN
```

**There is no milestone-complete statement in this file, and there cannot be
one while either proof is unclaimed.** Milestone 3 exists to close Proof C and
Proof D and nothing else (`MILESTONE-3-ROADMAP.md`). Neither is closed. Every
other line below is subordinate to those four lines, and no accumulation of
green pipelines, passing suites or clean evidence bundles changes them.

This record follows `WP-26-HW-ACCEPTANCE-DEFERRED.md`, which established the
repository's practice for writing down a thing that has **not** been achieved.
Deferred does not become passed. Blocked does not become started. Unclaimed
does not become proven by being described at length.

---

## The five things this milestone keeps separate

The whole risk in a milestone with two physical proofs is that five different
achievements get spoken about in one word. They are not interchangeable, they
are not ordered by difficulty, and passing four of them says nothing about the
fifth.

| # | Kind of assurance | What it establishes | What it cannot establish | Status |
|---|---|---|---|---|
| 1 | **Software qualification** | The code does what its contracts say, proven by suites that would fail if it stopped. Typecheck, lint, source gate, unit and integration suites against the live stack. | That any of it has met real hardware or a real network. | **Passing** for the work packages listed below |
| 2 | **System integration** | The modules hold their promises *when composed* — one operative, one incident, one site, across assignment, state, messaging, patrol, offline replay and Whisper. | That the composition was exercised through a genuine device boundary or a genuine outage. | **Passing** at the M2 boundary (`m2-field-loop`); M3B composition is partial |
| 3 | **Physical-device qualification** | A real StrongBox-capable Android device produces hardware attestation that the server verifies to `TRUSTED`. | Anything about what that device then does operationally. | **DEFERRED — NOT WAIVED** (WP-26) |
| 4 | **Proof C** | A physical device signs a real `DEVICE_ACTION` Whisper, a SILENT incident is created, two distinct commanders approve, and the device acknowledges — no step simulated, stubbed or server-constructed. | Anything about behaviour under connectivity loss. | **UNCLAIMED** |
| 5 | **Proof D** | An **actual** outage: central online, a real Field device connected, an Edge operational; the WAN severed; local operation continues; some operations explicitly refused; the link restored; authenticated reconnect; ordered synchronisation; duplicates converge; changed requests conflict; stale authority cannot rewrite current state; no duplicate incident action; complete audit trail. | Anything about hardware-backed identity, which is Proof C's question. | **UNCLAIMED** |

Three distinctions inside that table are the ones most easily lost, so they are
stated plainly:

- **1 is not 3.** A green CI run proves the code is internally consistent. It
  proves nothing about a secure element, because no secure element was present.
- **3 is not 4.** A device reaching `TRUSTED` is a device Sentinel is willing to
  believe. Proof C asks what happens when that device *acts* — through the
  Constitution, with two human approvals and an authenticated acknowledgement.
- **2 is not 5.** The offline replay machinery is exercised today by an internal
  replay service. That is system integration. Proof D requires a **real client
  queue behind a severed link**; a mocked method call and an `offline = true`
  flag are explicitly excluded by the locked definition.

---

## Work package status

```text
WP-23  Device Identity & Trust Contract Lock   CLOSED at ded82d596
WP-24  Shield Device Registry                  CLOSED at 578055a2
WP-25  Authenticated Device Gateway            CLOSED at 572ab324
WP-26  Field Mobile Foundation                 IMPLEMENTATION COMPLETE
                                               SOFTWARE QUALIFICATION PASS
                                               PHYSICAL ACCEPTANCE DEFERRED — NOT WAIVED
WP-27  Real DEVICE_ACTION Whisper              CLOSED at 662a91c7
                                               ends at VERIFIED_STATEMENT by design
WP-28  Proof C gate                            BLOCKED — NOT STARTED
                                               blocker: WP-26 physical acceptance
WP-29A Device policy lease persistence         IMPLEMENTED
WP-29B Edge identity and trusted time          IN EXECUTION
WP-30  WAN-loss recovery harness               IN EXECUTION
WP-31  Proof D evidence machinery              SOFTWARE IMPLEMENTATION COMPLETE
                                               PROOF D ACCEPTANCE BLOCKED — UNCLAIMED
```

WP-31's split is the point of this record and is deliberate. The directive
governing this lane permits the software and harness implementation to complete
while Proof D physical/system acceptance remains blocked. **The two halves are
recorded separately so that the first can never be read as the second.**

---

## What WP-31 delivered, and what it deliberately did not

### Delivered — the evidence collector

`services/core-api/src/modules/proof-d-evidence/` produces a machine-readable
evidence bundle for the locked Proof D definition. It is a gated read-only
script (`SENTINEL_PROOF_D_EVIDENCE=1`), not a route and not a scheduled job.

It rests on a finding that changed what was worth building: **most of Proof D
is already answerable by SQL over durable audit state that exists today.**
Receipts, cursors, gateway events, policy leases and outbox backlog already
record what an assessor needs. So WP-31 built a collector, not new
instrumentation:

```text
NO new metrics platform.   NO counter store.   NO scrape endpoint.
NO time series.            NO background collection.   NO schema change.
Migration delta: 0.
```

### Delivered — the distinction the bundle exists to protect

An evidence artefact fails not by carrying a wrong number but by carrying a
number whose origin has been forgotten. **Central cannot observe an interval it
was absent for.** A collector that mixed what the server saw with what the
harness said would manufacture evidence while looking tidier for doing it.

Every fact in the bundle therefore carries its own provenance, and the
constructors make an unprovenanced fact unrepresentable:

```text
OBSERVED                   server-authoritative durable state, citing its tables
CLIENT_CLAIMED             durably stored, but the VALUE is the device's word
HARNESS_ATTESTED           central could not observe it; the harness says so
ABSENT                     the source exists, was queried, holds nothing
SOURCE_NOT_PRESENT         the source does not exist at this commit
SOURCE_NOT_READABLE        the source exists; this collector cannot read it
WITHHELD_BY_PRIVACY_RULE   collectable, and deliberately not collected
```

The last three are what "degrade honestly" means in practice. An unbuilt
source produces a fact naming the source and the question it would have
answered, never a silently dropped field. An arrived-but-unrecognised source
produces the opposite statement, because reporting a capability the system
now has as one it lacks is also a lie.

That second rule now applies to this document. When it was written, the Edge
transport, the Edge durable queue and the outage harness were all in flight.
Two of the three have since landed on this branch — the durable queue
(`services/edge-runtime/src/modules/queue`) and the WAN-loss harness
(`tests/wan-loss`). The Edge transport has not, and it is the one that still
gates Proof D: with no outbound client there is nothing to drain the queue to
central, and so no Edge-originated record for the collector to read.

### Delivered — the sign-off document you are reading

### NOT delivered, and not deliverable by this lane

- **No Proof D claim.** The bundle's claim block is a constant with no writer.
  There is no code path that can move it.
- **No conversion of simulator success into acceptance.** The bundle records
  the attested environment, and a `SIMULATED` severance is refused
  physical-acceptance eligibility with the reason stated in the artefact. At
  this commit **even a perfectly attested `FIELD` run is refused**, because no
  Edge receipt source exists to evidence Edge-side persistence. That is
  asserted by a test, not left to judgement.
- **No waiver of WP-26.** Nothing here touches it.

---

## Which Proof D facts come from durable state, and which are attested

This is the substance of the bundle, and the table is the honest answer to
"what does central actually know?".

| Locked-definition question | Provenance | Source |
|---|---|---|
| When the WAN was cut and restored | **HARNESS_ATTESTED** | Central has no record of its own absence. A separate **OBSERVED** corroboration reports the quiet interval in central's own audit trail — and says, in the artefact, that a quiet interval is consistent with an outage and does not establish one. |
| Which Edge remained operational | Identity and standing **OBSERVED** (`edges`, `edge_security_events`); continued operation **HARNESS_ATTESTED** | Central was the party cut off; it cannot witness Edge liveness during a severance. |
| Which Field client queued work | Device **OBSERVED** from receipts; local queue contents **HARNESS_ATTESTED**; what the device says it composed during the cut **CLIENT_CLAIMED** | `client_created_at` is durably stored and is still the device's clock. The schema calls it telemetry and forbids it from becoming authority; the bundle does not relabel it. |
| Which operations were admitted | **OBSERVED** | `field_offline_operation_receipts` — a receipt *is* what admission means. |
| Which were refused, and why each refusal occurred | Central refusals **OBSERVED** (`conflict_code`, and the richer `refusal_reason` in `device_gateway_operation_events`); device-local refusals **HARNESS_ATTESTED**, with an **OBSERVED** corroboration from `device_policy_leases` showing which lease expired inside the attested window | A refusal taken on the device while the link is down produces no central row at all. This half of Proof D is unevidenced without an attestation, and the bundle says so rather than omitting it. |
| Which Edge receipt proves persistence | **SOURCE_NOT_PRESENT** | The durable Edge queue is owned by another work package. |
| When reconnect occurred | **HARNESS_ATTESTED**, alongside **OBSERVED** `authenticated_device_contexts` | |
| Which authenticated Edge identity reconnected | **SOURCE_NOT_PRESENT** | Central keeps no Edge session record at this commit. What *is* observable — the Edge roster and standing at the site — is emitted separately and the fact points at it. |
| Which operation central received first, and what it produced | **OBSERVED** | `first_received_at`, `outcome`, `conflict_code`, `finalized_at`, `first_trace_id`. |
| How duplicates converged | **OBSERVED, and structural** | Duplicate suppression is not measured. It is enforced by unique indexes, and the collector verifies those indexes are **present in the database the run was performed against** by reading `pg_indexes`. A missing constraint is a far louder finding than any counter. |
| How changed requests conflicted | **OBSERVED** | A changed request at a consumed position is refused in the classifying transaction and leaves *no receipt*; the bundle says so and points at the gateway refusal stream. |
| Final cursor / queue / domain state | **OBSERVED** | `last_finalized_sequence`, receipt status distribution, assignment and operative state projections. Message domain state is **WITHHELD_BY_PRIVACY_RULE** — see below. |
| No duplicate operational action | **OBSERVED, structural and derived** | Eight named checks, each stating its own basis, plus a written limitation saying what they do *not* establish. |
| Fan-out recovery | **OBSERVED** | Four outbox tables' `published_at IS NULL`, each already indexed for that predicate, counted at organisation scope. |
| Complete audit trail | **OBSERVED** | `field_audit_log` kinds, device security events, trust transitions, and the `trace_id` set joining the chain end to end. |

---

## Privacy constraints on the evidence, and how they are enforced

These are absolute, and they are enforced structurally rather than by anyone
remembering them.

**The source allowlist is the privacy boundary.** A fact may only be marked
OBSERVED if it cites a table on `PROOF_D_EVIDENCE_SOURCES`. That list contains
**no Whisper table at all** and **no message or recipient table**, so the
following cannot be produced by any code path in the collector:

- **No `recipient_user_id`, in any field, at any depth.** WP-18's protected
  recipient set must not be reconstructible from an evidence artefact. Message
  domain state is recorded as `WITHHELD_BY_PRIVACY_RULE` with the reason —
  visibly withheld, so the decision reads as a decision rather than an
  oversight somebody will later "fix".
- **No Whisper traffic rate and no per-device or per-user duress counter.**
  That is traffic analysis on a duress channel: a counter that rises when a
  particular operative is in trouble tells a hostile reader when to act. It is
  a safety defect before it is a privacy one, and Proof D — a question about
  ordering and idempotency under WAN loss — needs no Whisper row to answer.
- **No message bodies, need-to-know summaries, credentials, key material or
  nonces.** The frozen `DEVICE_AUDIT_FORBIDDEN_FIELDS` is inherited whole
  rather than restated, so the two cannot drift apart.
- **No `result_snapshot`, no `payload`, no operative `location`.** Every query
  is a named projection; there is not one `SELECT *` in the reader.
- **Aggregation at organisation scope.** The outbox backlog that routes per
  recipient is counted, never broken down.

Three independent mechanisms, because one is not enough:

1. **Structural.** The allowlist and the named projections. A table not on the
   list cannot be the basis of a field; a column not named cannot be selected.
   `incident_field_message_action_idempotency` is the one table admitted
   despite carrying a recipient column, for a grouped count against a known
   server-derived key — and the reader's return type has nowhere to put a
   recipient, so the value cannot cross whatever a future edit does to the
   query.
2. **A scanner.** It walks the finished bundle and **throws** on a forbidden
   key name, a forbidden key *family* (`recipient`, `duress`, `whisper`,
   `need_to_know`, per-device/per-user rates), or a value carrying key or token
   material. It throws rather than filtering: a collector that quietly stripped
   a forbidden field would emit a clean-looking bundle and hide the fact that
   something upstream had started producing recipient identifiers.
3. **Tests that feed the guards violations.** A guard only ever tested on clean
   input is a guard nobody has seen work. The suite asserts the exclusions
   directly — that the allowlist names no Whisper source, that the reader
   contains no star projection and never names the message tables, that a
   plausible future name like `recipient_user_digest` is refused, and that an
   attested value dressed in a durable source is rejected as an integrity
   failure.

---

## What remains, and what closes each item

```text
WP-26 physical acceptance   Run docs/execution/WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md
                            against 943a8fc2, on a StrongBox-capable device.
                            This is WP-28's start gate.

WP-28 / Proof C             Requires WP-26 closed first. A physical device
                            signing a real DEVICE_ACTION Whisper through the
                            genuine boundary, a SILENT incident, two distinct
                            commander approvals, an authenticated
                            acknowledgement. No step may be simulated.

Proof D                     Requires ALL of:
                              - central online and reachable before the cut;
                              - a real Field device, connected, authenticated;
                              - an Edge operational and continuing authorised
                                local functions during the severance;
                              - a real WAN severance, physical or logical —
                                not a flag and not a mocked call;
                              - operations explicitly refused during the cut
                                because policy expired or authority was
                                unavailable;
                              - authenticated reconnect and ordered sync;
                              - an Edge RECEIPT SOURCE, so Edge-side persistence
                                can be evidenced rather than attested. The Edge
                                durable queue (WP-29B) and the outage harness
                                (WP-30) have landed; the Edge transport that
                                would carry a receipt to central has not, and
                                nothing persists one centrally today.
                            The collector is ready. The run is not possible yet.
```

The refusals matter as much as the successes. A degraded client that quietly
allows everything has not survived an outage — it has stopped enforcing. That
is why the collector treats an absence of attested refusals as a reason to
decline eligibility rather than as a clean result.

---

## The sentence this file exists to prevent

Someone, later, reading a green pipeline and a clean evidence bundle, writing:
*"Milestone 3 is complete."*

It is not. Two of the five kinds of assurance in the table above have never
been attempted, because the hardware and the environment to attempt them do not
yet exist. The software is ready to be tested by them and is deliberately
fail-closed on every axis they would exercise. **That is a reason merging is
safe. It is not a proof, and it may not be cited as one.**
