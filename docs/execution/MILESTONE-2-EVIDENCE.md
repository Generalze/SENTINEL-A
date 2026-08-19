# Milestone 2 — Evidence Record

**Accepted base:** WP-21B closure `e779a454`; this record is produced by WP-22.

The purpose of this file is to keep the difference between **implemented**,
**tested** and **not yet proven** honest. A capability that exists in code but
has no test proving it is not "done", and a test that exercises a server-built
fixture is not proof that a real device did anything.

## Reading the columns

- **Implemented** — the behaviour exists in shipped code on accepted `main`.
- **Tested** — a named regression proves it, and would fail if the behaviour
  regressed.
- **Not yet proven** — deliberately outstanding. Nothing here may be upgraded
  by wording.

## Capability matrix

| Capability | Implemented | Tested by | Status |
|---|---|---|---|
| Field assignment lifecycle (create/accept/start/complete/cancel), CAS + idempotency | WP-16 | `field.api.integration.spec.ts`; `m2-field-loop` steps 1 | Tested |
| Authoritative Field operative state + append-only history | WP-16 | `field.api.integration.spec.ts`; `m2-field-loop` step 2 | Tested |
| Site-scoped Field realtime, need-to-know payloads (C7-08) | WP-17 | `realtime.field-isolation.integration.spec.ts`; `m2-field-loop` step 9 | Tested |
| Field `site_id` referential integrity (composite FK) | WP-17A | `field.api.integration.spec.ts` FK pin | Tested |
| Incident-scoped messaging: named-recipient entitlement, oversight as its own action, immutable recipients | WP-18 | `field-messaging.api.integration.spec.ts`; `m2-field-loop` step 3 | Tested |
| Transport-evidence delivery state (§76), per-socket acknowledgement | WP-18 | `field-messaging.realtime.integration.spec.ts` | Tested |
| Aggregate message size refused before the durable write | WP-20/R10 | `field-offline.acceptance.integration.spec.ts` | Tested |
| Patrol route versioning, immutable published standards | WP-19 | `patrol.api.integration.spec.ts` | Tested |
| Materialised checkpoint windows; TOO_EARLY / VERIFIED / LATE / EXPIRED | WP-19 | `patrol.api.integration.spec.ts` | Tested |
| MISSED as the server sweep's judgement alone; abandonment cannot launder | WP-19 | `patrol.api.integration.spec.ts`; `m2-field-loop` step 4 | Tested |
| Patrol evidence tuple enforced below the service layer | WP-19A | `patrol.audit-regressions.integration.spec.ts` | Tested |
| Offline V2 contract, contiguous sequencing, request-bound fingerprints | WP-20 | `field-offline.test.ts` — 24 contract tests; `field-offline.acceptance.integration.spec.ts` — 25 live tests | Tested |
| Offline effectively-once: claim fencing, domain-evidence recovery, exhaustion | WP-20/B10 | `field-offline.acceptance.integration.spec.ts`; `m2-field-loop` steps 10–11 | Tested |
| Offline allowlist is closed at six kinds | WP-20 | `m2-field-loop` step 5 (inadmissible kinds refused; the set is pinned) | Tested |
| Whisper contract: modality, lifecycle, canonicalisation, signed statement | WP-21A | `whisper.test.ts` — 69 contract tests (the contracts package totals 202 across all domains) | Tested |
| Whisper Studio: authority matrix, configuration freeze, distinct activation approver, one ACTIVE version | WP-21B | `whisper.studio.integration.spec.ts`; `m2-field-loop` step 15 | Tested |
| Ed25519 verification with a server-selected key; no client-chosen verifier | WP-21B | `whisper.runtime.integration.spec.ts` | Tested |
| Whisper anti-replay: seven-column identity; invalid signature consumes no nonce | WP-21B | `whisper.runtime.integration.spec.ts`; `m2-field-loop` step 13 | Tested |
| Principal cannot borrow another actor's invoke authority | WP-21B/C12-01 | `whisper.c12-regressions.integration.spec.ts`; `m2-field-loop` step 14 | Tested |
| Crash between incident commit and SILENT entry converges before ACCEPTED | WP-21B/C12-02 | `whisper.c12-regressions.integration.spec.ts` | Tested |
| Recognition initiates but never approves; two distinct commanders still required | WP-21B | `m2-field-loop` step 6 | Tested |
| No public Whisper recognition endpoint | WP-21B | `m2-field-loop` step 16: a **live route-table guard** — registered whisper routes must equal exactly the seven Studio routes, and no path in the whole table may match `/recogni|invoke|device-action/i` | Tested |
| Cross-tenant / wrong-site / unassigned isolation | WP-16..WP-21 | `m2-field-loop` steps 7–8: each refusal is asserted **byte-identical** (status *and* response body) to the same request for a nonexistent id, across the assignment, message, patrol run, Whisper signal and the Whisper-raised incident, with no narrative identifier present in the body | Tested |
| Proof A regression (Milestone 1 protected workflow) | WP-13 | `tests/integration/proof-a.test.ts` | Tested |

## Deliberately not yet proven

| Item | Why it is not proven | What would prove it |
|---|---|---|
| **Proof C — authenticated device invocation** | **UNCLAIMED.** Whisper recognition is exercised through a server-constructed `AuthenticatedWhisperDeviceContext` and a test-injected Ed25519 key. That proves the server-side authority, recognition, replay and SILENT-entry semantics — not that a production-authenticated physical device originated the signed action. | A real device identity facility (certificate/registry) issuing the context, a genuine client producing the signed device action, and the operative receiving the resulting acknowledgement. |
| **Proof D — degraded operations / WAN loss** | **UNCLAIMED.** WP-20 supplies the server-side ordering, idempotency and recovery foundation, exercised through the internal replay service. No WAN failure, no Edge continuity and no real Field client queue are demonstrated. | The integrated demonstration: WAN fails, Edge maintains critical local function, real Field clients queue, and central synchronisation recovers with no duplicate incident action. |
| Public mobile/device sync API | Prohibited until a genuine authenticated-device facility exists (C10-02, W21-05, B11-08). | The same device identity facility, then a directive authorising the surface. |
| Whisper modalities beyond DEVICE_ACTION | Out of scope by W21-01 — one safe deterministic modality is proven first. | A separate work package with its own anti-spoof evidence. |
| Command-web Field/Whisper UI | Not a Milestone-2 deliverable. | A UI work package. |

## Known debt carried forward

- **Patrol sweeper timing (closed in WP-22).** The WP-19 suite raced an
  ambient five-second sweep. Fixed at the scheduler boundary via a **test-only
  DI seam** (`PATROL_SWEEP_SCHEDULER`), with the interval hard-wired at 5000 ms
  and the boot sweep unconditional; the sweep logic is unchanged. The first
  attempt exposed the setting through the env schema, which would have been a
  production kill-switch for missed-checkpoint detection — recorded here
  because it is the sharper lesson: making a safety-critical job configurable
  is not the same as making it testable.
- **Incident/Event scalar site semantics.** Unchanged since WP-18; the
  divergence remains an explicit sign-off note rather than a silent
  assumption.

## Milestone-2 gate summary

```text
migrations from zero        20
patrol stress               50 consecutive runs, 0 failures
Proof A                     1/1
Proof C                     UNCLAIMED
Proof D                     UNCLAIMED
tag                         milestone-2-field-workflow (claims neither proof)
```
