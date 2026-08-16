# Wave 4 Adversarial Security Review — Initial Findings

**Reviewer:** Cipher (initial adversarial pass)
**Date:** 2026-08-16
**Scope:** Fusion incident-candidate hand-off, Incident/Response orchestration, Evidence snapshot persistence, realtime-facing incident data, and Constitution response-dispatch policy.

This register records the initial Wave-4 findings and the resolutions implemented in the working tree. It is an engineering security record, not a milestone sign-off. Proof-A/WP-13 acceptance remains a separate lead decision.

## Findings and disposition

| ID | Priority | Finding | Resolution / current state | Verification evidence |
|---|---|---|---|---|
| C4-01 | P0 | An incident-candidate message must not be able to claim a different organisation from the organisation encoded by its subject. Without that binding, a malformed or malicious publisher could create an incident in the wrong tenant. | **Fixed.** The incident consumer extracts the subject tenant and terminates candidates whose payload organisation does not match. The incident repository and detail paths remain organisation-scoped; callers use the canonical principal rather than a client-supplied organisation. | `incidents.consumer.spec.ts` covers a subject/payload tenant mismatch; `incidents.repository.ts` scopes incident and task reads by `organisationId`; controller handlers call `requirePrincipal`. |
| C4-02 | P1 | Fusion carries normalised `event_id` values while some Evidence callers hold database UUIDs. Treating the two identifiers as interchangeable can drop a requested event, produce a false snapshot, or allow an out-of-tenant lookup. | **Fixed.** Evidence resolves either identifier only inside the requested organisation, stores canonical database event IDs in the snapshot relation, and fails loudly when any requested ID is absent. | `evidence.service.spec.ts` covers unknown/out-of-tenant IDs; `evidence.repository.ts` validates UUID-shaped IDs before the UUID query and always applies the organisation predicate. |
| C4-03 | P1 | Incident-candidate redelivery can run the preserve-evidence task more than once. A second object and custody chain would make the response record ambiguous and weaken idempotent orchestration. | **Fixed.** Response-task identity is persisted as a nullable unique `response_task_id`; an existing snapshot is returned on retry, and a concurrent uniqueness conflict is re-read rather than creating a second canonical metadata row. | The Evidence service/repository tests cover duplicate response-task handling; Prisma migration `20260816120000_wp07_evidence_snapshot_idempotency` adds the database uniqueness constraint. |
| C4-04 | P2 | The response-dispatch actions were not represented in the certified Constitution baseline. In particular, a silent dispatch must be distinguishable from standard dispatch and must not silently bypass dual control. | **Fixed.** Lead ruling: Milestone-1 uses Constitution baseline **`sentinel-constitution-1.2.0`**. `response.dispatch.standard` is a no-approval action; `response.dispatch.silent` is a two-person action requiring the site-commander role. The `system.response` role is explicitly mapped to the response actions so the orchestration gate is evaluated by the Constitution rather than by client state. | `constitution.response-policy.spec.ts` exercises the standard/no-approval and silent/two-person policy paths; `constitution.policy.ts` contains the 1.2.0 version and action/category mappings. |
| C4-05 | P2 | A SILENT dispatch that receives a `REQUIRE_*` Constitution decision must not be marked delivered merely because the workflow retried. The prior state could otherwise be mistaken for an approved dispatch. | **Fixed for the hold decision.** The dispatch remains `REQUESTED`, the Constitution decision and trace are appended to the incident timeline, and no delivery transition occurs unless the decision is `ALLOW`. | `incidents.service.spec.ts` covers a SILENT dispatch remaining `REQUESTED` when two-person approval is required; the service calls `assertDeliveryTransition` before every state change. |

## Lead rulings and deferred work

The lead ruling is to keep the Constitution baseline at version `1.2.0` for this milestone. The response policy is therefore explicit and versioned: standard dispatch has no additional approval, while silent dispatch requires two-person approval. A policy change must continue to use the existing Constitution and Decision Ledger paths; the client cannot self-authorise delivery.

Two related capabilities are deliberately deferred and must not be inferred as complete from the current implementation:

1. **Typed coercion/duress candidate flag.** The current incident consumer derives `SILENT` from the versioned rule-pack marker tokens (`coercion`/`duress`). A first-class, schema-validated candidate field is deferred until the Fusion/contracts boundary is versioned. The marker fallback is narrow and documented; it is not a substitute for the typed contract.

2. **SILENT approval lifecycle.** Task-scoped approvals, site-commander authorisation, distinct-user enforcement, Constitution re-evaluation and ALLOW-only resume are implemented. Approval expiry/revocation semantics remain deferred; no retry is treated as a new approval and the unique handoff permits only one delivery.

The final audit also required crash-consistent mutation records. Incident creation, lifecycle changes, field acknowledgement, evidence-task completion, Constitution decisions, approval recording and local dispatch handoff now write their mandatory timeline/outbox records transactionally. A guarded periodic publisher retries unpublished incident updates after NATS recovery.

## Verification boundary

The named unit/service tests, live WP-07 integration test and database migrations are the evidence recorded for the resolutions above. This document does not claim that the complete WP-13 Proof-A scenario has passed and does not grant milestone sign-off. The typed coercion/duress contract and approval expiry/revocation remain later contract/workflow work.
