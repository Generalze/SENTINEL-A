# Directive WP-07 — Incident & Response Orchestration

**Lane:** Senior (Opus) with Sonnet support · **Wave:** 4 · **Depends:** WP-05, WP-06, WP-08
**Review chain:** Lead review

## Spec references
§12 (incident object, severity, response modes), §63 (workflow primitives), §76 (delivery semantics), §9.2 (Command needs).

## Deliverables (`services/core-api/src/modules/incidents`, `.../response`)
1. **Incident domain:** Prisma `Incident` per §12.1 (fields as in `@sentinel/contracts`), append-only `IncidentTimelineEntry` (at, kind, actor_user_id nullable, payload jsonb). Status transitions open → contained → closed enforced in one place; closing requires `closure_reason`.
2. **Incident-candidate consumer:** JetStream consumer on `sentinel.fusion.incident-candidate.*` — creates an Incident from a hypothesis (severity from `deriveSeverity`, response_mode default STANDARD; SILENT when the triggering rule pack flags coercion/duress families). One incident per hypothesis (idempotent, unique constraint on hypothesis_id).
3. **Response actions:** minimal Milestone-1 playbook, hardcoded as a versioned code object `PB-PROOF-A@1`: on SEV1/SEV2 incident → (a) preserve-evidence task (calls Evidence module WP-09 to snapshot related events), (b) notify-commander task, (c) dispatch-field task requiring field acknowledgement. Each task is a `ResponseTask` row carrying the §76 delivery state machine from `@sentinel/contracts` (`canTransition` enforced; illegal transition = thrown error + test).
4. **Constitution gate:** dispatch-field on a SILENT incident calls `ConstitutionService.evaluate` with action `response.dispatch.silent`; the task proceeds only on ALLOW (or records REQUIRE_* on the timeline and waits). Every evaluation's DecisionRecord flows to the Ledger (WP-08).
5. **Acknowledgement endpoint:** `POST /api/v1/incidents/:id/tasks/:taskId/ack` — principal must hold `field.acknowledge`; moves DELIVERED → ACKNOWLEDGED; timeline entry written; publishes `sentinel.incidents.updated.{organisation_id}`.
6. **Incident API:** tenant-scoped list/get with timeline, filterable by status/severity.

## Acceptance criteria
1. Hypothesis → incident-candidate → incident with correct severity and a populated timeline — integration test against the live stack.
2. Duplicate candidate delivery cannot create a second incident.
3. Illegal delivery-state transition rejected with test.
4. SILENT dispatch without Constitution ALLOW does not dispatch; timeline shows the REQUIRE_* decision.
5. Ack round-trip test: task reaches ACKNOWLEDGED and the NATS update fires.

## Out of scope
Real playbook engine/editor (Milestone 2+), timers/escalation chains (stub interfaces only), external connectors.
