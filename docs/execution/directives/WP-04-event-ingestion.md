# Directive WP-04 — Event Ingestion

**Lane:** Core (Sonnet) · **Wave:** 2 · **Depends:** WP-01, WP-02
**Review chain:** Opus adversarial review → Lead merge gate

## Spec references
§7.1 (event-first: events are immutable statements, conclusions come later), §40 (contract — already in `packages/contracts`), §64 (adapters do not make threat decisions), §64.1 (idempotency: duplicates are linked, never erased; the fact of multiple deliveries is preserved).

## Deliverables (`services/core-api/src/modules/events`)
1. **Prisma model `Event`:** columns mirror the §40 contract + `idempotency_key` (unique), `duplicate_of` (nullable self-reference), `received_count Int default 1`. No `updatedAt` — events are append-only.
2. **Append-only enforcement:** the module exposes create/read ONLY. No update or delete method exists anywhere in the service layer. Corrections are new events referencing the original via `metadata.corrects_event_id`.
3. **`POST /api/v1/events`:** validates body with `NormalisedEventSchema` from `@sentinel/contracts` (zero local redefinition); requires principal with `event.ingest` action; org in body must match principal org; computes idempotency key; on duplicate — increments `received_count` on the original, stores a linked duplicate record, returns 200 with `{ duplicate: true, original_event_id }` (idempotent, never 500 on replay).
4. **NATS publish:** accepted events publish to JetStream subject `sentinel.events.{organisation_id}.{site_id}` with the event JSON; stream `SENTINEL_EVENTS` created idempotently on boot (file-storage, 7d retention). Publish failure does NOT lose the event: DB write commits first; unpublished events are flagged (`published_at` nullable) and a retry sweep republishes them (§76: explicit delivery states).
5. **`GET /api/v1/events`:** tenant-scoped list, filterable by site, source_type, time range; pagination.

## Acceptance criteria
1. Same event delivered 3× → one canonical row, `received_count = 3`, duplicates linked; test proves no data about redelivery is lost.
2. Invalid event (bad confidence, missing trace_id) → 400 with field-level errors; nothing persisted.
3. Org-mismatch injection attempt → 404/denial, nothing persisted, denial logged.
4. NATS down during ingest → event persists, `published_at` null, retry sweep publishes when NATS returns. Test with the compose stack.
5. Grep-level check in review: no `.update(` / `.delete(` on the Event model anywhere.

## Out of scope
Correlation (WP-05), source adapters beyond HTTP (later milestones), WebSocket fan-out (WP-12).
