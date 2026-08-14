# Directive WP-09 — Evidence Vault Foundation

**Lane:** Core (Sonnet) · **Wave:** 3 · **Depends:** WP-02
**Review chain:** Opus adversarial review → Lead merge gate

## Spec references
§26.2 (immutable originals, derived objects), §26.3 (chain of custody), §72.1-72.2 (storage split, write path), §48 (forensic readiness).

## Deliverables (`services/core-api/src/modules/evidence`)
1. **MinIO client** (S3 API via `@aws-sdk/client-s3` — approved dependency) with bucket `sentinel-evidence` created idempotently at boot; per-organisation key prefix `{organisation_id}/{evidence_id}`.
2. **Write path per §72.2:** `EvidenceService.ingest({organisation_id, source_id, content: Buffer, content_type, classification, related_event_ids})` → SHA-256 hash → object PUT → Prisma `Evidence` row (id, org, source_id, object_key, content_hash, size, content_type, classification per §47 table, captured_at, stored_at) → custody event `INGESTED`. The object is NEVER overwritten: the service has no update/replace method for originals.
3. **Custody events:** append-only `CustodyEvent` (evidence_id, at, actor kind system|user, actor_id, action INGESTED|VIEWED|DERIVED|EXPORT_REQUESTED|EXPORTED, detail). Every read through the API writes VIEWED.
4. **Derived objects:** `derive(evidenceId, transform_label, content)` → new Evidence row with `derived_from_evidence_id`, own hash, custody DERIVED on both rows. Originals and derivatives never share an object key.
5. **Integrity check:** `verify(evidenceId)` — re-download, re-hash, compare; result recorded as custody event; admin endpoint.
6. **Event snapshot helper for WP-07:** `preserveEventSnapshot(organisation_id, incident_id, event_ids)` — serialises the referenced event rows to canonical JSON, ingests as evidence classification EVIDENCE, returns evidence_id.
7. **API:** tenant-scoped list/get (metadata only; content download requires `evidence.read` + purpose string, custody-logged).

## Acceptance criteria
1. Ingest → hash matches independently computed SHA-256 (test).
2. No API or service path can overwrite an original object (review + test that ingest of same content produces a NEW evidence id).
3. verify() detects a tampered object (test tampers via direct S3 put to the same key using the client — then verify fails and custody records it).
4. Download without purpose → denied; with purpose → custody VIEWED entry written (test).
5. preserveEventSnapshot round-trips: snapshot content parses back to the exact events (test).

## Out of scope
Object-lock/WORM configuration (prod concern, documented TODO), retention/legal hold engine, export manifest generator (Milestone 2), video.
