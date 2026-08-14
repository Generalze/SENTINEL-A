# Directive WP-08 — Decision Ledger

**Lane:** Core (Sonnet) · **Wave:** 3 · **Depends:** WP-02, WP-06 (interface)
**Review chain:** Opus adversarial review → Lead merge gate

## Spec references
§5.2 (ledger contents), §61 (append-only; no rewriting of security history), §29 (Black Box is later — the ledger is Milestone 1's audit spine).

## Deliverables (`services/core-api/src/modules/ledger`)
1. Prisma `DecisionLedgerEntry` mirroring `@sentinel/contracts` ledger.ts. **Append-only:** service exposes append + query only; no update/delete methods exist. Outcome updates are NEW entries with `supersedes_entry_id` — history is never rewritten.
2. `LedgerService.append(entry)` — validates with the contracts schema, stamps `entry_id`/`decided_at` if absent, computes `content_hash` = SHA-256 over a canonicalised (sorted-keys) JSON of the entry, and stores `previous_hash` of the org's latest entry — a per-organisation hash chain making silent tampering detectable.
3. Implements the `LedgerSink` interface WP-06 defined; wire ConstitutionService's buffered stub to the real sink at module init (flush the buffer).
4. `GET /api/v1/ledger` — tenant-scoped, `investigator`/`admin` roles only, filter by decision_type/time, pagination. Read access is logged (who read the ledger, when).
5. `LedgerService.verifyChain(organisationId)` — walks the chain, returns first broken link if any; exposed as an admin endpoint.

## Acceptance criteria
1. No update/delete path exists (review grep + test that the service surface has no such method).
2. Chain verification detects a manually corrupted row in a test (write via raw SQL in the test to simulate tampering).
3. Constitution evaluations from WP-06 land as entries automatically — count test.
4. Unauthorized role reading ledger → denied + denial logged.

## Out of scope
Independent Black Box store (later milestone), cryptographic signing (hash chain now), retention policies.
