# Directive WP-14 — Security Hardening (Wave 2 findings remediation)

**Lane:** Senior (Opus) — security-critical · **Wave:** 3.5 (after Wave 3 merges, before Wave 4 wiring)
**Depends:** Wave 3 merged · **Review chain:** Lead executes the merge; a second adversarial pass re-verifies each fix
**Source:** `docs/execution/security/WAVE-2-FINDINGS.md`

## Objective
Close every confirmed finding from the Wave 2 adversarial review. Each fix lands with a regression test that fails before and passes after (Crucible §25). This is the wave-boundary contract change window, so C1's contract edit is now permitted.

## P0 — must fix first
1. **C1 cross-tenant idempotency.** `deriveIdempotencyKey` gains `organisationId` (and `siteId`) as the leading key components; `events.repository` lookup becomes `findFirst({ where: { idempotencyKey, organisationId } })`; the `@unique` becomes a composite `@@unique([organisationId, idempotencyKey])`. Migration required. Regression test: org-A event cannot mask an org-B event with a colliding source/event id.

## Canonical Principal (fixes H1, H2, L1)
2. One `Principal` type in a shared location importable by every module (`packages/contracts` or a new `packages/auth`): `{ user: { id, clearance }, organisation_id, roles: {role, site_id|null}[], hasAction(action): boolean }`. Delete the per-module principal shims and the duplicated `RequiresAction` decorator/metadata-key; every module uses the identity decorator + guard. Health endpoints get a `@Public()` exemption so probes work when `DEV_AUTH_ENABLED=false`. All flag reads go through the zod config. **Add an AppModule e2e boot test** (boots the whole app on an ephemeral port) exercising: authorised request 200, wrong-role 403, cross-org 404, health reachable with auth disabled.

## Privilege & tenancy (H3, M4, M5, M6, L2)
3. `POST /users`: reject `dto.clearance > principal.user.clearance`; every `site_id` in a role assignment must belong to the principal's org.
4. List endpoints (organisations/sites/zones/users) intersect results with the principal's site scope unless an org-wide assignment grants the action; apply the events cursor + `MAX_LIST_LIMIT` cap to all of them.
5. Events `list` and `findUnpublishedOlderThan` filter `duplicateOfEventId: null`.
6. Restrict/rate-limit organisation creation so an admin cannot mint unbounded orphan tenants.

## Constitution wiring (M1, M2, M3)
7. `POST /users` role grant calls `ConstitutionService.evaluate` for `user.role.grant`; the result gates the write and lands in the ledger.
8. Approver roles are resolved server-side from Identity (never trusted from the request body); actor/approver id comparisons normalise (trim + case-fold) before self-exclusion and distinctness; two-person control additionally requires approver-role diversity where the policy demands it.
9. Constitution target is a fixed platform-org constant requiring platform-level authority; document the platform-singleton policy model explicitly (or add an org column if per-tenant policies are intended — lead decision: platform singleton for Milestone 1).

## Input safety (M7)
10. Cap serialized size of `metadata`/`location` and lengths of `track_ids`/`evidence_refs` in the contracts event schema; add `@nestjs/throttler` on `/api/v1/events` ingest; set an explicit JSON body limit in `main.ts`.

## Acceptance
- Every finding C1–L2 has a named regression test; the pre-existing clean bills stay clean (re-run their tests).
- `pnpm -r typecheck && lint && test` green; new AppModule e2e green.
- A re-run adversarial pass finds no CRITICAL/HIGH.
- Findings register updated with fix commit + test name per row.
