# Wave 2 Adversarial Security Review — Findings Register

**Reviewer:** Opus (adversarial security lane, read-only) · **Date:** 2026-08-14
**Scope:** identity, events, constitution modules + contracts + schema/wiring (Wave 2)
**Doctrine:** Crucible §25 — every confirmed finding is tracked and becomes a permanent regression test. Nothing is silently patched.

**Lead disposition:** C1 and the contracts-touching fixes are deferred to the **wave boundary** (EXECUTION_PLAN §6 forbids mid-wave contract changes; Fusion is building against contracts now). All confirmed findings are assigned to **WP-14 Security Hardening**, executed immediately after Wave 3 merges and before any auth is wired live in Wave 4. None of these are remotely exploitable today because the HTTP auth layer is not yet wired end-to-end (see H2).

| ID | Sev | Title | File(s) | Disposition |
|---|---|---|---|---|
| C1 | CRITICAL | Idempotency key omits organisation_id → cross-tenant event suppression + oracle | contracts/idempotency.ts:24; events.service.ts:23; events.repository.ts:36; events.prisma:51 | WP-14 P0 — add org_id (+site_id) to key; scope lookup by org |
| H1 | HIGH | Events routes carry decorator whose metadata key no bound guard reads → global AccessGuard inert on events | requires-action.decorator.ts:5 vs events/principal-action.guard.ts:5 | WP-14 — unify decorator/guard; delete shim |
| H2 | HIGH | Principal shape incompatible across modules → all 3 HTTP surfaces fail at runtime; health 401s when DEV_AUTH disabled; no AppModule boot test | dev-auth.guard.ts:57; events + constitution guards; health.controller.ts | WP-14 — single Principal type; @Public health; AppModule e2e |
| H3 | HIGH | Clearance/role escalation via POST /users + dev-auth impersonation (no privilege ceiling; site not checked against org) | user.dto.ts:11; users.service.ts:11,19 | WP-14 — reject clearance>creator; validate site∈org |
| M1 | MED | Constitution gates nothing — evaluate() has no caller outside its module | users.controller.ts:14 | WP-14 / Wave 4 — call evaluate() on role grant |
| M2 | MED | Two-person control forgeable — approver_roles caller-asserted; id comparisons not normalised (trim/case) | constitution.service.ts:70,264; engine.ts:356,376 | WP-14 — resolve roles server-side; normalise ids |
| M3 | MED | ORGANISATION_MATCH self-compares on constitution gate; policy is one global row (any tenant can alter global constitution) | constitution.service.ts:255; constitution.prisma:26 | WP-14 — platform-org constant + platform authority |
| M4 | MED | Site-scoped role grants org-wide reads (list endpoints name no site) | access.guard.ts:108; sites/users.service | WP-14 — intersect list scope with principal site grants |
| M5 | MED | Duplicate event rows are listed AND republished (queries don't filter duplicate_of null) | events.repository.ts:81,89 | WP-14 — add duplicateOfEventId:null filter |
| M6 | MED | Unbounded identity list endpoints (no take/cursor) | organisations/sites/zones/users controllers | WP-14 — apply events' cursor/MAX_LIST_LIMIT pattern |
| M7 | MED | Unbounded jsonb/arrays; no rate limiting; occurred_at bucket lets a source defeat dedup with sub-bucket shift | contracts/event.ts:24; main.ts | WP-14 — cap sizes; @nestjs/throttler on ingest |
| L1 | LOW | DEV_AUTH_ENABLED read raw (!=='true') in one guard vs zod-normalised config elsewhere | principal-action.guard.ts:54 | WP-14 — read from config |
| L2 | LOW | admin can create orphan organisations bound to nobody, unbounded | organisations.service.ts:11 | WP-14 — restrict/rate-limit org creation |

## Clean bills (verified, not merely asserted)
- **events append-only: CLEAN** — only the two documented `.event.update` exceptions; no delete/raw SQL in src.
- **constitution policy-row immutability: CLEAN** — writes are create + guarded status transitions; hash+version re-checked on every load.
- **evaluate() always ledgers: CLEAN** — unconditional `await ledger.append` between evaluation and return; rejecting sink fails the call.
- **validatePolicy: CLEAN** — all 5 rules, own-property checks, enforced at draft/boot/pre-activation.
- **identity query tenant-filtering: CLEAN** — every finder scoped by principal org; site→zone re-verifies ownership, 404 on cross-org; no create DTO accepts organisation_id from the body.

## Note on H2 vs plan
H1/H2/M1/M3 are the cross-module wiring that WP-03/04/06 directives explicitly deferred with `TODO-WIRED-IN-WAVE-4` markers — they were scheduled, not missed. The review's value is making them concrete and adding the hard requirements: one canonical Principal type, a booting AppModule e2e test, and health-endpoint exemption. Folded into WP-14 so integration is deliberate rather than discovered.
