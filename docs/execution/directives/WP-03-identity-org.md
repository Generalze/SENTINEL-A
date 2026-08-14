# Directive WP-03 — Identity & Organisation Domain

**Lane:** Core (Sonnet) · **Wave:** 2 · **Depends:** WP-02
**Review chain:** Opus adversarial review (this is authorisation code) → Lead merge gate

## Spec references
Architecture §38 (Identity & Organisation), §39.2 (multi-tenancy: cross-org denied by default), §62 (roles), §62.1 (permission model — implement the ALLOW-WHEN rule verbatim).

## Deliverables (`services/core-api/src/modules/identity`)
1. **Prisma models:** `Organisation`, `Site`, `Zone` (belongs to Site), `User` (belongs to Organisation; `clearance Int 0-5`), `UserRole` (user ↔ role string ↔ optional site scope). Migration committed.
2. **Roles:** constant registry of Milestone-1 roles: `site.commander`, `operator`, `dispatcher`, `field.operative`, `investigator`, `evidence.custodian`, `admin` — each with an action allow-list (registry lives in code, versioned; §62 table is the source).
3. **Dev auth (Milestone 1 only):** guard reading `x-dev-user-id` header when `DEV_AUTH_ENABLED=true`; loads user + roles into `request.principal`. File carries a prominent comment: dev-only, replaced by OIDC in a later milestone; when the flag is false every request is 401.
4. **Access guard implementing §62.1:** ALLOW action WHEN role permits action AND organisation matches AND site/incident scope matches AND clearance >= object classification AND purpose is valid (purpose required for SENSITIVE+ reads). Decorator-driven: `@RequiresAction('incident.view', { classification: ... })`. Every DENY logs actor, action, and failed condition.
5. **Endpoints:** CRUD-minimal — create/list organisations (admin only), create/list sites and zones, create/list users with roles. Every query tenant-filtered by the principal's organisation; cross-org access returns 404 (not 403 — do not leak existence).

## Acceptance criteria
1. Cross-organisation read attempt → 404 and a logged denial. Test proves it.
2. Clearance boundary test: equal passes, one-below fails.
3. Role without the action → denied; role with action + wrong site scope → denied.
4. Unit tests for the guard cover every §62.1 conjunct independently.
5. Seed script creates: 1 org, 1 site, 3 zones, users for each Milestone-1 role.

## Out of scope
Real authentication, sessions, password/OIDC flows, device trust (arrives with Shield later).
