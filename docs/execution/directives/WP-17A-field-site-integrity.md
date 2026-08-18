# Directive WP-17A - Field Site Referential Integrity

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 7 (hardening)
**Depends:** WP-16 Field Domain, WP-17 Field Realtime
**Review chain:** Cipher adversarial review -> Lead merge gate
**Status:** Implemented and in final merge gate. Presence of this work package
on `main` closes C7-07 and completes Wave 7.

## Objective

Make a Field record's `site_id` refer to a site that actually exists in the
caller's organisation. WP-17 proved the id is *subject-safe*; it did not prove
the site is *real*.

## Why this is not an acceptable long-lived limitation

WP-17 recorded this as an accepted limitation on the grounds that it is less
severe than the cross-site leak it replaced. On review that framing is too
generous, and this directive supersedes it:

- Field assignment and operative-state rows are **audited, authoritative
  history**. A row naming a site that does not exist is a permanent, unfixable
  record — the audit trail asserts something about a place that was never in
  the tenant.
- The same id reaches the outbox and therefore a realtime room name. A room for
  a nonexistent site is unreachable by construction, so the event is silently
  undeliverable — a Field signal that no one can receive, with no error surfaced
  to the writer.
- It weakens the §62.1 site conjunct from "the site you are scoped to" to "any
  string you are scoped to", which is exactly the class of drift the Field
  domain was built to close.

Severity is **P2**: it requires an organisation-wide Field grant to reach, it
cannot cross a tenant boundary, and assignment creation is already constrained
by the assignee's site-scoped `field.operative` role. It is an integrity defect,
not a disclosure one.

## Deliverables

- Service-layer existence check on every Field write that names a site
  (`createAssignment`, `recordState`): the site must exist **and** belong to the
  caller's organisation. A site in another tenant must be indistinguishable from
  a site that does not exist — 404/400, never a message that confirms it.
- A Prisma relation from the Field models to `Site` where the model allows it,
  with an additive migration. Before adding the constraint, verify no existing
  Field row would violate it; if any does, the migration must fail loudly rather
  than drop or rewrite rows (§61 — no security state silently rewritten).
- Decide and record whether `Event.siteId` and `Incident.siteId` take the same
  constraint. They currently do not, and several Milestone-1 fixtures create
  events against site ids with no `Site` row, so this is a data-model ruling,
  not a mechanical change. **Do not** widen the constraint to those domains
  inside WP-17A without that ruling.
- Tests: a Field write naming a nonexistent site is refused; a Field write
  naming another tenant's real site is refused identically; the existing
  lifecycle tests still pass.

## Constraints

- Additive migration only. No destructive backfill.
- Do not couple the Field module to the identity module's services; a scoped
  repository query is sufficient and keeps the module boundary.
- Do not change the WP-15 Field contracts. `site_id` remains a scoped id in the
  contract; this is a server-side integrity rule.
- Keep the subject-token validation from WP-17. Existence and token safety are
  independent checks and both stay.

## Acceptance Criteria

1. A Field assignment or state write naming a site id with no `Site` row is
   refused before persistence.
2. A Field write naming a real site belonging to another organisation is refused
   with the same response as a nonexistent site.
3. A database-level relation backs the check wherever the model allows it, added
   by an additive migration that fails rather than mutates on pre-existing
   violations.
4. The `Event`/`Incident` site-id ruling is written down, either as an extension
   of this constraint or as an explicit, reasoned exemption.
5. `pnpm -r typecheck`, `pnpm -r lint`, `pnpm -r test`, and the Proof A
   regression pass.

## Out of Scope

- Zone-level referential integrity.
- Backfilling or repairing historical rows in other domains.
- Any change to realtime delivery, which WP-17 already settled.

---

# Decision Record (locked)

Written down because each of these is a boundary a later reader could
reasonably misinterpret in the permissive direction.

## 1. Which tables carry a database relation, and why the reference is composite

```text
Site
 ├── composite FK, ON DELETE RESTRICT  <-- FieldAssignment
 └── composite FK, ON DELETE RESTRICT  <-- FieldOperativeCurrentState

no Site FK
 ├── FieldOperativeStateHistory
 ├── FieldStateUpdateIdempotency
 ├── FieldAuditLog
 └── FieldOutbox
```

`FieldAssignment` and `FieldOperativeCurrentState` are **live domain state** —
they assert something true right now, so the site they name must exist and must
belong to the same organisation.

The reference is `(site_id, organisation_id) -> sites(id, organisation_id)`, not
`site_id -> sites(id)`. A plain reference to `Site.id` would still permit:

```text
FieldAssignment: organisation_id = org-A, site_id = site-B
Site:            site-B belongs to org-B     <-- structurally legal, wrong
```

The composite reference makes the database reject that pairing, so §62.1's
tenant boundary is defended below the service layer and not only by it. `Site.id`
remains the primary key; `@@unique([id, organisationId])` exists solely to make
the pair referenceable.

## 2. Why the historical tables deliberately have no relation

`Cascade` is unacceptable: a site's lifecycle could then erase security history,
which §61 forbids outright. `Restrict` on every historical table has the
opposite failure: once a site produced a single audit, outbox, history, or
idempotency row, it could never be removed without first inventing an archive
policy — which would make WP-17A silently decide Site lifecycle architecture it
has no mandate over.

Instead their `site_id` stays what it has always been: **the site identifier as
recorded at the time of the event**. Integrity comes from the write path:

```text
prove Site exists
  -> prove Site.organisation_id == principal.organisation_id
    -> write live record, history, audit, and outbox in one transaction
```

Every historical row therefore carries a scope that was validated at the moment
it was written, and afterwards stands on its own as a record of what Sentinel
knew.

## 3. Standing rule for any future Site lifecycle work

> **WP-17A does not establish hard-delete semantics for operational Sites.** A
> future Site lifecycle feature must define RETIRED / tombstoned / archive
> behaviour before allowing deletion of a Site referenced by retained security
> history. Historical Field records must never be cascaded, rewritten, or
> pruned to make a deletion possible.

The absence of a foreign key on the historical tables is **not** permission to
erase them. It is the opposite: those rows are retained precisely because they
must outlive the operational lifecycle of the thing they describe.

## 4. Ruling on `Event.site_id` and `Incident.site_id`

```text
FIELD site_id
  authoritative operational Site reference
  -> existence required
  -> organisation ownership required

EVENT / INCIDENT site_id
  UNCHANGED by WP-17A
  -> existing Milestone-1 semantics retained
  -> strict referential integrity deferred pending an explicit
     event/incident data-model ruling
```

Milestone-1 scenarios and fixtures ingest events against site ids that have no
`Site` row, and Proof A depends on that. Making those columns strict references
would change a proven domain assumption, and the only way to make such a
migration pass would be to edit the fixtures — which would conceal a contract
decision inside test maintenance. That is explicitly forbidden here: **do not
"fix" the fixtures.** If Event/Incident site ids should become strict
references, that is its own directive with its own migration and its own
adversarial review.

## 5. Migration safety

The migration runs a preflight for rows whose `(site_id, organisation_id)` pair
has no matching site, for both constrained tables, and `RAISE EXCEPTION`s if any
exist. It does not delete, rewrite, backfill, or invent a Site to make itself
pass. A violation is an operator decision.

Preflight result at implementation time: **0 violations** in both tables.
