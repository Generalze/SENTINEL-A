# Directive WP-17A - Field Site Referential Integrity

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 7 (hardening)
**Depends:** WP-16 Field Domain, WP-17 Field Realtime
**Review chain:** Cipher adversarial review -> Lead merge gate
**Status:** Scheduled. Not started.

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
