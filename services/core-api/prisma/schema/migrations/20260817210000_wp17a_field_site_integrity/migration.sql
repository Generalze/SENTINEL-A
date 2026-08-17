-- WP-17A: Field site referential integrity (Wave-7 finding C7-07).
--
-- Additive only. Adds a candidate key on sites(id, organisation_id) and two
-- composite foreign keys from the Field LIVE-STATE tables, so the database
-- rejects a Field row whose site does not exist OR exists under a different
-- organisation.
--
-- Historical/reliability tables (field_operative_state_history,
-- field_state_update_idempotency, field_audit_log, field_outbox) deliberately
-- get NO foreign key: their site_id is the identifier as recorded at the time
-- of the event. See prisma/schema/field.prisma and
-- docs/execution/directives/WP-17A-field-site-integrity.md.

-- ---------------------------------------------------------------------------
-- Preflight. If any existing row already violates the constraint, STOP.
--
-- Per the WP-17A directive and the §61 append-only doctrine, this migration
-- must never delete, rewrite, backfill, or invent a Site to make itself pass.
-- A violation is an operator decision, not a migration side effect.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  orphan_assignments  bigint;
  orphan_states       bigint;
BEGIN
  SELECT count(*) INTO orphan_assignments
  FROM field_assignments fa
  LEFT JOIN sites s
    ON s.id = fa.site_id
   AND s.organisation_id = fa.organisation_id
  WHERE s.id IS NULL;

  SELECT count(*) INTO orphan_states
  FROM field_operative_current_states fs
  LEFT JOIN sites s
    ON s.id = fs.site_id
   AND s.organisation_id = fs.organisation_id
  WHERE s.id IS NULL;

  IF orphan_assignments > 0 OR orphan_states > 0 THEN
    RAISE EXCEPTION
      'WP-17A preflight failed: % field_assignments and % field_operative_current_states row(s) name a site that does not exist in their organisation. Resolve these rows deliberately before migrating; do NOT backfill or delete automatically.',
      orphan_assignments, orphan_states;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Candidate key the composite references point at. `id` remains the primary
-- key; this only makes (id, organisation_id) referenceable.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX "sites_id_organisation_key" ON "sites" ("id", "organisation_id");

-- ---------------------------------------------------------------------------
-- Composite foreign keys on live Field state.
--
-- ON DELETE RESTRICT: a site with live Field state cannot be deleted out from
-- under it. WP-17A does not define Site retirement semantics, so it refuses
-- the delete rather than guessing what should happen to the operational state.
-- ---------------------------------------------------------------------------
ALTER TABLE "field_assignments"
  ADD CONSTRAINT "field_assignments_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "field_operative_current_states"
  ADD CONSTRAINT "field_operative_current_states_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
