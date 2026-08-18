-- WP-19A (audit batch, correction 1): complete the verification evidence tuple.
--
-- The initial WP-19 migration bound a run checkpoint to its run's full
-- identity, but bound a verification to the run checkpoint only on
-- (id, patrol_run_id, organisation_id) while the verification row ALSO stores
-- site_id, patrol_route_id and patrol_checkpoint_id — and no route_version at
-- all. A service-bypassing writer could therefore attach a verification to the
-- correct run checkpoint while the immutable evidence row claimed the wrong
-- site, route or definition checkpoint. This migration adds route_version to
-- the evidence record and rebinds it through the run checkpoint's COMPLETE
-- authoritative identity.
--
-- Additive follow-up by design: the applied WP-19 migration is never edited
-- (checksum integrity). One commentary correction from that migration is also
-- recorded here rather than by rewriting history: its preamble said every
-- patrol relation is ON DELETE RESTRICT, but the replay guard
-- patrol_run_action_idempotency -> patrol_runs is deliberately ON DELETE
-- CASCADE, matching the WP-16/WP-18 replay-guard precedent — an idempotency
-- row is not history; it only dedupes requests against a live run. Every
-- EVIDENCE relation remains RESTRICT.

-- ---------------------------------------------------------------------------
-- Preflight. Fail loudly rather than repair silently (WP-17A precedent): any
-- existing verification whose stored scope disagrees with its run checkpoint
-- is evidence of exactly the corruption this migration exists to prevent, and
-- must be investigated, not rewritten.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  mismatched bigint;
BEGIN
  SELECT count(*) INTO mismatched
  FROM patrol_checkpoint_verifications v
  JOIN patrol_run_checkpoints rc ON rc.id = v.patrol_run_checkpoint_id
  WHERE v.site_id <> rc.site_id
     OR v.patrol_route_id <> rc.patrol_route_id
     OR v.patrol_checkpoint_id <> rc.patrol_checkpoint_id
     OR v.patrol_run_id <> rc.patrol_run_id
     OR v.organisation_id <> rc.organisation_id;

  IF mismatched > 0 THEN
    RAISE EXCEPTION
      'WP-19A preflight failed: % verification row(s) disagree with their run checkpoint about site/route/checkpoint scope. Investigate deliberately; do NOT auto-repair.',
      mismatched;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- route_version on the evidence record, backfilled from the run checkpoint it
-- verifies (the preflight above proved the join is trustworthy).
-- ---------------------------------------------------------------------------
ALTER TABLE "patrol_checkpoint_verifications" ADD COLUMN "route_version" INTEGER;

UPDATE "patrol_checkpoint_verifications" v
SET "route_version" = rc."route_version"
FROM "patrol_run_checkpoints" rc
WHERE rc."id" = v."patrol_run_checkpoint_id";

DO $$
DECLARE
  unfilled bigint;
BEGIN
  SELECT count(*) INTO unfilled FROM "patrol_checkpoint_verifications" WHERE "route_version" IS NULL;
  IF unfilled > 0 THEN
    RAISE EXCEPTION
      'WP-19A backfill failed: % verification row(s) have no resolvable route_version. Investigate deliberately.',
      unfilled;
  END IF;
END
$$;

ALTER TABLE "patrol_checkpoint_verifications" ALTER COLUMN "route_version" SET NOT NULL;

-- ---------------------------------------------------------------------------
-- The run checkpoint's complete authoritative identity, as one candidate key.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX "patrol_run_checkpoint_identity_key"
  ON "patrol_run_checkpoints"
  ("id", "patrol_run_id", "organisation_id", "site_id", "patrol_route_id", "route_version", "patrol_checkpoint_id");

-- Rebind the evidence record through the full identity, replacing the narrow
-- three-column binding and its now-unreferenced candidate key.
ALTER TABLE "patrol_checkpoint_verifications"
  DROP CONSTRAINT "patrol_checkpoint_verifications_run_checkpoint_fkey";
ALTER TABLE "patrol_checkpoint_verifications"
  ADD CONSTRAINT "patrol_checkpoint_verifications_run_checkpoint_fkey"
  FOREIGN KEY ("patrol_run_checkpoint_id", "patrol_run_id", "organisation_id", "site_id", "patrol_route_id", "route_version", "patrol_checkpoint_id")
  REFERENCES "patrol_run_checkpoints" ("id", "patrol_run_id", "organisation_id", "site_id", "patrol_route_id", "route_version", "patrol_checkpoint_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

DROP INDEX "patrol_run_checkpoint_binding_key";
