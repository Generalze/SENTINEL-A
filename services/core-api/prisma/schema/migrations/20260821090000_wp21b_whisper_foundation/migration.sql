-- WP-21B: Whisper persistence + authority foundation.
--
-- Additive. Four new tables, plus a MINIMAL generalisation of the existing
-- incidents table. No existing migration is edited (checksum discipline); the
-- Site candidate key sites(id, organisation_id) added by WP-17A is referenced,
-- never modified.
--
-- WHAT THE FOUR WHISPER TABLES ARE FOR
-- ------------------------------------
--   whisper_signal_versions        LIVE configuration state. One immutable
--     row per (tenant, signal family, version). W21-02 freezes a version the
--     moment it leaves DRAFT, because from SIMULATION onward it is
--     ACCUMULATING EVIDENCE — false-positive results, anti-spoof results, a
--     field drill, an approval. Editing the configuration underneath that
--     evidence would leave the approval attesting to a signal that no longer
--     exists, which is exactly how a "tested and safe" label ends up on
--     something nobody tested. A semantic change is therefore a NEW version.
--     whisper_signal_id is the FAMILY id, stable across versions;
--     signal_version counts within it. configuration_fingerprint is the
--     SHA-256 of the six semantic fields only — name and trace_id are absent
--     because renaming a signal changes no authority.
--
--   whisper_activation_approvals   IMMUTABLE attestation (W21-13) that a
--     TESTED CONFIGURATION IS SAFE TO RECOGNISE, bound to the exact
--     configuration_fingerprint that was tested. It carries NO incident, task
--     or dispatch column — structurally, not by convention — so it can never
--     be read or replayed as an approval of an operational response. When an
--     active signal later fires, the existing SILENT path still requires its
--     own Constitution-governed approvals from distinct commanders. Exactly
--     one approval per version (W21-12 additionally requires the approver to
--     be distinct from the creator; both ids are stored so that is auditable
--     after the fact, not merely enforced in flight).
--
--   whisper_recognition_receipts   DURABLE ANTI-REPLAY (B11-12/W21-09). A
--     recognition may be RETRIED — the same canonical statement converges on
--     the same row and returns the stored outcome. It may never be REPLAYED.
--     The boundary is a REAL COMPOSITE KEY over seven columns (C11-01):
--     organisation, site, ACTOR, device, signal family, signal version, nonce.
--     Not a hash and not a delimiter-joined string: a digest would refuse the
--     duplicate but throw away the ability to query and audit the parts, and a
--     joined string would let two different tuples collide — which is one
--     tenant's nonce consuming another's replay slot. The actor is IN the
--     identity because two people may legitimately be authorised on one
--     version and may share a device between shifts.
--
--   whisper_audit_log              APPEND-ONLY record of the channel (W21-14).
--     Its payload is constrained by the frozen contract's strict schema, which
--     has no field for the discreet action definition, signature material,
--     public keys, the authorised-user roster or the context values — so an
--     audit row cannot widen into a disclosure of the very secret this
--     modality depends on.
--
-- SITE REFERENTIAL INTEGRITY — the WP-17A split, applied here
-- ------------------------------------------------------------
-- whisper_signal_versions is LIVE state, so it carries the composite
-- (site_id, organisation_id) foreign key to sites, ON DELETE RESTRICT, exactly
-- like field_assignments, field_operative_current_states, patrol_routes,
-- patrol_runs and field_offline_device_cursors. The pair must match, not just
-- the site id, so the database itself rejects a row pairing one tenant's
-- organisation with another tenant's site (section 62.1 defence in depth) —
-- which for a silent duress trigger is not a theoretical concern.
--
-- The site_id is NULLABLE because W21-03/C11-02 admit an ORGANISATION-WIDE
-- signal. NULL means "every site in this organisation", never "unknown site",
-- and Postgres MATCH SIMPLE gives precisely that reading: a NULL member leaves
-- the composite constraint unenforced rather than dangling. The runtime gate
-- still requires the firing device to be entitled to the specific site it
-- fires at, so org-wide scope widens WHERE a signal may exist, never WHO may
-- fire it.
--
-- whisper_recognition_receipts and whisper_audit_log deliberately get NO
-- foreign key, per the WP-17A historical-artefact rule (see the doctrine
-- header in prisma/schema/field.prisma and
-- docs/execution/directives/WP-17A-field-site-integrity.md) — the same rule
-- that governs field_operative_state_history, field_state_update_idempotency,
-- field_audit_log, field_outbox and field_offline_operation_receipts. Their
-- site_id is the site as recorded at the time of the event and must stay that
-- way. CASCADE would let a site's lifecycle erase the record of a silent
-- duress signal (forbidden by section 61) and, worse for a receipt, deleting a
-- consumed replay identity RE-ADMITS the nonce it retired. RESTRICT would mean
-- a site could never be removed once a single recognition had been received,
-- silently inventing a Site retirement policy this work package has no mandate
-- to decide. Integrity comes from the write-time check instead.
--
-- NOTHING HERE CASCADES. Contrast the WP-16/WP-18/WP-19 action-idempotency
-- tables, which legitimately cascade because they only dedupe requests against
-- a live parent. None of these four rows is that.
--
-- THE INCIDENT SOURCE SEAM (B11-13)
-- ---------------------------------
-- incidents.hypothesis_id and incidents.incident_candidate_id are currently
-- NOT NULL, which makes "an incident comes from Fusion" a structural
-- assumption rather than a fact about one source. A recognised Whisper
-- device-action duress signal enters the SAME already-proven silent response
-- path, and under the current shape the only way it could open an incident is
-- by FABRICATING a hypothesis id and a candidate id — inventing Fusion
-- evidence no Fusion pipeline ever produced.
--
-- The seam added below is GENERIC and is deliberately NOT a whisper_* column.
-- A whisper-specific column would make Incident know about Whisper, and the
-- next source would add a third column, and that one a fourth. source_kind +
-- source_ref state the fact once for every source there will ever be.
--
-- hypothesis_id KEEPS its unique index. Postgres treats NULLs as distinct in a
-- unique index, so Fusion's exactly-one-incident-per-hypothesis redelivery
-- boundary survives untouched while non-Fusion rows carry NULL, and
-- incidents_source_identity_key gives every source the general form of that
-- same guarantee.

-- ---------------------------------------------------------------------------
-- Live configuration state (W21-02, W21-03).
-- ---------------------------------------------------------------------------
CREATE TABLE "whisper_signal_versions" (
    "id" UUID NOT NULL,
    -- The FAMILY id: server-generated, stable across every version.
    "whisper_signal_id" TEXT NOT NULL,
    "signal_version" INTEGER NOT NULL,
    "organisation_id" TEXT NOT NULL,
    -- NULL = organisation-wide (W21-03/C11-02), never "unknown site".
    "site_id" TEXT,
    -- Deliberately NOT fingerprinted: a rename changes no authority.
    "name" TEXT NOT NULL,
    -- The nine-status section 14.5 lifecycle.
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    -- The six SEMANTIC configuration fields, and only these, are what
    -- configuration_fingerprint digests.
    "modality" TEXT NOT NULL DEFAULT 'DEVICE_ACTION',
    "device_action_id" TEXT NOT NULL,
    -- B11-07: stored SORTED. This is an allowlist SET, so order is not
    -- authority and reordering the roster is not a configuration change.
    "authorised_user_ids" TEXT[],
    "context_requirements" JSONB NOT NULL DEFAULT '{}',
    "minimum_confidence" DOUBLE PRECISION NOT NULL,
    -- W21-10: a reference into the server-owned protocol allowlist, never
    -- executable content. Nullable for DRAFT; ACTIVE requires it.
    "response_protocol_id" TEXT,
    -- SHA-256 hex of the six fields above, canonically digested.
    "configuration_fingerprint" TEXT NOT NULL,
    "created_by_user_id" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    -- Distinct columns: ROTATED and RETIRED are different outcomes, and an
    -- audit must be able to tell how long a version was actually live.
    "activated_at" TIMESTAMPTZ(3),
    "rotated_at" TIMESTAMPTZ(3),
    "retired_at" TIMESTAMPTZ(3),

    CONSTRAINT "whisper_signal_versions_pkey" PRIMARY KEY ("id")
);

-- The W21-02 freeze made durable: one row per (tenant, family, version), so a
-- second write of the same version cannot exist to be edited.
CREATE UNIQUE INDEX "whisper_signal_version_key"
  ON "whisper_signal_versions" ("organisation_id", "whisper_signal_id", "signal_version");

-- Candidate key, deliberately redundant with the primary key: it makes
-- (id, organisation_id) referenceable so a child row binds to THIS version
-- UNDER THIS TENANT rather than to an id that merely exists. Same technique as
-- sites_id_organisation_key and incidents_id_org_site_key.
CREATE UNIQUE INDEX "whisper_signal_version_id_org_key"
  ON "whisper_signal_versions" ("id", "organisation_id");

-- Resolve the active version of a family; list a family's history.
CREATE INDEX "whisper_signal_family_status_idx"
  ON "whisper_signal_versions" ("organisation_id", "whisper_signal_id", "status");

-- WP-17A live-state precedent: the pair must match, not just the site id.
-- RESTRICT — a site's lifecycle must never silently delete a configuration
-- that can raise a silent dispatch. MATCH SIMPLE leaves the constraint
-- unenforced for the org-wide (NULL site_id) case, which is the intent.
ALTER TABLE "whisper_signal_versions"
  ADD CONSTRAINT "whisper_signal_versions_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Immutable activation attestation (W21-12, W21-13).
--
-- No incident, task or dispatch column exists here BY DESIGN: this can never
-- be replayed as an approval of an operational response.
-- ---------------------------------------------------------------------------
CREATE TABLE "whisper_activation_approvals" (
    "id" UUID NOT NULL,
    "signal_version_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    -- Bound to the EXACT tested configuration: an approval must not survive a
    -- configuration it never saw.
    "configuration_fingerprint" TEXT NOT NULL,
    "approved_by_user_id" TEXT NOT NULL,
    "created_by_user_id" TEXT NOT NULL,
    "approved_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "whisper_activation_approvals_pkey" PRIMARY KEY ("id")
);

-- EXACTLY ONE activation per version, enforced below the service layer. A
-- second row would let an activation be re-attested after the fact, or let two
-- partial approvals be mistaken for the one the lifecycle requires.
CREATE UNIQUE INDEX "whisper_activation_approval_version_key"
  ON "whisper_activation_approvals" ("signal_version_id");

-- Bound through the version's (id, organisation_id) candidate key, so an
-- approval cannot be attached to another tenant's version. RESTRICT: the
-- attestation must never be separated from what it attests to.
ALTER TABLE "whisper_activation_approvals"
  ADD CONSTRAINT "whisper_activation_approvals_version_org_fkey"
  FOREIGN KEY ("signal_version_id", "organisation_id")
  REFERENCES "whisper_signal_versions" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Durable anti-replay receipts (B11-12, W21-09, C11-01).
--
-- No Site foreign key by design — see the preamble's WP-17A reasoning.
-- ---------------------------------------------------------------------------
CREATE TABLE "whisper_recognition_receipts" (
    "id" UUID NOT NULL,
    -- THE SEVEN IDENTITY COLUMNS (C11-01). A real composite key, never a hash
    -- and never a joined string.
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "whisper_signal_id" TEXT NOT NULL,
    "whisper_signal_version" INTEGER NOT NULL,
    "anti_replay_nonce" TEXT NOT NULL,
    -- NULLABLE on purpose: a refusal that never got as far as resolving a
    -- signal must STILL be recorded, because the replay boundary also has to
    -- retire the nonce of an attempt that failed. Requiring the reference here
    -- would mean the failures most worth recording were the ones that could
    -- not be written.
    "signal_version_id" UUID,
    -- SHA-256 of the canonical signed statement. Stored SEPARATELY; it never
    -- replaces the composite identity above. The fingerprint answers "is this
    -- the same request?"; the seven columns answer "has this one-shot identity
    -- already been spent?".
    "recognition_fingerprint" TEXT NOT NULL,
    -- RECEIVED | APPLYING | APPLIED | REFUSED | UNKNOWN. UNKNOWN is unresolved,
    -- not failed: it is retried into convergence, never silently finalized.
    "status" TEXT NOT NULL DEFAULT 'RECEIVED',
    -- ACCEPTED | REFUSED once finalized.
    "outcome" TEXT,
    -- A WhisperRecognitionConflictCode: safe by construction, it cannot say
    -- whether a signal exists, only that the attempt did not qualify.
    "conflict_code" TEXT,
    -- Where an ACCEPTED recognition entered the existing SILENT path. A SCALAR
    -- LINK WITH NO FOREIGN KEY: history must never be cascade-erased by an
    -- incident's lifecycle, nor may a receipt pin an incident open.
    "incident_id" UUID,
    -- Fencing generation for crash recovery (WP-20/B10-01 precedent).
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "processing_claimed_at" TIMESTAMPTZ(3),
    -- AUTHORITATIVE server receipt time. W21-08 judges freshness against this,
    -- never against the device's self-reported freshness_ms.
    "recorded_at" TIMESTAMPTZ(3) NOT NULL,
    "finalized_at" TIMESTAMPTZ(3),
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "whisper_recognition_receipts_pkey" PRIMARY KEY ("id")
);

-- THE seven-column anti-replay boundary, enforced BELOW the service layer so a
-- service-bypassing writer cannot spend one identity twice.
CREATE UNIQUE INDEX "whisper_recognition_replay_key"
  ON "whisper_recognition_receipts"
  ("organisation_id", "site_id", "actor_user_id", "device_id", "whisper_signal_id", "whisper_signal_version", "anti_replay_nonce");

-- Recovery sweep: find recognitions left in a non-finalized status.
CREATE INDEX "whisper_recognition_recovery_idx"
  ON "whisper_recognition_receipts" ("status", "updated_at");

-- When a version WAS resolved, it must belong to this same tenant. MATCH
-- SIMPLE leaves this unenforced when signal_version_id is NULL, which is the
-- intended reading for an unresolved refusal. RESTRICT, never CASCADE:
-- deleting a consumed replay identity would re-admit the nonce it retired.
ALTER TABLE "whisper_recognition_receipts"
  ADD CONSTRAINT "whisper_recognition_receipts_version_org_fkey"
  FOREIGN KEY ("signal_version_id", "organisation_id")
  REFERENCES "whisper_signal_versions" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Append-only audit (W21-14).
--
-- No Site foreign key by design — history must never be cascade-erased.
-- ---------------------------------------------------------------------------
CREATE TABLE "whisper_audit_log" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT,
    "whisper_signal_id" TEXT NOT NULL,
    -- Nullable: family-level events, and events logged before a version could
    -- be resolved, are real and must be recordable.
    "signal_version" INTEGER,
    "kind" TEXT NOT NULL,
    -- Nullable: system-owned transitions have no human actor, and refusing to
    -- log one for want of an actor id would be the wrong trade.
    "actor_user_id" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "whisper_audit_log_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "whisper_audit_family_idx"
  ON "whisper_audit_log" ("organisation_id", "whisper_signal_id", "at");

-- ---------------------------------------------------------------------------
-- The Incident source seam (B11-13), in a deliberately safe order:
-- relax, add nullable, prove the source of truth, backfill, prove the
-- backfill, tighten, then constrain.
-- ---------------------------------------------------------------------------

-- 1. Relax. A non-Fusion incident has no hypothesis and no candidate, and must
--    not be forced to invent one.
ALTER TABLE "incidents" ALTER COLUMN "hypothesis_id" DROP NOT NULL;
ALTER TABLE "incidents" ALTER COLUMN "incident_candidate_id" DROP NOT NULL;

-- 2. Add the generic seam NULLABLE first, so existing rows remain valid while
--    they are backfilled.
ALTER TABLE "incidents" ADD COLUMN "source_kind" TEXT;
ALTER TABLE "incidents" ADD COLUMN "source_ref" TEXT;

-- 3. PREFLIGHT, before the backfill. Every existing incident came from Fusion
--    and hypothesis_id was NOT NULL until step 1, so this count must be zero.
--    It is asserted anyway: if the assumption is somehow false, the backfill
--    below would quietly write a NULL source_ref and step 6 would then fail
--    with a far less informative message. Fail loudly, and never auto-repair
--    (the WP-17A/WP-19A precedent) — a surprising row here is evidence about
--    how this table was written, and that must be investigated, not patched.
DO $$
DECLARE
  sourceless bigint;
BEGIN
  SELECT count(*) INTO sourceless FROM "incidents" WHERE "hypothesis_id" IS NULL;

  IF sourceless > 0 THEN
    RAISE EXCEPTION
      'WP-21B preflight failed: % incident row(s) have a NULL hypothesis_id before any backfill, which cannot happen while the column is NOT NULL. Investigate deliberately; do NOT auto-repair.',
      sourceless;
  END IF;
END
$$;

-- 4. Backfill. Every pre-existing incident is, by construction, Fusion-sourced:
--    createFromCandidate was the only write path. Its source reference is the
--    hypothesis id the preflight just proved is present.
UPDATE "incidents"
SET "source_kind" = 'FUSION_HYPOTHESIS',
    "source_ref" = "hypothesis_id"
WHERE "source_kind" IS NULL OR "source_ref" IS NULL;

-- 5. Prove the backfill. Same rule: fail loudly rather than repair silently.
DO $$
DECLARE
  unfilled bigint;
BEGIN
  SELECT count(*) INTO unfilled
  FROM "incidents"
  WHERE "source_kind" IS NULL OR "source_ref" IS NULL;

  IF unfilled > 0 THEN
    RAISE EXCEPTION
      'WP-21B backfill failed: % incident row(s) still have no source_kind/source_ref. Investigate deliberately; do NOT auto-repair.',
      unfilled;
  END IF;
END
$$;

-- 6. Tighten. From here an incident must always state where it came from.
ALTER TABLE "incidents" ALTER COLUMN "source_kind" SET NOT NULL;
ALTER TABLE "incidents" ALTER COLUMN "source_ref" SET NOT NULL;

-- 7. One incident per (tenant, source) — the GENERAL form of the redelivery
--    boundary that hypothesis_id's unique index gave Fusion alone, now
--    available to every source without any of them inventing a hypothesis to
--    get it. incidents_hypothesis_id_key is untouched and still holds for
--    Fusion rows; NULLs are distinct in Postgres, so it costs Whisper nothing.
CREATE UNIQUE INDEX "incidents_source_identity_key"
  ON "incidents" ("organisation_id", "source_kind", "source_ref");
