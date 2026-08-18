-- WP-19: Patrol Foundation.
--
-- Additive only: seven new tables, no change to any existing table, column or
-- constraint. Incident's WP-18 candidate key (id, organisation_id, site_id)
-- and Site's (id, organisation_id) key are referenced, not modified.
--
-- Integrity model (C9-07): the route/run/checkpoint tuple is enforced below
-- the service layer. A patrol_run_checkpoints row binds its run's identity
-- AND tenant AND site AND route AND pinned version in one foreign key, and its
-- definition checkpoint's identity AND route AND version in another, so a row
-- that disagrees with its run about any of those cannot exist. All patrol
-- relations are ON DELETE RESTRICT: patrol truth is history (§61) and a parent
-- lifecycle must never cascade-erase it.

-- ---------------------------------------------------------------------------
-- Routes
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_routes" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "current_version" INTEGER NOT NULL,
    "created_by_user_id" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "patrol_routes_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_route_id_org_site_key"
  ON "patrol_routes" ("id", "organisation_id", "site_id");
CREATE UNIQUE INDEX "patrol_route_create_idem_key"
  ON "patrol_routes" ("organisation_id", "site_id", "created_by_user_id", "idempotency_key");
CREATE INDEX "patrol_route_scope_idx"
  ON "patrol_routes" ("organisation_id", "site_id");

-- WP-17A: the pair must match, not just the site id.
ALTER TABLE "patrol_routes"
  ADD CONSTRAINT "patrol_routes_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Route versions (C9-04: one immutable published standard each)
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_route_versions" (
    "id" UUID NOT NULL,
    "patrol_route_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "published_by_user_id" TEXT NOT NULL,
    "published_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idempotency_key" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,

    CONSTRAINT "patrol_route_versions_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_route_version_key"
  ON "patrol_route_versions" ("patrol_route_id", "version");
CREATE UNIQUE INDEX "patrol_route_version_publish_idem_key"
  ON "patrol_route_versions" ("patrol_route_id", "published_by_user_id", "idempotency_key");

ALTER TABLE "patrol_route_versions"
  ADD CONSTRAINT "patrol_route_versions_route_fkey"
  FOREIGN KEY ("patrol_route_id", "organisation_id", "site_id")
  REFERENCES "patrol_routes" ("id", "organisation_id", "site_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Versioned checkpoint definitions (timing standard lives here)
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_checkpoints" (
    "id" UUID NOT NULL,
    "patrol_route_id" UUID NOT NULL,
    "route_version" INTEGER NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "sequence_number" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "zone_id" TEXT,
    "location" JSONB,
    "window_open_offset_ms" INTEGER NOT NULL,
    "late_after_offset_ms" INTEGER NOT NULL,
    "missed_after_offset_ms" INTEGER NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "patrol_checkpoints_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_checkpoint_sequence_key"
  ON "patrol_checkpoints" ("patrol_route_id", "route_version", "sequence_number");
CREATE UNIQUE INDEX "patrol_checkpoint_id_route_version_key"
  ON "patrol_checkpoints" ("id", "patrol_route_id", "route_version");

ALTER TABLE "patrol_checkpoints"
  ADD CONSTRAINT "patrol_checkpoints_version_fkey"
  FOREIGN KEY ("patrol_route_id", "route_version")
  REFERENCES "patrol_route_versions" ("patrol_route_id", "version")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "patrol_checkpoints"
  ADD CONSTRAINT "patrol_checkpoints_route_fkey"
  FOREIGN KEY ("patrol_route_id", "organisation_id", "site_id")
  REFERENCES "patrol_routes" ("id", "organisation_id", "site_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Runs (one operative executing one exact pinned version)
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_runs" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "patrol_route_id" UUID NOT NULL,
    "route_version" INTEGER NOT NULL,
    "assigned_operative_user_id" TEXT NOT NULL,
    "incident_id" UUID,
    "status" TEXT NOT NULL DEFAULT 'SCHEDULED',
    "scheduled_start_at" TIMESTAMPTZ(3) NOT NULL,
    "started_at" TIMESTAMPTZ(3),
    "ended_at" TIMESTAMPTZ(3),
    "abandon_reason" TEXT,
    "created_by_user_id" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "patrol_runs_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_run_binding_key"
  ON "patrol_runs" ("id", "organisation_id", "site_id", "patrol_route_id", "route_version");
CREATE UNIQUE INDEX "patrol_run_id_org_key"
  ON "patrol_runs" ("id", "organisation_id");
CREATE UNIQUE INDEX "patrol_run_schedule_idem_key"
  ON "patrol_runs" ("organisation_id", "site_id", "created_by_user_id", "idempotency_key");
CREATE INDEX "patrol_run_status_idx"
  ON "patrol_runs" ("organisation_id", "site_id", "status");
CREATE INDEX "patrol_run_operative_idx"
  ON "patrol_runs" ("organisation_id", "assigned_operative_user_id", "created_at");
CREATE INDEX "patrol_runs_incident_id_idx"
  ON "patrol_runs" ("incident_id");

ALTER TABLE "patrol_runs"
  ADD CONSTRAINT "patrol_runs_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "patrol_runs"
  ADD CONSTRAINT "patrol_runs_route_fkey"
  FOREIGN KEY ("patrol_route_id", "organisation_id", "site_id")
  REFERENCES "patrol_routes" ("id", "organisation_id", "site_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "patrol_runs"
  ADD CONSTRAINT "patrol_runs_route_version_fkey"
  FOREIGN KEY ("patrol_route_id", "route_version")
  REFERENCES "patrol_route_versions" ("patrol_route_id", "version")
  ON DELETE RESTRICT ON UPDATE CASCADE;
-- WP-18 tuple: THIS incident under THIS tenant and site, or nothing.
ALTER TABLE "patrol_runs"
  ADD CONSTRAINT "patrol_runs_incident_fkey"
  FOREIGN KEY ("incident_id", "organisation_id", "site_id")
  REFERENCES "incidents" ("id", "organisation_id", "site_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Materialised run checkpoints (directive section 3)
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_run_checkpoints" (
    "id" UUID NOT NULL,
    "patrol_run_id" UUID NOT NULL,
    "patrol_checkpoint_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "patrol_route_id" UUID NOT NULL,
    "route_version" INTEGER NOT NULL,
    "sequence_number" INTEGER NOT NULL,
    "window_opens_at" TIMESTAMPTZ(3) NOT NULL,
    "late_after" TIMESTAMPTZ(3) NOT NULL,
    "missed_after" TIMESTAMPTZ(3) NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'PENDING',
    "resolved_at" TIMESTAMPTZ(3),
    "verification_id" UUID,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "patrol_run_checkpoints_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_run_checkpoint_pair_key"
  ON "patrol_run_checkpoints" ("patrol_run_id", "patrol_checkpoint_id");
CREATE UNIQUE INDEX "patrol_run_checkpoint_sequence_key"
  ON "patrol_run_checkpoints" ("patrol_run_id", "sequence_number");
CREATE UNIQUE INDEX "patrol_run_checkpoint_binding_key"
  ON "patrol_run_checkpoints" ("id", "patrol_run_id", "organisation_id");
CREATE UNIQUE INDEX "patrol_run_checkpoint_verification_key"
  ON "patrol_run_checkpoints" ("verification_id");
CREATE INDEX "patrol_run_checkpoint_sweep_idx"
  ON "patrol_run_checkpoints" ("state", "missed_after");

-- C9-07: one reference binds run identity, tenant, site, route AND version.
ALTER TABLE "patrol_run_checkpoints"
  ADD CONSTRAINT "patrol_run_checkpoints_run_fkey"
  FOREIGN KEY ("patrol_run_id", "organisation_id", "site_id", "patrol_route_id", "route_version")
  REFERENCES "patrol_runs" ("id", "organisation_id", "site_id", "patrol_route_id", "route_version")
  ON DELETE RESTRICT ON UPDATE CASCADE;
-- C9-07: the definition checkpoint must belong to that exact route version.
ALTER TABLE "patrol_run_checkpoints"
  ADD CONSTRAINT "patrol_run_checkpoints_checkpoint_fkey"
  FOREIGN KEY ("patrol_checkpoint_id", "patrol_route_id", "route_version")
  REFERENCES "patrol_checkpoints" ("id", "patrol_route_id", "route_version")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Verification records (C9-01, C9-06). Append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_checkpoint_verifications" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "patrol_run_id" UUID NOT NULL,
    "patrol_run_checkpoint_id" UUID NOT NULL,
    "patrol_route_id" UUID NOT NULL,
    "patrol_checkpoint_id" UUID NOT NULL,
    "operative_user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "verification_method" TEXT NOT NULL,
    "verification_context" JSONB NOT NULL DEFAULT '{}',
    "source_at" TIMESTAMPTZ(3) NOT NULL,
    "recorded_at" TIMESTAMPTZ(3) NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "patrol_checkpoint_verifications_pkey" PRIMARY KEY ("id")
);

-- C9-06: the idempotency namespace includes the authoritative actor and run
-- scope, so another actor's key collision can never return this record.
CREATE UNIQUE INDEX "patrol_verification_idem_key"
  ON "patrol_checkpoint_verifications"
  ("organisation_id", "patrol_run_id", "patrol_run_checkpoint_id", "operative_user_id", "idempotency_key");
CREATE INDEX "patrol_verification_run_idx"
  ON "patrol_checkpoint_verifications" ("organisation_id", "patrol_run_id", "recorded_at");

ALTER TABLE "patrol_checkpoint_verifications"
  ADD CONSTRAINT "patrol_checkpoint_verifications_run_fkey"
  FOREIGN KEY ("patrol_run_id", "organisation_id")
  REFERENCES "patrol_runs" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "patrol_checkpoint_verifications"
  ADD CONSTRAINT "patrol_checkpoint_verifications_run_checkpoint_fkey"
  FOREIGN KEY ("patrol_run_checkpoint_id", "patrol_run_id", "organisation_id")
  REFERENCES "patrol_run_checkpoints" ("id", "patrol_run_id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- The resolving-verification pointer is added AFTER both tables exist because
-- the reference is circular by design: the verification proves the resolution,
-- and the run checkpoint records which verification resolved it.
ALTER TABLE "patrol_run_checkpoints"
  ADD CONSTRAINT "patrol_run_checkpoints_verification_fkey"
  FOREIGN KEY ("verification_id")
  REFERENCES "patrol_checkpoint_verifications" ("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Run lifecycle action replay guard (C9-06/C8-05: actor is part of the key)
-- ---------------------------------------------------------------------------
CREATE TABLE "patrol_run_action_idempotency" (
    "id" UUID NOT NULL,
    "patrol_run_id" UUID NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "patrol_run_action_idempotency_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "patrol_run_action_idem_key"
  ON "patrol_run_action_idempotency" ("patrol_run_id", "actor_user_id", "action", "idempotency_key");

ALTER TABLE "patrol_run_action_idempotency"
  ADD CONSTRAINT "patrol_run_action_idempotency_run_fkey"
  FOREIGN KEY ("patrol_run_id")
  REFERENCES "patrol_runs" ("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
