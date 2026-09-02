-- WP-25 Authenticated Device Gateway (D25-03A, D25-10, D25-13, D25-14).
--
-- ONE migration, chain 21 -> 22 (D25-14). The frozen WP-24 migration and every
-- migration before it are UNTOUCHED. It adds four tables and nothing else:
--   * `device_context_establishment_challenges` — the D25-03A pre-context
--     ceremony. One-shot and short-lived, and NOT a secret: every column in it
--     could be stolen wholesale and confer zero device authority without both
--     the registered private key and the independent human session.
--   * `authenticated_device_contexts` — an issued AuthenticatedDeviceContext
--     as server state. A SCOPE STATEMENT, never a credential (D25-01). There
--     is deliberately NO `device_trust` column: the frozen context carries
--     trust as HISTORICAL ISSUANCE STATE, every operation uses current Shield
--     standing, and a stale authority-shaped column beside a live context row
--     would invite exactly one mistake.
--   * `authenticated_device_context_sites` — the site binding as a CHILD
--     TABLE with a composite foreign key, not a string array, so the binding
--     is referentially real rather than a list of unvalidated strings.
--   * `device_gateway_operation_events` — the append-only gateway audit. A
--     HISTORICAL ARTEFACT with no lifecycle foreign key at all, per the WP-17A
--     doctrine shield.prisma applies to `device_security_events`.
--
-- Every foreign key here is COMPOSITE over (id, organisation_id) — against
-- `users_id_organisation_key`, `devices_id_organisation_key` and
-- `sites_id_organisation_key` — and every one is ON DELETE RESTRICT. Nothing
-- here cascades.
--
-- NO GATEWAY REPLAY TABLE IS ADDED, DELIBERATELY. WP-25 reuses Shield's
-- `device_nonce_consumptions` with a new `ceremony` value. A second replay
-- subsystem beside it would be two implementations of one security decision.
--
-- No existing migration is edited and there is no destructive or reset
-- statement anywhere below: every statement is CREATE TABLE, CREATE INDEX or
-- ADD CONSTRAINT.
--
-- NOTE FOR REVIEW: `prisma migrate diff` also emitted 8 `ALTER COLUMN ... DROP
-- DEFAULT` statements (field_*, incident_field_message_recipients) and 25
-- `RENAME CONSTRAINT` statements (field_*, incident_*, patrol_*, whisper_*).
-- They were REMOVED from this file for the same reason the WP-24 migration
-- header records: they are PRE-EXISTING drift between the 21-migration chain
-- and the datamodel as it already stands at HEAD — the same statements are
-- produced with WP-25's schema file absent entirely. D25-08 carries that drift
-- into WP-25 as an explicit CONSTRAINT: it belongs to a dedicated
-- migration-hygiene work package with its own reproduction, compatibility
-- ruling and migration proof, and WP-25 does not repair it and does not
-- rewrite historical migrations.

-- CreateTable
CREATE TABLE "device_context_establishment_challenges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "proposed_context_id" UUID NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "site_id" TEXT NOT NULL,
    "key_id" TEXT NOT NULL,
    "key_version" INTEGER NOT NULL,
    "nonce" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_context_establishment_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "authenticated_device_contexts" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "key_id" TEXT NOT NULL,
    "key_version" INTEGER NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "closed_at" TIMESTAMPTZ(3),
    "close_reason" TEXT,
    "establishment_id" UUID NOT NULL,
    "issuance_trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "authenticated_device_contexts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "authenticated_device_context_sites" (
    "id" UUID NOT NULL,
    "context_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "authenticated_device_context_sites_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_gateway_operation_events" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "context_id" UUID,
    "device_id" UUID,
    "actor_user_id" TEXT,
    "operation_kind" TEXT,
    "event_type" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "refusal_reason" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_gateway_operation_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "device_context_establishment_proposed_context_key" ON "device_context_establishment_challenges"("organisation_id", "proposed_context_id");

-- CreateIndex
CREATE UNIQUE INDEX "device_context_establishment_id_organisation_key" ON "device_context_establishment_challenges"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "authenticated_device_context_establishment_key" ON "authenticated_device_contexts"("organisation_id", "establishment_id");

-- CreateIndex
CREATE UNIQUE INDEX "authenticated_device_context_id_organisation_key" ON "authenticated_device_contexts"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "authenticated_device_context_site_key" ON "authenticated_device_context_sites"("context_id", "site_id");

-- CreateIndex
CREATE INDEX "device_gateway_operation_events_organisation_id_event_type__idx" ON "device_gateway_operation_events"("organisation_id", "event_type", "occurred_at");

-- CreateIndex
CREATE INDEX "device_gateway_operation_events_organisation_id_device_id_o_idx" ON "device_gateway_operation_events"("organisation_id", "device_id", "occurred_at");

-- AddForeignKey
ALTER TABLE "device_context_establishment_challenges" ADD CONSTRAINT "device_context_establishment_challenges_actor_user_id_orga_fkey" FOREIGN KEY ("actor_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_context_establishment_challenges" ADD CONSTRAINT "device_context_establishment_challenges_device_id_organisa_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_context_establishment_challenges" ADD CONSTRAINT "device_context_establishment_challenges_site_id_organisati_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_contexts" ADD CONSTRAINT "authenticated_device_contexts_actor_user_id_organisation_i_fkey" FOREIGN KEY ("actor_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_contexts" ADD CONSTRAINT "authenticated_device_contexts_device_id_organisation_id_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_contexts" ADD CONSTRAINT "authenticated_device_contexts_establishment_id_organisatio_fkey" FOREIGN KEY ("establishment_id", "organisation_id") REFERENCES "device_context_establishment_challenges"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_context_sites" ADD CONSTRAINT "authenticated_device_context_sites_context_id_organisation_fkey" FOREIGN KEY ("context_id", "organisation_id") REFERENCES "authenticated_device_contexts"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_context_sites" ADD CONSTRAINT "authenticated_device_context_sites_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- ===========================================================================
-- C17-05 — A CONTEXT IS BOUND TO THE EXACT SHIELD KEY, BY THE DATABASE.
--
-- `key_id` and `key_version` on the two tables above were plain scalars. Both
-- objects could therefore exist independently and still disagree: a writer that
-- bypassed the service layer could persist `device_id = <device A>` beside
-- `key_id = <device B's key>`, or a key version device A has never held, and
-- every one of Shield's existing constraints would be satisfied.
--
-- Shield has UNIQUE (organisation_id, device_id, key_version) and UNIQUE
-- (organisation_id, key_id). Neither ties the FULL tuple, so neither can be the
-- target of a foreign key that says "this key belongs to THIS device at THIS
-- version". The candidate key below is that target. It is redundant as an
-- index and load-bearing as a CONSTRAINT: it is what makes the two foreign keys
-- after it expressible.
--
-- THIS IS A FORWARD CONSTRAINT, NOT A REWRITE OF WP-24 HISTORY. It ADDs to
-- `device_keys`; it edits no historical migration, changes no existing column
-- and drops nothing. A rotation does not delete the superseded key row (D24-10
-- moves its status to ROTATED), so contexts pinned to a superseded version
-- continue to satisfy it — which is exactly the behaviour WP-25 relies on when
-- it refuses such a context with CONTEXT_KEY_MISMATCH rather than with a
-- dangling reference.
-- ===========================================================================

-- AddCandidateKey
ALTER TABLE "device_keys" ADD CONSTRAINT "device_key_identity_tuple_key" UNIQUE ("organisation_id", "device_id", "key_id", "key_version");

-- AddForeignKey
ALTER TABLE "device_context_establishment_challenges" ADD CONSTRAINT "device_context_establishment_challenges_organisation_id_de_fkey" FOREIGN KEY ("organisation_id", "device_id", "key_id", "key_version") REFERENCES "device_keys"("organisation_id", "device_id", "key_id", "key_version") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticated_device_contexts" ADD CONSTRAINT "authenticated_device_contexts_organisation_id_device_id_ke_fkey" FOREIGN KEY ("organisation_id", "device_id", "key_id", "key_version") REFERENCES "device_keys"("organisation_id", "device_id", "key_id", "key_version") ON DELETE RESTRICT ON UPDATE CASCADE;
