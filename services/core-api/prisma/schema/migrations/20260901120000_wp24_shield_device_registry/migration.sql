-- WP-24 Shield device registry (D24-04, D24-04a, D24-06, D24-10A, D24-11, D24-12).
--
-- ONE migration, chain 20 -> 21 (D24-14). It adds:
--   * the users_id_organisation_key candidate key on `users` (D24-04a) — an
--     index only: no column is added, no existing constraint is altered.
--   * fifteen new device-security tables, all composite-tenant-referencing and
--     all ON DELETE RESTRICT. Nothing here cascades.
--
-- No existing migration is edited and there is no destructive reset
-- instruction anywhere below: every statement is CREATE or ADD.
--
-- NOTE FOR REVIEW: `prisma migrate diff` also emitted 8 `ALTER COLUMN ... DROP
-- DEFAULT` statements (field_* and incident_field_message_recipients) and 24
-- `RENAME CONSTRAINT` statements (field_*, incident_*, patrol_*, whisper_*).
-- They were REMOVED from this file because they are PRE-EXISTING drift between
-- the 20-migration chain and the datamodel as it already stands at HEAD — the
-- same statements are produced with WP-24's schema files absent entirely. They
-- are not WP-24 changes and this work package has no mandate to make them.

-- CreateTable
CREATE TABLE "devices" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "custody" TEXT NOT NULL,
    "enrolled_by_user_id" TEXT NOT NULL,
    "intended_user_id" TEXT NOT NULL,
    "sequence_namespace_id" TEXT NOT NULL,
    "trust" TEXT NOT NULL,
    "revocation_disposition" TEXT,
    "revoked_at" TIMESTAMPTZ(3),
    "current_key_id" TEXT,
    "current_key_version" INTEGER,
    "enrollment_request_id" UUID NOT NULL,
    "enrolled_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_site_scopes" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "site_id" TEXT NOT NULL,
    "custody" TEXT NOT NULL,
    "assigned_user_id" TEXT,
    "custody_regime_id" TEXT,
    "associated_at" TIMESTAMPTZ(3) NOT NULL,
    "released_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_site_scopes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_keys" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "key_id" TEXT NOT NULL,
    "key_version" INTEGER NOT NULL,
    "public_key" TEXT NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "key_storage" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "registered_at" TIMESTAMPTZ(3) NOT NULL,
    "rotated_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "revocation_disposition" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_enrollment_bootstrap_grants" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "intended_user_id" TEXT NOT NULL,
    "issued_by_user_id" TEXT NOT NULL,
    "token_digest" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_enrollment_bootstrap_grants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_enrollment_requests" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "intended_user_id" TEXT NOT NULL,
    "bootstrap_grant_id" UUID NOT NULL,
    "custody" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "key_storage" TEXT NOT NULL,
    "claimed_signature_profile" TEXT NOT NULL,
    "server_selected_signature_profile" TEXT NOT NULL,
    "request_fingerprint" TEXT NOT NULL,
    "attestation_outcome" TEXT NOT NULL,
    "attestation_evaluated_at" TIMESTAMPTZ(3) NOT NULL,
    "attestation_reference" TEXT,
    "requested_at" TIMESTAMPTZ(3) NOT NULL,
    "state" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_enrollment_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_enrollment_approvals" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "enrollment_request_id" UUID NOT NULL,
    "approved_by_user_id" TEXT NOT NULL,
    "approved_request_fingerprint" TEXT NOT NULL,
    "approved_site_id" TEXT NOT NULL,
    "approved_intended_user_id" TEXT NOT NULL,
    "approved_custody" TEXT NOT NULL,
    "approved_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_enrollment_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_possession_challenges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "enrollment_request_id" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_possession_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_possession_verifications" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "challenge_id" UUID NOT NULL,
    "enrollment_request_id" UUID NOT NULL,
    "enrollment_request_fingerprint" TEXT NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "possession_statement_fingerprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL,
    "verified_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_possession_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_key_rotation_requests" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "current_key_id" TEXT NOT NULL,
    "current_key_version" INTEGER NOT NULL,
    "proposed_key_id" TEXT NOT NULL,
    "proposed_key_version" INTEGER NOT NULL,
    "new_public_key" TEXT NOT NULL,
    "new_public_key_thumbprint" TEXT NOT NULL,
    "new_key_storage" TEXT NOT NULL,
    "server_resolved_signature_profile" TEXT NOT NULL,
    "request_fingerprint" TEXT NOT NULL,
    "requested_at" TIMESTAMPTZ(3) NOT NULL,
    "state" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_key_rotation_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_key_rotation_challenges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "rotation_request_id" UUID NOT NULL,
    "rotation_request_fingerprint" TEXT NOT NULL,
    "current_key_id" TEXT NOT NULL,
    "current_key_version" INTEGER NOT NULL,
    "proposed_key_id" TEXT NOT NULL,
    "proposed_key_version" INTEGER NOT NULL,
    "new_public_key_thumbprint" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_key_rotation_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_key_rotation_verifications" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "rotation_request_id" UUID NOT NULL,
    "rotation_request_fingerprint" TEXT NOT NULL,
    "rotation_challenge_id" UUID NOT NULL,
    "current_key_id" TEXT NOT NULL,
    "current_key_version" INTEGER NOT NULL,
    "proposed_key_id" TEXT NOT NULL,
    "proposed_key_version" INTEGER NOT NULL,
    "new_public_key_thumbprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "canonical_statement_fingerprint" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL,
    "verified_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_key_rotation_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_nonce_consumptions" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "ceremony" TEXT NOT NULL,
    "replay_identity_digest" TEXT NOT NULL,
    "replay_key" TEXT NOT NULL,
    "statement_fingerprint" TEXT NOT NULL,
    "stored_outcome_ref" TEXT,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_nonce_consumptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_attestation_observations" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID,
    "enrollment_request_id" UUID,
    "outcome" TEXT NOT NULL,
    "attestation_reference" TEXT,
    "evaluated_at" TIMESTAMPTZ(3) NOT NULL,
    "observed_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_attestation_observations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_trust_transitions" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "previous_trust" TEXT NOT NULL,
    "new_trust" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "evidence_refs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "authorised_by_user_id" TEXT,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_trust_transitions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_security_events" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID,
    "event_type" TEXT NOT NULL,
    "actor_user_id" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_security_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "devices_organisation_id_trust_idx" ON "devices"("organisation_id", "trust");

-- CreateIndex
CREATE UNIQUE INDEX "devices_id_organisation_key" ON "devices"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "devices_enrollment_request_key" ON "devices"("organisation_id", "enrollment_request_id");

-- CreateIndex
CREATE INDEX "device_site_scopes_organisation_id_site_id_idx" ON "device_site_scopes"("organisation_id", "site_id");

-- CreateIndex
CREATE UNIQUE INDEX "device_site_scope_key" ON "device_site_scopes"("organisation_id", "device_id", "site_id");

-- CreateIndex
CREATE INDEX "device_keys_organisation_id_device_id_status_idx" ON "device_keys"("organisation_id", "device_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "device_key_version_key" ON "device_keys"("organisation_id", "device_id", "key_version");

-- CreateIndex
CREATE UNIQUE INDEX "device_key_id_key" ON "device_keys"("organisation_id", "key_id");

-- CreateIndex
CREATE INDEX "device_enrollment_bootstrap_grants_organisation_id_intended_idx" ON "device_enrollment_bootstrap_grants"("organisation_id", "intended_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "bootstrap_grant_token_digest_key" ON "device_enrollment_bootstrap_grants"("organisation_id", "token_digest");

-- CreateIndex
CREATE UNIQUE INDEX "bootstrap_grant_id_organisation_key" ON "device_enrollment_bootstrap_grants"("id", "organisation_id");

-- CreateIndex
CREATE INDEX "device_enrollment_requests_organisation_id_state_idx" ON "device_enrollment_requests"("organisation_id", "state");

-- CreateIndex
CREATE UNIQUE INDEX "enrollment_request_id_organisation_key" ON "device_enrollment_requests"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "enrollment_approval_request_key" ON "device_enrollment_approvals"("organisation_id", "enrollment_request_id");

-- CreateIndex
CREATE INDEX "device_possession_challenges_organisation_id_enrollment_req_idx" ON "device_possession_challenges"("organisation_id", "enrollment_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "possession_verification_challenge_key" ON "device_possession_verifications"("organisation_id", "challenge_id");

-- CreateIndex
CREATE INDEX "device_key_rotation_requests_organisation_id_device_id_stat_idx" ON "device_key_rotation_requests"("organisation_id", "device_id", "state");

-- CreateIndex
CREATE UNIQUE INDEX "rotation_request_id_organisation_key" ON "device_key_rotation_requests"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "rotation_request_proposed_version_key" ON "device_key_rotation_requests"("organisation_id", "device_id", "proposed_key_version");

-- CreateIndex
CREATE INDEX "device_key_rotation_challenges_organisation_id_rotation_req_idx" ON "device_key_rotation_challenges"("organisation_id", "rotation_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "rotation_verification_challenge_key" ON "device_key_rotation_verifications"("organisation_id", "rotation_challenge_id");

-- CreateIndex
CREATE INDEX "device_nonce_consumptions_organisation_id_ceremony_first_se_idx" ON "device_nonce_consumptions"("organisation_id", "ceremony", "first_seen_at");

-- CreateIndex
CREATE UNIQUE INDEX "device_nonce_consumption_identity_key" ON "device_nonce_consumptions"("organisation_id", "replay_identity_digest");

-- CreateIndex
CREATE INDEX "device_attestation_observations_organisation_id_device_id_e_idx" ON "device_attestation_observations"("organisation_id", "device_id", "evaluated_at");

-- CreateIndex
CREATE INDEX "device_attestation_observations_organisation_id_enrollment__idx" ON "device_attestation_observations"("organisation_id", "enrollment_request_id");

-- CreateIndex
CREATE INDEX "device_trust_transitions_organisation_id_device_id_occurred_idx" ON "device_trust_transitions"("organisation_id", "device_id", "occurred_at");

-- CreateIndex
CREATE INDEX "device_security_events_organisation_id_event_type_occurred__idx" ON "device_security_events"("organisation_id", "event_type", "occurred_at");

-- CreateIndex
CREATE INDEX "device_security_events_organisation_id_device_id_occurred_a_idx" ON "device_security_events"("organisation_id", "device_id", "occurred_at");

-- CreateIndex
CREATE UNIQUE INDEX "users_id_organisation_key" ON "users"("id", "organisation_id");

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_organisation_id_fkey" FOREIGN KEY ("organisation_id") REFERENCES "organisations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_enrolled_by_user_id_organisation_id_fkey" FOREIGN KEY ("enrolled_by_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_intended_user_id_organisation_id_fkey" FOREIGN KEY ("intended_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_enrollment_request_id_organisation_id_fkey" FOREIGN KEY ("enrollment_request_id", "organisation_id") REFERENCES "device_enrollment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_site_scopes" ADD CONSTRAINT "device_site_scopes_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_site_scopes" ADD CONSTRAINT "device_site_scopes_device_id_organisation_id_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_site_scopes" ADD CONSTRAINT "device_site_scopes_assigned_user_id_organisation_id_fkey" FOREIGN KEY ("assigned_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_keys" ADD CONSTRAINT "device_keys_device_id_organisation_id_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_bootstrap_grants" ADD CONSTRAINT "device_enrollment_bootstrap_grants_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_bootstrap_grants" ADD CONSTRAINT "device_enrollment_bootstrap_grants_intended_user_id_organi_fkey" FOREIGN KEY ("intended_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_bootstrap_grants" ADD CONSTRAINT "device_enrollment_bootstrap_grants_issued_by_user_id_organ_fkey" FOREIGN KEY ("issued_by_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_requests" ADD CONSTRAINT "device_enrollment_requests_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_requests" ADD CONSTRAINT "device_enrollment_requests_intended_user_id_organisation_i_fkey" FOREIGN KEY ("intended_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_requests" ADD CONSTRAINT "device_enrollment_requests_bootstrap_grant_id_organisation_fkey" FOREIGN KEY ("bootstrap_grant_id", "organisation_id") REFERENCES "device_enrollment_bootstrap_grants"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_approvals" ADD CONSTRAINT "device_enrollment_approvals_enrollment_request_id_organisa_fkey" FOREIGN KEY ("enrollment_request_id", "organisation_id") REFERENCES "device_enrollment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_approvals" ADD CONSTRAINT "device_enrollment_approvals_approved_by_user_id_organisati_fkey" FOREIGN KEY ("approved_by_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_possession_challenges" ADD CONSTRAINT "device_possession_challenges_enrollment_request_id_organis_fkey" FOREIGN KEY ("enrollment_request_id", "organisation_id") REFERENCES "device_enrollment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_possession_verifications" ADD CONSTRAINT "device_possession_verifications_enrollment_request_id_orga_fkey" FOREIGN KEY ("enrollment_request_id", "organisation_id") REFERENCES "device_enrollment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_key_rotation_requests" ADD CONSTRAINT "device_key_rotation_requests_device_id_organisation_id_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_key_rotation_challenges" ADD CONSTRAINT "device_key_rotation_challenges_rotation_request_id_organis_fkey" FOREIGN KEY ("rotation_request_id", "organisation_id") REFERENCES "device_key_rotation_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_key_rotation_verifications" ADD CONSTRAINT "device_key_rotation_verifications_rotation_request_id_orga_fkey" FOREIGN KEY ("rotation_request_id", "organisation_id") REFERENCES "device_key_rotation_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

