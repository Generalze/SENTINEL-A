-- WP-26 Field Mobile Foundation — the device enrollment ingress (D26-01,
-- D26-04A, D26-04B, D26-09, D26-11).
--
-- ONE migration, chain 22 -> 23 (D26-11). The frozen WP-25 migration and every
-- migration before it are UNTOUCHED. It adds two tables and nothing else:
--   * `device_attestation_challenges` — the D26-04A pre-key-generation
--     challenge. Android Key Attestation is baked in AT KEY GENERATION, so the
--     server nonce must exist BEFORE the phone generates its key; a server that
--     does not compare the value inside the certificate against its own
--     challenge can be handed an old certificate. One-shot, short-lived
--     (DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS = 120_000, exclusive boundary,
--     clamped so it can never outlive its bootstrap grant), and NOT a secret:
--     every column in it could be stolen wholesale and confer zero device
--     authority without the one-shot grant secret, the intended user's
--     independent session, the StrongBox private key and an independent
--     commander's approval of the exact request fingerprint.
--   * `android_key_attestation_artifacts` — the D26-04B restricted provider
--     record. A HISTORICAL ARTEFACT with no lifecycle foreign key at all, per
--     the WP-17A doctrine `shield.prisma` applies to `device_security_events`
--     and `device-gateway.prisma` applies to `device_gateway_operation_events`.
--     `certificate_chain_der` is the ONE place in Sentinel that holds a raw
--     attestation chain: it never enters an audit payload, a request
--     fingerprint, a general log or a client-readable response. Shield receives
--     only the opaque server-generated `id` and the verdict.
--
-- Every foreign key on the challenge table is COMPOSITE over
-- (id, organisation_id) — against `sites_id_organisation_key`,
-- `users_id_organisation_key` and `bootstrap_grant_id_organisation_key` — and
-- every one is ON DELETE RESTRICT. Nothing here cascades. The artifact table
-- has NO foreign key by design.
--
-- No existing migration is edited and there is no destructive or reset
-- statement anywhere below: every statement is CREATE TABLE, CREATE INDEX or
-- ADD CONSTRAINT.
--
-- NOTE FOR REVIEW: `prisma migrate diff` also emitted 8 `ALTER COLUMN ... DROP
-- DEFAULT` statements (field_*, incident_field_message_recipients) and 25
-- `RENAME CONSTRAINT` statements (field_*, incident_*, patrol_*, whisper_*).
-- They were REMOVED from this file for the same reason the WP-24 and WP-25
-- migration headers record: they are PRE-EXISTING drift between the
-- 22-migration chain and the datamodel as it already stands at HEAD — the same
-- statements are produced with WP-26's schema file absent entirely. D26-07
-- carries that drift into WP-26 as an explicit CONSTRAINT ("NO rewriting
-- historical migrations — standing debt, its own work package"): it belongs to
-- a dedicated migration-hygiene work package with its own reproduction,
-- compatibility ruling and migration proof, and WP-26 does not repair it and
-- does not rewrite historical migrations.

-- CreateTable
CREATE TABLE "device_attestation_challenges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "intended_user_id" TEXT NOT NULL,
    "bootstrap_grant_id" UUID NOT NULL,
    "challenge_value" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

CONSTRAINT "device_attestation_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "android_key_attestation_artifacts" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "bootstrap_grant_id" UUID NOT NULL,
    "attestation_challenge_id" UUID NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "certificate_chain_hash" TEXT NOT NULL,
    "verifier_version" TEXT NOT NULL,
    "trust_anchor_set_version" TEXT NOT NULL,
    "revocation_snapshot_version" TEXT NOT NULL,
    "attestation_version" INTEGER,
    "attestation_security_level" INTEGER,
    "keymaster_security_level" INTEGER,
    "key_purposes" INTEGER[],
    "key_algorithm" INTEGER,
    "key_size" INTEGER,
    "key_ec_curve" INTEGER,
    "key_origin" INTEGER,
    "no_auth_required" BOOLEAN,
    "verified_boot_state" INTEGER,
    "device_locked" BOOLEAN,
    "attestation_package_name" TEXT,
    "attestation_signing_digest" TEXT,
    "outcome" TEXT NOT NULL,
    "outcome_reason" TEXT NOT NULL,
    "evaluated_at" TIMESTAMPTZ(3) NOT NULL,
    "certificate_chain_der" TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

CONSTRAINT "android_key_attestation_artifacts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "device_attestation_challenges_organisation_id_bootstrap_gra_idx" ON "device_attestation_challenges"("organisation_id", "bootstrap_grant_id");

-- CreateIndex
CREATE UNIQUE INDEX "device_attestation_challenge_value_key" ON "device_attestation_challenges"("organisation_id", "challenge_value");

-- CreateIndex
CREATE INDEX "android_key_attestation_artifacts_organisation_id_public_ke_idx" ON "android_key_attestation_artifacts"("organisation_id", "public_key_thumbprint");

-- CreateIndex
CREATE INDEX "android_key_attestation_artifacts_organisation_id_attestati_idx" ON "android_key_attestation_artifacts"("organisation_id", "attestation_challenge_id");

-- AddForeignKey
ALTER TABLE "device_attestation_challenges" ADD CONSTRAINT "device_attestation_challenges_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_attestation_challenges" ADD CONSTRAINT "device_attestation_challenges_intended_user_id_organisatio_fkey" FOREIGN KEY ("intended_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_attestation_challenges" ADD CONSTRAINT "device_attestation_challenges_bootstrap_grant_id_organisat_fkey" FOREIGN KEY ("bootstrap_grant_id", "organisation_id") REFERENCES "device_enrollment_bootstrap_grants"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;
