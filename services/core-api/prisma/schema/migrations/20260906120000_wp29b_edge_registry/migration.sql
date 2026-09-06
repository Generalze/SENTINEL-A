-- WP-29B / migration 26 — THE CENTRAL EDGE IDENTITY REGISTRY AND ITS ENROLMENT
-- CEREMONY.
--
-- C15-02 stated the hole this closes in one line: AN EDGE RECEIPT NOBODY CAN
-- VERIFY IS NOT EVIDENCE. `evaluateOfflineOperationAdmissibility` has always
-- asked for a `registeredEdgeKey` — the record holding the public key an Edge
-- signature is checked against, the server-selected profile, the key's
-- lifecycle and the Edge's own trust — and Sentinel stored no Edge key
-- anywhere. So the entire time-witness argument rested on a verification with
-- nothing to run against, and every time-bounded offline operation refused at
-- NO_TRUSTWORTHY_TIME_WITNESS. These tables are what that verification resolves
-- to.
--
-- ENROLLING AN EDGE IS NOT TRUST-ON-FIRST-USE. The ceremony begins with a human
-- holding a capability, in a named organisation and a named site; the Edge
-- generates its keypair locally, proves possession against a server-chosen
-- challenge, and the server resolves the tenancy from the AUTHORITY rather than
-- from anything the Edge said. A row in `edges` is created PENDING and
-- SUSPENDED and becomes ACTIVE and TRUSTED only after that proof.
--
-- ON DELETE RESTRICT EVERYWHERE, NO CASCADES. A withdrawn Edge's registry row
-- must stay resolvable after the site is reorganised or the authorising human
-- leaves, because that is exactly when someone asks which box witnessed a
-- shift's work. Restrict refuses the erasing lifecycle change rather than
-- propagating it. `edge_security_events` is the other half of the WP-17A split:
-- an append-only artefact with no foreign keys at all, so the trail survives
-- even the deletions Restrict would otherwise forbid.
--
-- NO SECRET IS STORED. `edge_enrolment_authorities` has a `secret_digest`
-- column and no column a raw bearer secret could occupy, following
-- `device_enrollment_bootstrap_grants`. The Edge's private key is generated on
-- the Edge and never leaves it; there is no column here it could occupy either.
--
-- ONE HAND-WRITTEN STATEMENT, at the end of this file:
--
--   * `edge_registry_keys_one_current_key`, a PARTIAL unique index Prisma
--     cannot model. `@@unique` is unconditional, and an unconditional unique on
--     (organisation_id, edge_id) would forbid an Edge from ever holding a
--     second key version — the opposite of what rotation requires. It follows
--     `device_keys_one_current_key` from migration 20260901120000 exactly, and
--     the datamodel records its existence in a comment on `EdgeRegistryKey`.
--
-- Everything else in this file is `prisma migrate diff` output, unedited. It
-- contains no reconciliation statements: the MC-01 drift the chain used to
-- carry was fixed in 20260904090000, and the diff against the pre-change
-- datamodel produced only the objects below.

-- CreateTable
CREATE TABLE "edges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "enrolment_state" TEXT NOT NULL,
    "edge_trust" TEXT NOT NULL,
    "enrolled_by_user_id" TEXT NOT NULL,
    "activated_at" TIMESTAMPTZ(3),
    "withdrawn_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_enrolment_authorities" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "issued_by_user_id" TEXT NOT NULL,
    "secret_digest" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_enrolment_authorities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_enrolment_requests" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "authority_id" UUID NOT NULL,
    "edge_id" UUID NOT NULL,
    "offered_public_key" TEXT NOT NULL,
    "offered_public_key_thumbprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "request_fingerprint" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_enrolment_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_possession_challenges" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "enrolment_request_id" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_possession_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_possession_verifications" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "challenge_id" UUID NOT NULL,
    "enrolment_request_id" UUID NOT NULL,
    "enrolment_request_fingerprint" TEXT NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "possession_statement_fingerprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL,
    "verified_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_possession_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_registry_keys" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "edge_id" UUID NOT NULL,
    "enrolment_request_id" UUID NOT NULL,
    "edge_key_id" TEXT NOT NULL,
    "edge_key_version" INTEGER NOT NULL,
    "public_key" TEXT NOT NULL,
    "public_key_thumbprint" TEXT NOT NULL,
    "signature_profile" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "registered_at" TIMESTAMPTZ(3) NOT NULL,
    "activated_at" TIMESTAMPTZ(3) NOT NULL,
    "rotated_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_registry_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_security_events" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "edge_id" UUID,
    "site_id" TEXT,
    "event_type" TEXT NOT NULL,
    "actor_user_id" TEXT,
    "edge_key_id" TEXT,
    "edge_key_version" INTEGER,
    "outcome" TEXT,
    "refusal_code" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "edge_security_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "edges_organisation_id_site_id_enrolment_state_idx" ON "edges"("organisation_id", "site_id", "enrolment_state");

-- CreateIndex
CREATE UNIQUE INDEX "edges_id_organisation_key" ON "edges"("id", "organisation_id");

-- CreateIndex
CREATE INDEX "edge_enrolment_authorities_organisation_id_site_id_expires__idx" ON "edge_enrolment_authorities"("organisation_id", "site_id", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "edge_enrolment_authority_secret_digest_key" ON "edge_enrolment_authorities"("organisation_id", "secret_digest");

-- CreateIndex
CREATE UNIQUE INDEX "edge_enrolment_authority_tenant_key" ON "edge_enrolment_authorities"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_enrolment_request_tenant_key" ON "edge_enrolment_requests"("id", "organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_enrolment_request_authority_key" ON "edge_enrolment_requests"("organisation_id", "authority_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_enrolment_request_edge_key" ON "edge_enrolment_requests"("organisation_id", "edge_id");

-- CreateIndex
CREATE INDEX "edge_possession_challenges_organisation_id_enrolment_reques_idx" ON "edge_possession_challenges"("organisation_id", "enrolment_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_possession_challenge_request_tuple_key" ON "edge_possession_challenges"("id", "organisation_id", "enrolment_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_possession_verification_challenge_key" ON "edge_possession_verifications"("organisation_id", "challenge_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_registry_key_version_key" ON "edge_registry_keys"("organisation_id", "edge_id", "edge_key_version");

-- CreateIndex
CREATE UNIQUE INDEX "edge_registry_key_id_key" ON "edge_registry_keys"("organisation_id", "edge_key_id");

-- CreateIndex
CREATE UNIQUE INDEX "edge_registry_key_identity_tuple_key" ON "edge_registry_keys"("organisation_id", "edge_id", "edge_key_id", "edge_key_version");

-- CreateIndex
CREATE UNIQUE INDEX "edge_registry_key_enrolment_request_key" ON "edge_registry_keys"("organisation_id", "enrolment_request_id");

-- CreateIndex
CREATE INDEX "edge_security_events_organisation_id_event_type_occurred_at_idx" ON "edge_security_events"("organisation_id", "event_type", "occurred_at");

-- CreateIndex
CREATE INDEX "edge_security_events_organisation_id_edge_id_occurred_at_idx" ON "edge_security_events"("organisation_id", "edge_id", "occurred_at");

-- AddForeignKey
ALTER TABLE "edges" ADD CONSTRAINT "edges_organisation_id_fkey" FOREIGN KEY ("organisation_id") REFERENCES "organisations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edges" ADD CONSTRAINT "edges_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edges" ADD CONSTRAINT "edges_enrolled_by_user_id_organisation_id_fkey" FOREIGN KEY ("enrolled_by_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_enrolment_authorities" ADD CONSTRAINT "edge_enrolment_authorities_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_enrolment_authorities" ADD CONSTRAINT "edge_enrolment_authorities_issued_by_user_id_organisation__fkey" FOREIGN KEY ("issued_by_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_enrolment_requests" ADD CONSTRAINT "edge_enrolment_requests_authority_id_organisation_id_fkey" FOREIGN KEY ("authority_id", "organisation_id") REFERENCES "edge_enrolment_authorities"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_enrolment_requests" ADD CONSTRAINT "edge_enrolment_requests_edge_id_organisation_id_fkey" FOREIGN KEY ("edge_id", "organisation_id") REFERENCES "edges"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_enrolment_requests" ADD CONSTRAINT "edge_enrolment_requests_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_possession_challenges" ADD CONSTRAINT "edge_possession_challenges_enrolment_request_id_organisati_fkey" FOREIGN KEY ("enrolment_request_id", "organisation_id") REFERENCES "edge_enrolment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_possession_verifications" ADD CONSTRAINT "edge_possession_verifications_enrolment_request_id_organis_fkey" FOREIGN KEY ("enrolment_request_id", "organisation_id") REFERENCES "edge_enrolment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_possession_verifications" ADD CONSTRAINT "edge_possession_verifications_challenge_id_organisation_id_fkey" FOREIGN KEY ("challenge_id", "organisation_id", "enrolment_request_id") REFERENCES "edge_possession_challenges"("id", "organisation_id", "enrolment_request_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_registry_keys" ADD CONSTRAINT "edge_registry_keys_edge_id_organisation_id_fkey" FOREIGN KEY ("edge_id", "organisation_id") REFERENCES "edges"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_registry_keys" ADD CONSTRAINT "edge_registry_keys_enrolment_request_id_organisation_id_fkey" FOREIGN KEY ("enrolment_request_id", "organisation_id") REFERENCES "edge_enrolment_requests"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- CreateIndex
-- HAND-WRITTEN. AT MOST ONE `CURRENT` KEY PER (tenant, Edge).
--
-- `prisma migrate diff` cannot emit this and will not reproduce it: Prisma has
-- no way to express a partial unique index in the datamodel. It is the
-- constraint that lets the registry resolve "the Edge's current key" without a
-- `findFirst` picking a winner out of a set nobody made a singleton, and it is
-- what stops a service-bypassing writer from leaving two CURRENT keys competing
-- to verify one receipt.
CREATE UNIQUE INDEX "edge_registry_keys_one_current_key" ON "edge_registry_keys"("organisation_id", "edge_id") WHERE "status" = 'CURRENT';
