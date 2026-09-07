-- CreateTable
CREATE TABLE "edge_transport_identities" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "edge_id" UUID NOT NULL,
    "transport_key_version" INTEGER NOT NULL,
    "transport_public_key" TEXT NOT NULL,
    "tls_spki_sha256" TEXT NOT NULL,
    "https_endpoint" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "registered_at" TIMESTAMPTZ(3) NOT NULL,
    "activated_at" TIMESTAMPTZ(3),
    "rotated_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "edge_transport_identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_receipt_observations" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "edge_id" TEXT NOT NULL,
    "edge_key_id" TEXT NOT NULL,
    "edge_key_version" INTEGER NOT NULL,
    "offline_operation_id" TEXT,
    "witnessed_operation_fingerprint" TEXT NOT NULL,
    "receipt_fingerprint" TEXT NOT NULL,
    "trusted_time_anchor_id" TEXT,
    "trusted_time_anchor_fingerprint" TEXT,
    "verified_edge_trusted_time" TIMESTAMPTZ(3),
    "edge_monotonic_position" INTEGER,
    "observed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "trace_id" TEXT,

    CONSTRAINT "edge_receipt_observations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "edge_transport_identities_organisation_id_site_id_status_idx" ON "edge_transport_identities"("organisation_id", "site_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "edge_transport_identity_version_key" ON "edge_transport_identities"("organisation_id", "edge_id", "transport_key_version");

-- CreateIndex
CREATE INDEX "edge_receipt_observations_organisation_id_site_id_observed__idx" ON "edge_receipt_observations"("organisation_id", "site_id", "observed_at");

-- CreateIndex
CREATE INDEX "edge_receipt_observations_organisation_id_edge_id_observed__idx" ON "edge_receipt_observations"("organisation_id", "edge_id", "observed_at");

-- CreateIndex
CREATE UNIQUE INDEX "edge_receipt_observation_receipt_key" ON "edge_receipt_observations"("organisation_id", "receipt_fingerprint");

-- AddForeignKey
ALTER TABLE "edge_transport_identities" ADD CONSTRAINT "edge_transport_identities_edge_id_organisation_id_fkey" FOREIGN KEY ("edge_id", "organisation_id") REFERENCES "edges"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_transport_identities" ADD CONSTRAINT "edge_transport_identities_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "edge_transport_identities" ADD CONSTRAINT "edge_transport_identities_organisation_id_fkey" FOREIGN KEY ("organisation_id") REFERENCES "organisations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- ===========================================================================
-- M3B §2 — EXACTLY ONE CURRENT FIELD-INGRESS TRANSPORT IDENTITY PER SITE.
--
-- HAND-WRITTEN. Prisma cannot express a PARTIAL unique index, and an
-- unconditional unique on (organisation_id, site_id) would forbid a site from
-- ever holding a second transport key version -- the opposite of what rotation
-- requires. `prisma migrate diff` will not reproduce this statement, so it is
-- carried by hand exactly as `edge_registry_keys_one_current_key` is.
--
-- WHY PER SITE RATHER THAN PER EDGE. The descriptor endpoint resolves a site
-- to the one transport identity its devices should pin. If a site could
-- present two CURRENT identities the endpoint would have to choose, and the
-- fleet's trust anchor would be decided by row ordering -- half a site pinned
-- to one key and half to another, with nothing recording that it happened.
-- The service refuses with AMBIGUOUS_TRANSPORT_IDENTITY; this index means the
-- ambiguity cannot be created for it to detect.
-- ===========================================================================
CREATE UNIQUE INDEX "edge_transport_identities_one_current_per_site"
  ON "edge_transport_identities"("organisation_id","site_id")
  WHERE "status" = 'CURRENT';
