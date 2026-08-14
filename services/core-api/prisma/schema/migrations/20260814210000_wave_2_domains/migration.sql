-- CreateEnum
CREATE TYPE "constitution_policy_status" AS ENUM ('draft', 'active', 'retired');

-- CreateTable
CREATE TABLE "constitution_policies" (
    "id" UUID NOT NULL,
    "version" TEXT NOT NULL,
    "body" JSONB NOT NULL,
    "content_sha256" TEXT NOT NULL,
    "status" "constitution_policy_status" NOT NULL DEFAULT 'draft',
    "created_by" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "activated_at" TIMESTAMP(3),

    CONSTRAINT "constitution_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "events" (
    "id" UUID NOT NULL,
    "event_id" TEXT NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "zone_id" TEXT,
    "source_type" TEXT NOT NULL,
    "source_id" TEXT NOT NULL,
    "source_trust" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "ingested_at" TIMESTAMPTZ(3) NOT NULL,
    "location" JSONB NOT NULL DEFAULT '{}',
    "track_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "evidence_refs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "trace_id" TEXT NOT NULL,
    "idempotency_key" TEXT,
    "duplicate_of_event_id" UUID,
    "received_count" INTEGER NOT NULL DEFAULT 1,
    "published_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organisations" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organisations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sites" (
    "id" TEXT NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sites_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "zones" (
    "id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "zones_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "clearance" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_roles" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "site_id" TEXT,

    CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "constitution_policies_version_key" ON "constitution_policies"("version");

-- CreateIndex
CREATE INDEX "constitution_policies_status_idx" ON "constitution_policies"("status");

-- CreateIndex
CREATE UNIQUE INDEX "events_idempotency_key_key" ON "events"("idempotency_key");

-- CreateIndex
CREATE INDEX "events_organisation_id_site_id_occurred_at_idx" ON "events"("organisation_id", "site_id", "occurred_at");

-- CreateIndex
CREATE INDEX "events_organisation_id_source_type_occurred_at_idx" ON "events"("organisation_id", "source_type", "occurred_at");

-- CreateIndex
CREATE INDEX "events_published_at_idx" ON "events"("published_at");

-- CreateIndex
CREATE INDEX "events_duplicate_of_event_id_idx" ON "events"("duplicate_of_event_id");

-- CreateIndex
CREATE INDEX "sites_organisation_id_idx" ON "sites"("organisation_id");

-- CreateIndex
CREATE INDEX "zones_site_id_idx" ON "zones"("site_id");

-- CreateIndex
CREATE INDEX "users_organisation_id_idx" ON "users"("organisation_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_organisation_id_email_key" ON "users"("organisation_id", "email");

-- CreateIndex
CREATE INDEX "user_roles_user_id_idx" ON "user_roles"("user_id");

-- CreateIndex
CREATE INDEX "user_roles_role_idx" ON "user_roles"("role");

-- CreateIndex
CREATE UNIQUE INDEX "user_roles_user_id_role_site_id_key" ON "user_roles"("user_id", "role", "site_id");

-- AddForeignKey
ALTER TABLE "events" ADD CONSTRAINT "events_duplicate_of_event_id_fkey" FOREIGN KEY ("duplicate_of_event_id") REFERENCES "events"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sites" ADD CONSTRAINT "sites_organisation_id_fkey" FOREIGN KEY ("organisation_id") REFERENCES "organisations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "zones" ADD CONSTRAINT "zones_site_id_fkey" FOREIGN KEY ("site_id") REFERENCES "sites"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_organisation_id_fkey" FOREIGN KEY ("organisation_id") REFERENCES "organisations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_site_id_fkey" FOREIGN KEY ("site_id") REFERENCES "sites"("id") ON DELETE SET NULL ON UPDATE CASCADE;


-- Single-active constitution policy (WP-06): partial unique index not expressible in Prisma DSL.
CREATE UNIQUE INDEX "constitution_policies_single_active" ON "constitution_policies" ("status") WHERE "status" = 'active';
