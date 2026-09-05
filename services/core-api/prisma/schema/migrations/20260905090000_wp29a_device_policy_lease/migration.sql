-- WP-29A / D29A-26 — DURABLE DEVICE POLICY LEASE PERSISTENCE.
--
-- `policy_lease_id` has always been a required field inside the signed bytes
-- of a `DeviceOfflineOperationEnvelope`: an operation created while
-- disconnected NAMES the authority it acted under, so that authority can later
-- be judged on the server's own issue/expiry times rather than on a timestamp
-- the device controls. Until now nothing resolved that name — the WP-23
-- contract had no persistence, so `evaluateOfflineOperationAdmissibility`
-- refused every envelope with LEASE_MISSING and the offline path could not run.
--
-- This migration adds the record that name resolves to, and the provenance
-- link that keeps it readable afterwards.
--
-- ON DELETE RESTRICT EVERYWHERE, NO CASCADES. A lease must remain resolvable
-- after the device is revoked, the actor disabled or the site's permissions
-- rewritten, because that is precisely when someone needs to ask what
-- authority a queued operation claimed. Restrict refuses the erasing
-- lifecycle change rather than propagating it.
--
-- `field_offline_operation_receipts.policy_lease_id` is NULLABLE and is NOT
-- back-filled. Every existing receipt predates the lease mechanism entirely;
-- inventing leases for them would fabricate authority provenance. NULL means
-- "before WP-29A", not "unknown quality". New envelope-backed receipts always
-- carry the resolved lease — that invariant is enforced in the application,
-- which has no branch that writes NULL on this path.

-- AlterTable
ALTER TABLE "field_offline_operation_receipts" ADD COLUMN     "policy_lease_id" TEXT;

-- CreateTable
CREATE TABLE "device_policy_leases" (
    "id" TEXT NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "device_id" UUID NOT NULL,
    "site_id" TEXT NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "authority_basis_id" TEXT NOT NULL,
    "scope" TEXT[],
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_policy_leases_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "device_policy_leases_organisation_id_device_id_actor_user_i_idx" ON "device_policy_leases"("organisation_id", "device_id", "actor_user_id", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "device_policy_lease_tenant_key" ON "device_policy_leases"("id", "organisation_id");

-- CreateIndex
CREATE INDEX "field_offline_receipt_policy_lease_idx" ON "field_offline_operation_receipts"("policy_lease_id");

-- AddForeignKey
ALTER TABLE "field_offline_operation_receipts" ADD CONSTRAINT "field_offline_operation_receipts_policy_lease_id_organisat_fkey" FOREIGN KEY ("policy_lease_id", "organisation_id") REFERENCES "device_policy_leases"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_policy_leases" ADD CONSTRAINT "device_policy_leases_device_id_organisation_id_fkey" FOREIGN KEY ("device_id", "organisation_id") REFERENCES "devices"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_policy_leases" ADD CONSTRAINT "device_policy_leases_site_id_organisation_id_fkey" FOREIGN KEY ("site_id", "organisation_id") REFERENCES "sites"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_policy_leases" ADD CONSTRAINT "device_policy_leases_actor_user_id_organisation_id_fkey" FOREIGN KEY ("actor_user_id", "organisation_id") REFERENCES "users"("id", "organisation_id") ON DELETE RESTRICT ON UPDATE CASCADE;

