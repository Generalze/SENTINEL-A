-- MC-01 — FORWARD SCHEMA RECONCILIATION.
--
-- A fresh database built from the committed migration chain was not identical
-- to the committed Prisma datamodel. Both sides worked, and every test passed
-- either way, which is exactly why this went unnoticed for eight work
-- packages: the defect is not runtime behaviour, it is that the chain and the
-- datamodel disagreed about what the schema IS.
--
-- The disagreement had two classes, measured rather than assumed:
--
--   25 x RENAME CONSTRAINT   hand-written short foreign-key names from WP-16,
--                            WP-18 and later, versus the names the current
--                            engine generates. Naming only - identical
--                            columns, targets and referential semantics.
--
--    8 x DROP DEFAULT        database-side defaults the datamodel never
--                            declared: seven `gen_random_uuid()` on `id`
--                            columns whose models say `@default(uuid())`, and
--                            one `CURRENT_TIMESTAMP` on a column whose model
--                            says `@updatedAt`. Prisma generates both
--                            client-side and always sends a value, so the
--                            database defaults were never consulted.
--
-- WHY THE COSMETIC HALF IS NOT COSMETIC. The renames matter not because
-- longer names are better, but because while they diverge the engine tries to
-- "fix" them in EVERY future generated migration. WP-24, WP-25 and WP-26 each
-- had to strip these 33 statements out by hand, and each carries a header
-- saying so. That recurring contamination is itself the defect, and one bad
-- pass would have shipped it by accident.
--
-- WHAT THIS MIGRATION DELIBERATELY IS NOT.
--
--   * It does not edit history. The 23 existing migrations and their
--     checksums are untouched; the correction is forward.
--   * It does not change the datamodel to match the accident. Making
--     `@default(uuid())` into `dbgenerated()` would promote an incidental
--     historical SQL choice into the domain contract. The physical schema is
--     brought to the schema the application already declares, not the reverse.
--   * It is SCHEMA ONLY. No row is inserted, updated or deleted; no UUID is
--     regenerated; no timestamp is rewritten.
--   * It is not self-healing. There is no `IF EXISTS` guard for the renames.
--     A database that lacks the expected pre-migration objects is not a
--     database this migration should quietly paper over - it is evidence, and
--     failing loudly is the correct answer.
--
-- Generated from the measured `prisma migrate diff`, then audited statement by
-- statement. Acceptance is a ZERO-drift diff after it applies, not merely a
-- green test run.

-- AlterTable
ALTER TABLE "field_assignment_action_idempotency" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_assignments" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_audit_log" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_operative_current_states" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_operative_state_history" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_outbox" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "field_state_update_idempotency" ALTER COLUMN "id" DROP DEFAULT;

-- AlterTable
ALTER TABLE "incident_field_message_recipients" ALTER COLUMN "updated_at" DROP DEFAULT;

-- RenameForeignKey
ALTER TABLE "field_assignments" RENAME CONSTRAINT "field_assignments_site_org_fkey" TO "field_assignments_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "field_offline_device_cursors" RENAME CONSTRAINT "field_offline_device_cursors_site_org_fkey" TO "field_offline_device_cursors_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "field_operative_current_states" RENAME CONSTRAINT "field_operative_current_states_site_org_fkey" TO "field_operative_current_states_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "incident_field_message_action_idempotency" RENAME CONSTRAINT "incident_field_message_action_idempotency_message_fkey" TO "incident_field_message_action_idempotency_message_id_fkey";

-- RenameForeignKey
ALTER TABLE "incident_field_message_recipients" RENAME CONSTRAINT "incident_field_message_recipients_message_fkey" TO "incident_field_message_recipients_message_id_fkey";

-- RenameForeignKey
ALTER TABLE "incident_field_messages" RENAME CONSTRAINT "incident_field_messages_incident_tuple_fkey" TO "incident_field_messages_incident_id_organisation_id_site_i_fkey";

-- RenameForeignKey
ALTER TABLE "incident_field_messages" RENAME CONSTRAINT "incident_field_messages_site_org_fkey" TO "incident_field_messages_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_checkpoint_verifications" RENAME CONSTRAINT "patrol_checkpoint_verifications_run_checkpoint_fkey" TO "patrol_checkpoint_verifications_patrol_run_checkpoint_id_p_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_checkpoint_verifications" RENAME CONSTRAINT "patrol_checkpoint_verifications_run_fkey" TO "patrol_checkpoint_verifications_patrol_run_id_organisation_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_checkpoints" RENAME CONSTRAINT "patrol_checkpoints_route_fkey" TO "patrol_checkpoints_patrol_route_id_organisation_id_site_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_checkpoints" RENAME CONSTRAINT "patrol_checkpoints_version_fkey" TO "patrol_checkpoints_patrol_route_id_route_version_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_route_versions" RENAME CONSTRAINT "patrol_route_versions_route_fkey" TO "patrol_route_versions_patrol_route_id_organisation_id_site_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_routes" RENAME CONSTRAINT "patrol_routes_site_org_fkey" TO "patrol_routes_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_run_action_idempotency" RENAME CONSTRAINT "patrol_run_action_idempotency_run_fkey" TO "patrol_run_action_idempotency_patrol_run_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_run_checkpoints" RENAME CONSTRAINT "patrol_run_checkpoints_checkpoint_fkey" TO "patrol_run_checkpoints_patrol_checkpoint_id_patrol_route_i_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_run_checkpoints" RENAME CONSTRAINT "patrol_run_checkpoints_run_fkey" TO "patrol_run_checkpoints_patrol_run_id_organisation_id_site__fkey";

-- RenameForeignKey
ALTER TABLE "patrol_run_checkpoints" RENAME CONSTRAINT "patrol_run_checkpoints_verification_fkey" TO "patrol_run_checkpoints_verification_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_runs" RENAME CONSTRAINT "patrol_runs_incident_fkey" TO "patrol_runs_incident_id_organisation_id_site_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_runs" RENAME CONSTRAINT "patrol_runs_route_fkey" TO "patrol_runs_patrol_route_id_organisation_id_site_id_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_runs" RENAME CONSTRAINT "patrol_runs_route_version_fkey" TO "patrol_runs_patrol_route_id_route_version_fkey";

-- RenameForeignKey
ALTER TABLE "patrol_runs" RENAME CONSTRAINT "patrol_runs_site_org_fkey" TO "patrol_runs_site_id_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "whisper_activation_approvals" RENAME CONSTRAINT "whisper_activation_approvals_version_org_fkey" TO "whisper_activation_approvals_signal_version_id_organisatio_fkey";

-- RenameForeignKey
ALTER TABLE "whisper_recognition_receipts" RENAME CONSTRAINT "whisper_recognition_receipts_version_org_fkey" TO "whisper_recognition_receipts_signal_version_id_organisatio_fkey";

-- RenameForeignKey
ALTER TABLE "whisper_signal_versions" RENAME CONSTRAINT "whisper_signal_versions_organisation_fkey" TO "whisper_signal_versions_organisation_id_fkey";

-- RenameForeignKey
ALTER TABLE "whisper_signal_versions" RENAME CONSTRAINT "whisper_signal_versions_site_org_fkey" TO "whisper_signal_versions_site_id_organisation_id_fkey";

