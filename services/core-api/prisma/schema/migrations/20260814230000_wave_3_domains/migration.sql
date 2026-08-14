-- CreateEnum
CREATE TYPE "evidence_classification" AS ENUM ('PUBLIC', 'INTERNAL', 'SENSITIVE', 'RESTRICTED', 'EVIDENCE', 'SECRETS');

-- CreateEnum
CREATE TYPE "evidence_custody_actor_kind" AS ENUM ('system', 'user');

-- CreateEnum
CREATE TYPE "evidence_custody_action" AS ENUM ('INGESTED', 'VIEWED', 'DERIVED', 'EXPORT_REQUESTED', 'EXPORTED', 'VERIFIED', 'VERIFY_FAILED');

-- CreateTable
CREATE TABLE "evidence" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "source_id" TEXT NOT NULL,
    "object_key" TEXT NOT NULL,
    "content_hash" TEXT NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "content_type" TEXT NOT NULL,
    "classification" "evidence_classification" NOT NULL,
    "derived_from_evidence_id" UUID,
    "incident_id" TEXT,
    "related_event_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "captured_at" TIMESTAMPTZ(3) NOT NULL,
    "stored_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence_custody_events" (
    "id" UUID NOT NULL,
    "evidence_id" UUID NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actor_kind" "evidence_custody_actor_kind" NOT NULL,
    "actor_id" TEXT NOT NULL,
    "action" "evidence_custody_action" NOT NULL,
    "detail" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "evidence_custody_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fusion_hypotheses" (
    "id" UUID NOT NULL,
    "incident_candidate_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "zone_id" TEXT,
    "zone_key" TEXT NOT NULL,
    "correlation_key" TEXT NOT NULL,
    "window_start" TIMESTAMPTZ(3) NOT NULL,
    "window_end" TIMESTAMPTZ(3) NOT NULL,
    "state" INTEGER NOT NULL,
    "detection_confidence" DOUBLE PRECISION NOT NULL,
    "threat_probability" DOUBLE PRECISION NOT NULL,
    "potential_impact" TEXT NOT NULL,
    "operational_severity" TEXT NOT NULL,
    "source_diversity" INTEGER NOT NULL,
    "supporting_event_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "contradicting_event_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence_explanation" TEXT NOT NULL,
    "rule_versions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "signals" JSONB NOT NULL DEFAULT '[]',
    "ignored_signals" JSONB NOT NULL DEFAULT '[]',
    "supporting_impact_families" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "incident_candidate_latched" BOOLEAN NOT NULL DEFAULT false,
    "incident_candidate_de_escalated" BOOLEAN NOT NULL DEFAULT false,
    "incident_candidate_emissions" INTEGER NOT NULL DEFAULT 0,
    "transition_count" INTEGER NOT NULL DEFAULT 0,
    "version" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "fusion_hypotheses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fusion_hypothesis_transitions" (
    "id" UUID NOT NULL,
    "hypothesis_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "from_state" INTEGER NOT NULL,
    "to_state" INTEGER NOT NULL,
    "event_id" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "rule_versions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "sequence" INTEGER NOT NULL,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "fusion_hypothesis_transitions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fusion_applied_events" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "event_id" TEXT NOT NULL,
    "hypothesis_id" UUID,
    "correlation_key" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "signal_kind" TEXT,
    "ignore_reason" TEXT,
    "rule_version" TEXT NOT NULL,
    "applied_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "fusion_applied_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "decision_ledger_entries" (
    "entry_id" TEXT NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "decided_at" TIMESTAMPTZ(3) NOT NULL,
    "decision_type" TEXT NOT NULL,
    "inputs_snapshot" JSONB NOT NULL,
    "rule_or_model_versions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "policy_version" TEXT NOT NULL,
    "evidence_for" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "evidence_against" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence" DOUBLE PRECISION,
    "approvals" JSONB NOT NULL DEFAULT '[]',
    "action_taken" TEXT NOT NULL,
    "outcome" TEXT,
    "trace_id" TEXT NOT NULL,
    "schema_version" INTEGER NOT NULL DEFAULT 1,
    "content_hash" TEXT NOT NULL,
    "previous_hash" TEXT,
    "supersedes_entry_id" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "seq" SERIAL NOT NULL,

    CONSTRAINT "decision_ledger_entries_pkey" PRIMARY KEY ("entry_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "evidence_object_key_key" ON "evidence"("object_key");

-- CreateIndex
CREATE INDEX "evidence_organisation_id_stored_at_idx" ON "evidence"("organisation_id", "stored_at");

-- CreateIndex
CREATE INDEX "evidence_organisation_id_incident_id_idx" ON "evidence"("organisation_id", "incident_id");

-- CreateIndex
CREATE INDEX "evidence_derived_from_evidence_id_idx" ON "evidence"("derived_from_evidence_id");

-- CreateIndex
CREATE INDEX "evidence_custody_events_evidence_id_at_idx" ON "evidence_custody_events"("evidence_id", "at");

-- CreateIndex
CREATE UNIQUE INDEX "fusion_hypotheses_incident_candidate_id_key" ON "fusion_hypotheses"("incident_candidate_id");

-- CreateIndex
CREATE UNIQUE INDEX "fusion_hypotheses_correlation_key_key" ON "fusion_hypotheses"("correlation_key");

-- CreateIndex
CREATE INDEX "fusion_hypotheses_organisation_id_updated_at_idx" ON "fusion_hypotheses"("organisation_id", "updated_at");

-- CreateIndex
CREATE INDEX "fusion_hypotheses_organisation_id_site_id_window_start_idx" ON "fusion_hypotheses"("organisation_id", "site_id", "window_start");

-- CreateIndex
CREATE INDEX "fusion_hypotheses_organisation_id_state_idx" ON "fusion_hypotheses"("organisation_id", "state");

-- CreateIndex
CREATE INDEX "fusion_hypothesis_transitions_organisation_id_created_at_idx" ON "fusion_hypothesis_transitions"("organisation_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "fusion_hypothesis_transitions_hypothesis_id_sequence_key" ON "fusion_hypothesis_transitions"("hypothesis_id", "sequence");

-- CreateIndex
CREATE INDEX "fusion_applied_events_hypothesis_id_idx" ON "fusion_applied_events"("hypothesis_id");

-- CreateIndex
CREATE INDEX "fusion_applied_events_organisation_id_applied_at_idx" ON "fusion_applied_events"("organisation_id", "applied_at");

-- CreateIndex
CREATE UNIQUE INDEX "fusion_applied_events_organisation_id_event_id_key" ON "fusion_applied_events"("organisation_id", "event_id");

-- CreateIndex
CREATE UNIQUE INDEX "decision_ledger_entries_seq_key" ON "decision_ledger_entries"("seq");

-- CreateIndex
CREATE INDEX "decision_ledger_entries_organisation_id_seq_idx" ON "decision_ledger_entries"("organisation_id", "seq");

-- CreateIndex
CREATE INDEX "decision_ledger_entries_organisation_id_decision_type_decid_idx" ON "decision_ledger_entries"("organisation_id", "decision_type", "decided_at");

-- CreateIndex
CREATE INDEX "decision_ledger_entries_organisation_id_decided_at_idx" ON "decision_ledger_entries"("organisation_id", "decided_at");

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_derived_from_evidence_id_fkey" FOREIGN KEY ("derived_from_evidence_id") REFERENCES "evidence"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence_custody_events" ADD CONSTRAINT "evidence_custody_events_evidence_id_fkey" FOREIGN KEY ("evidence_id") REFERENCES "evidence"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fusion_hypothesis_transitions" ADD CONSTRAINT "fusion_hypothesis_transitions_hypothesis_id_fkey" FOREIGN KEY ("hypothesis_id") REFERENCES "fusion_hypotheses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fusion_applied_events" ADD CONSTRAINT "fusion_applied_events_hypothesis_id_fkey" FOREIGN KEY ("hypothesis_id") REFERENCES "fusion_hypotheses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

