CREATE TABLE "field_assignments" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "incident_id" UUID,
    "assignee_user_id" TEXT NOT NULL,
    "assignment_type" TEXT NOT NULL,
    "priority" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "delivery_state" TEXT NOT NULL DEFAULT 'REQUESTED',
    "need_to_know_summary" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3),
    "accepted_at" TIMESTAMPTZ(3),
    "started_at" TIMESTAMPTZ(3),
    "completed_at" TIMESTAMPTZ(3),
    "cancelled_at" TIMESTAMPTZ(3),
    "declined_at" TIMESTAMPTZ(3),
    "created_by_user_id" TEXT NOT NULL,
    "updated_by_user_id" TEXT NOT NULL,
    "accepted_by_user_id" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "field_assignments_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_assignment_action_idempotency" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "assignment_id" UUID NOT NULL,
    "action" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "actor_user_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "field_assignment_action_idempotency_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_operative_current_states" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "location" JSONB,
    "source_at" TIMESTAMPTZ(3) NOT NULL,
    "received_at" TIMESTAMPTZ(3) NOT NULL,
    "client_freshness_ms" INTEGER NOT NULL,
    "authoritative_freshness_ms" INTEGER NOT NULL,
    "trace_id" TEXT NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "field_operative_current_states_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_operative_state_history" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "location" JSONB,
    "source_at" TIMESTAMPTZ(3) NOT NULL,
    "received_at" TIMESTAMPTZ(3) NOT NULL,
    "client_freshness_ms" INTEGER NOT NULL,
    "authoritative_freshness_ms" INTEGER NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "field_operative_state_history_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_state_update_idempotency" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "field_state_update_idempotency_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_audit_log" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "assignment_id" UUID,
    "actor_user_id" TEXT,
    "kind" TEXT NOT NULL,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "field_audit_log_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "field_outbox" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "published_at" TIMESTAMPTZ(3),

    CONSTRAINT "field_outbox_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "field_assignment_create_idem_key" ON "field_assignments"("organisation_id", "site_id", "idempotency_key");
CREATE INDEX "field_assignment_status_idx" ON "field_assignments"("organisation_id", "site_id", "status");
CREATE INDEX "field_assignment_assignee_idx" ON "field_assignments"("organisation_id", "site_id", "assignee_user_id");
CREATE INDEX "field_assignments_incident_id_idx" ON "field_assignments"("incident_id");
CREATE UNIQUE INDEX "field_assignment_action_idem_key" ON "field_assignment_action_idempotency"("assignment_id", "action", "idempotency_key");
CREATE INDEX "field_assignment_action_created_idx" ON "field_assignment_action_idempotency"("assignment_id", "created_at");
CREATE UNIQUE INDEX "field_current_state_scope_key" ON "field_operative_current_states"("organisation_id", "site_id", "user_id");
CREATE INDEX "field_current_state_state_idx" ON "field_operative_current_states"("organisation_id", "site_id", "state");
CREATE INDEX "field_state_history_user_created_idx" ON "field_operative_state_history"("organisation_id", "site_id", "user_id", "created_at");
CREATE UNIQUE INDEX "field_state_update_idem_key" ON "field_state_update_idempotency"("organisation_id", "site_id", "user_id", "device_id", "idempotency_key");
CREATE INDEX "field_state_update_user_created_idx" ON "field_state_update_idempotency"("organisation_id", "site_id", "user_id", "created_at");
CREATE INDEX "field_audit_scope_at_idx" ON "field_audit_log"("organisation_id", "site_id", "at");
CREATE INDEX "field_audit_assignment_at_idx" ON "field_audit_log"("assignment_id", "at");
CREATE INDEX "field_outbox_publish_idx" ON "field_outbox"("published_at", "created_at");
CREATE INDEX "field_outbox_scope_created_idx" ON "field_outbox"("organisation_id", "site_id", "created_at");

ALTER TABLE "field_assignment_action_idempotency" ADD CONSTRAINT "field_assignment_action_idempotency_assignment_id_fkey" FOREIGN KEY ("assignment_id") REFERENCES "field_assignments"("id") ON DELETE CASCADE ON UPDATE CASCADE;
