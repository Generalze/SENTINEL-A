-- CreateTable
CREATE TABLE "incidents" (
    "id" UUID NOT NULL,
    "hypothesis_id" UUID NOT NULL,
    "incident_candidate_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "incident_type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "threat_state" INTEGER NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "response_mode" TEXT NOT NULL,
    "commander_user_id" TEXT,
    "related_event_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "playbook_version" TEXT,
    "status" TEXT NOT NULL DEFAULT 'open',
    "closure_reason" TEXT,
    "opened_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incident_timeline_entries" (
    "id" UUID NOT NULL,
    "incident_id" UUID NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "kind" TEXT NOT NULL,
    "actor_user_id" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "incident_timeline_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "response_tasks" (
    "id" UUID NOT NULL,
    "incident_id" UUID NOT NULL,
    "task_type" TEXT NOT NULL,
    "playbook_version" TEXT NOT NULL,
    "delivery_state" TEXT NOT NULL DEFAULT 'REQUESTED',
    "payload" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "response_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "incidents_hypothesis_id_key" ON "incidents"("hypothesis_id");
CREATE INDEX "incidents_organisation_id_status_idx" ON "incidents"("organisation_id", "status");
CREATE INDEX "incidents_organisation_id_severity_idx" ON "incidents"("organisation_id", "severity");
CREATE INDEX "incidents_organisation_id_opened_at_idx" ON "incidents"("organisation_id", "opened_at");
CREATE INDEX "incident_timeline_entries_incident_id_at_idx" ON "incident_timeline_entries"("incident_id", "at");
CREATE UNIQUE INDEX "response_tasks_incident_id_task_type_key" ON "response_tasks"("incident_id", "task_type");
CREATE INDEX "response_tasks_incident_id_delivery_state_idx" ON "response_tasks"("incident_id", "delivery_state");

-- AddForeignKey
ALTER TABLE "incident_timeline_entries" ADD CONSTRAINT "incident_timeline_entries_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "response_tasks" ADD CONSTRAINT "response_tasks_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
