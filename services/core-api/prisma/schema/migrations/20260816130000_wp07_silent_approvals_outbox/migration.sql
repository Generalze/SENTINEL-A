CREATE TABLE "response_task_silent_approvals" (
  "id" UUID NOT NULL,
  "task_id" UUID NOT NULL,
  "user_id" TEXT NOT NULL,
  "claimed_role" TEXT NOT NULL,
  "approved_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "response_task_silent_approvals_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "response_task_silent_approvals_task_id_user_id_key" ON "response_task_silent_approvals"("task_id", "user_id");
CREATE INDEX "response_task_silent_approvals_task_id_approved_at_idx" ON "response_task_silent_approvals"("task_id", "approved_at");
ALTER TABLE "response_task_silent_approvals" ADD CONSTRAINT "response_task_silent_approvals_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "response_tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "incident_update_outbox" (
  "id" UUID NOT NULL,
  "incident_id" UUID NOT NULL,
  "organisation_id" TEXT NOT NULL,
  "payload" JSONB NOT NULL,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "published_at" TIMESTAMPTZ(3),
  CONSTRAINT "incident_update_outbox_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "incident_update_outbox_published_at_created_at_idx" ON "incident_update_outbox"("published_at", "created_at");
CREATE INDEX "incident_update_outbox_organisation_id_created_at_idx" ON "incident_update_outbox"("organisation_id", "created_at");
