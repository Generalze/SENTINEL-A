-- Preserve both sides of Fusion evidence independently; related_event_ids is
-- their union retained for the §12 Incident contract.
ALTER TABLE "incidents" ADD COLUMN "supporting_event_ids" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE "incidents" ADD COLUMN "contradicting_event_ids" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

-- Response task completion/ack facts are distinct from §76 delivery state.
ALTER TABLE "response_tasks" ADD COLUMN "completed_at" TIMESTAMPTZ(3);
ALTER TABLE "response_tasks" ADD COLUMN "completion_detail" JSONB;
ALTER TABLE "response_tasks" ADD COLUMN "evidence_snapshot_id" UUID;
ALTER TABLE "response_tasks" ADD COLUMN "evidence_snapshot_started_at" TIMESTAMPTZ(3);
ALTER TABLE "response_tasks" ADD COLUMN "acknowledged_at" TIMESTAMPTZ(3);
ALTER TABLE "response_tasks" ADD COLUMN "acknowledged_by_user_id" TEXT;
CREATE UNIQUE INDEX "response_tasks_evidence_snapshot_id_key" ON "response_tasks"("evidence_snapshot_id");

-- A durable local dispatch handoff is the M1 destination that may accept a
-- field dispatch before the task is marked DELIVERED. It is not an external
-- connector receipt and does not imply execution.
CREATE TABLE "response_dispatch_handoffs" (
  "id" UUID NOT NULL,
  "task_id" UUID NOT NULL,
  "accepted_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "destination" TEXT NOT NULL,
  "receipt" JSONB NOT NULL DEFAULT '{}',
  CONSTRAINT "response_dispatch_handoffs_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "response_dispatch_handoffs_task_id_key" ON "response_dispatch_handoffs"("task_id");
ALTER TABLE "response_dispatch_handoffs" ADD CONSTRAINT "response_dispatch_handoffs_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "response_tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;
