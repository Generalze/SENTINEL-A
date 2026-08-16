-- Only response-task snapshots participate in this uniqueness boundary;
-- ordinary evidence ingestion remains unchanged.
ALTER TABLE "evidence" ADD COLUMN "response_task_id" UUID;
CREATE UNIQUE INDEX "evidence_response_task_id_key" ON "evidence"("response_task_id");
