-- WP-14 C1: idempotency key is scoped per organisation (was globally unique).
DROP INDEX "events_idempotency_key_key";
CREATE UNIQUE INDEX "events_organisation_id_idempotency_key_key" ON "events"("organisation_id", "idempotency_key");