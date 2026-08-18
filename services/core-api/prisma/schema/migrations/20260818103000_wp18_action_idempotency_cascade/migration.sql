-- WP-18 follow-up: give the message action replay guard the same cascade
-- relation WP-16's assignment action idempotency already has.
--
-- A replay guard for a message that no longer exists has no meaning, and
-- orphaned rows would slowly desynchronise the guard from reality. Kept as a
-- separate additive migration rather than editing the applied one, because
-- rewriting an applied migration breaks its recorded checksum and would force
-- a destructive database reset.

ALTER TABLE "incident_field_message_action_idempotency"
  ADD CONSTRAINT "incident_field_message_action_idempotency_message_fkey"
  FOREIGN KEY ("message_id") REFERENCES "incident_field_messages" ("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
