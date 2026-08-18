-- WP-18/C8-05: make the send-idempotency identity sender-scoped.
--
-- The original uniqueness was (organisation_id, incident_id, idempotency_key).
-- Because the replay lookup used that same scope, a send by a DIFFERENT sender
-- that collided on the key hit the unique violation and was answered with the
-- EXISTING message — body and recipient list included — even though the caller
-- was neither its sender nor a named recipient. That bypassed the entitlement
-- layer the whole design rests on. Adding the sender also prevents one sender
-- from squatting another's idempotency keys.
--
-- Expand before contract: the broader sender-scoped index is created FIRST, so
-- there is never an interval without idempotency protection, and only then is
-- the narrower one dropped.
--
-- This replaces a constraint rather than adding one, which departs from the
-- normal additive-only posture; it is explicitly authorised because it removes
-- no table, column or row and performs no data rewrite. The outgoing index is
-- strictly stricter than the incoming one, so every existing row is already
-- unique under the new key: no backfill, DELETE, UPDATE or deduplication is
-- required or performed.

CREATE UNIQUE INDEX "incident_field_message_sender_idem_key"
  ON "incident_field_messages" ("organisation_id", "incident_id", "sender_user_id", "idempotency_key");

DROP INDEX "incident_field_message_idem_key";
