-- WP-18: Incident Field Messaging.
--
-- Additive only. Adds the message, immutable recipient membership, action
-- idempotency and outbox tables, plus the Incident candidate key the message's
-- tuple foreign key references.
--
-- Existing Incident/Event site semantics are NOT changed. Incident keeps its
-- scalar organisation_id/site_id; this migration only makes the triple
-- referenceable. The Event/Incident site-identity question remains an explicit
-- WP-22 / Milestone-2 sign-off prerequisite.

-- ---------------------------------------------------------------------------
-- Preflight. Per the WP-17A precedent this migration must fail loudly rather
-- than repair anything silently.
--
-- The candidate key below can only fail on duplicate (id, organisation_id,
-- site_id) triples, which the incidents primary key already precludes — so this
-- is expected to be a no-op. It is included deliberately: a future edit that
-- widens the key must not be able to slip past unverified, and a surprising
-- result here is far cheaper than a half-applied constraint.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  duplicate_triples bigint;
BEGIN
  SELECT count(*) INTO duplicate_triples
  FROM (
    SELECT id, organisation_id, site_id
    FROM incidents
    GROUP BY id, organisation_id, site_id
    HAVING count(*) > 1
  ) AS d;

  IF duplicate_triples > 0 THEN
    RAISE EXCEPTION
      'WP-18 preflight failed: % duplicate (id, organisation_id, site_id) triple(s) in incidents. Resolve deliberately; do NOT deduplicate automatically.',
      duplicate_triples;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Candidate key referenced by incident_field_messages. `id` remains the
-- primary key; this only makes the tenant/site-qualified triple referenceable.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX "incidents_id_org_site_key" ON "incidents" ("id", "organisation_id", "site_id");

-- ---------------------------------------------------------------------------
-- Messages
-- ---------------------------------------------------------------------------
CREATE TABLE "incident_field_messages" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "incident_id" UUID NOT NULL,
    "sender_user_id" TEXT NOT NULL,
    "body" TEXT,
    "media_refs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "retention_class" TEXT NOT NULL,
    "sent_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3),
    "idempotency_key" TEXT NOT NULL,
    "trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "incident_field_messages_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "incident_field_message_idem_key"
  ON "incident_field_messages" ("organisation_id", "incident_id", "idempotency_key");
CREATE INDEX "incident_field_message_incident_sent_idx"
  ON "incident_field_messages" ("organisation_id", "incident_id", "sent_at");
CREATE INDEX "incident_field_message_sender_idx"
  ON "incident_field_messages" ("organisation_id", "sender_user_id", "sent_at");

-- Tuple integrity: the site must be real AND in the same tenant; the incident
-- must be that exact incident under that exact tenant and site.
ALTER TABLE "incident_field_messages"
  ADD CONSTRAINT "incident_field_messages_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "incident_field_messages"
  ADD CONSTRAINT "incident_field_messages_incident_tuple_fkey"
  FOREIGN KEY ("incident_id", "organisation_id", "site_id")
  REFERENCES "incidents" ("id", "organisation_id", "site_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Immutable recipient membership + per-recipient delivery state
-- ---------------------------------------------------------------------------
CREATE TABLE "incident_field_message_recipients" (
    "id" UUID NOT NULL,
    "message_id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "recipient_user_id" TEXT NOT NULL,
    "delivery_state" TEXT NOT NULL DEFAULT 'REQUESTED',
    "delivered_at" TIMESTAMPTZ(3),
    "acknowledged_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "incident_field_message_recipients_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "incident_field_message_recipient_key"
  ON "incident_field_message_recipients" ("message_id", "recipient_user_id");
CREATE INDEX "incident_field_message_recipient_user_idx"
  ON "incident_field_message_recipients" ("organisation_id", "recipient_user_id", "created_at");

ALTER TABLE "incident_field_message_recipients"
  ADD CONSTRAINT "incident_field_message_recipients_message_fkey"
  FOREIGN KEY ("message_id") REFERENCES "incident_field_messages" ("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Recipient action replay guard
-- ---------------------------------------------------------------------------
CREATE TABLE "incident_field_message_action_idempotency" (
    "id" UUID NOT NULL,
    "message_id" UUID NOT NULL,
    "recipient_user_id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "incident_field_message_action_idempotency_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "incident_field_message_action_idem_key"
  ON "incident_field_message_action_idempotency" ("message_id", "recipient_user_id", "action", "idempotency_key");

-- ---------------------------------------------------------------------------
-- Outbox — per-recipient routing, content-free payload
-- ---------------------------------------------------------------------------
CREATE TABLE "incident_field_message_outbox" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "recipient_user_id" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "published_at" TIMESTAMPTZ(3),

    CONSTRAINT "incident_field_message_outbox_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "incident_field_message_outbox_publish_idx"
  ON "incident_field_message_outbox" ("published_at", "created_at");
