-- WP-20: Offline Replay Foundation (Checkpoint B persistence).
--
-- Additive only: two new tables, no change to any existing table, column or
-- constraint. The Site candidate key sites(id, organisation_id) added by
-- WP-17A is referenced, not modified.
--
-- WHAT THESE TWO TABLES ARE FOR
-- -----------------------------
-- A reconnect may DELAY an authorised operation. It must never duplicate it,
-- reorder it, weaken its authorization, backdate server authority, or let a
-- changed request hide behind an old idempotency identity.
--
--   field_offline_device_cursors    LIVE sync state. One row per authenticated
--     replay namespace (organisation, site, user, device), holding
--     last_finalized_sequence — the C10-07 rule: the cursor tracks the last
--     FINALIZED sequence, not the last APPLIED one, because a deterministic
--     rejection consumes a queue position exactly as an application does.
--     Without that, a rejected entry would wedge the queue behind a position
--     nothing could ever fill. NULL means a fresh namespace: the contract's
--     OFFLINE_SEQUENCE_START (0) has not been consumed yet, so the next
--     admissible sequence is 0 rather than last + 1. An UNKNOWN outcome
--     (C10-08) never advances the cursor; it is retried into convergence.
--
--   field_offline_operation_receipts   APPEND-MOSTLY reliability records. One
--     row per queued operation, inserted on first receipt and then advanced
--     through the C10-08 lifecycle (RECEIVED -> APPLYING -> APPLIED/REJECTED/
--     UNKNOWN) in place. No write path deletes one: a receipt is the only
--     durable answer to "did my queued operation actually happen?", and it is
--     what a REPLAY returns instead of re-executing a domain effect.
--
-- SITE REFERENTIAL INTEGRITY — the WP-17A split, applied here
-- -----------------------------------------------------------
-- The cursor is live state, so it carries the composite (site_id,
-- organisation_id) foreign key to sites, ON DELETE RESTRICT, exactly like
-- field_assignments and field_operative_current_states. The pair must match,
-- not just the site id, so the database itself rejects a row pairing one
-- tenant's organisation with another tenant's site (§62.1 defence in depth).
--
-- The receipt table deliberately gets NO foreign key, per the WP-17A
-- historical-artefact rule (see prisma/schema/field.prisma's doctrine header
-- and docs/execution/directives/WP-17A-field-site-integrity.md), the same rule
-- that governs field_operative_state_history, field_state_update_idempotency,
-- field_audit_log and field_outbox. Its site_id is the site identifier as
-- recorded at receipt time and must stay that way: CASCADE would let a site's
-- lifecycle erase the record of what a device was told happened to its queued
-- work (forbidden by §61), and RESTRICT would mean a site could never be
-- removed once a single device had ever synced — silently inventing a Site
-- retirement policy this work package has no mandate to decide. Integrity
-- comes from the write-time check instead: the service proves the site exists
-- in the organisation, and that the principal is authorised for it, BEFORE the
-- transaction that claims the receipt, calls the domain and advances the
-- cursor.
--
-- NOTHING HERE CASCADES. Unlike the WP-16/WP-18/WP-19 action-idempotency
-- tables, a receipt is not a replay guard that may be discarded with its
-- parent: losing one converts an applied operation back into an unapplied one,
-- which is the precise duplication this work package exists to forbid.

-- ---------------------------------------------------------------------------
-- Live per-device queue position (C10-03, C10-07).
-- ---------------------------------------------------------------------------
CREATE TABLE "field_offline_device_cursors" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    -- NULL = fresh namespace; OFFLINE_SEQUENCE_START (0) not yet consumed.
    "last_finalized_sequence" BIGINT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "field_offline_device_cursors_pkey" PRIMARY KEY ("id")
);

-- One cursor per authenticated replay namespace.
CREATE UNIQUE INDEX "field_offline_cursor_namespace_key"
  ON "field_offline_device_cursors" ("organisation_id", "site_id", "user_id", "device_id");

-- WP-17A live-state precedent: the pair must match, not just the site id.
-- RESTRICT — a site deletion must never silently reset a live queue position.
ALTER TABLE "field_offline_device_cursors"
  ADD CONSTRAINT "field_offline_device_cursors_site_org_fkey"
  FOREIGN KEY ("site_id", "organisation_id")
  REFERENCES "sites" ("id", "organisation_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Operation receipts (C10-04, C10-08, C10-09, C10-11).
--
-- No Site foreign key by design — see the preamble's WP-17A reasoning.
-- ---------------------------------------------------------------------------
CREATE TABLE "field_offline_operation_receipts" (
    "id" UUID NOT NULL,
    "organisation_id" TEXT NOT NULL,
    "site_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_id" TEXT NOT NULL,
    "device_sequence" BIGINT NOT NULL,
    "offline_operation_id" UUID NOT NULL,
    "operation_kind" TEXT NOT NULL,
    -- C10-04: SHA-256 hex of the canonical semantic request.
    "request_fingerprint" TEXT NOT NULL,
    -- C10-09: server-derived, never the client's key; stored so a crash retry
    -- converges on the same domain identity.
    "downstream_idempotency_key" TEXT NOT NULL,
    -- C10-06: client telemetry only, never server authority.
    "client_created_at" TIMESTAMPTZ(3) NOT NULL,
    -- Server clock.
    "first_received_at" TIMESTAMPTZ(3) NOT NULL,
    -- C10-08: RECEIVED | APPLYING | APPLIED | REJECTED | UNKNOWN.
    "status" TEXT NOT NULL DEFAULT 'RECEIVED',
    -- APPLIED | REJECTED once finalized.
    "outcome" TEXT,
    -- Safe code (e.g. DOMAIN_REJECTED) — never domain detail (C10-11).
    "conflict_code" TEXT,
    "result_ref" TEXT,
    -- Bounded, allowlist-populated; NEVER message body/recipients/need-to-know.
    "result_snapshot" JSONB,
    -- CAS/lease claim marker for crash recovery.
    "processing_claimed_at" TIMESTAMPTZ(3),
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "finalized_at" TIMESTAMPTZ(3),
    "first_trace_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "field_offline_operation_receipts_pkey" PRIMARY KEY ("id")
);

-- One receipt per queue position per namespace: the durable proof that makes
-- REPLAY / SEQUENCE_REUSED / SEQUENCE_STALE distinguishable (C10-03).
CREATE UNIQUE INDEX "field_offline_receipt_sequence_key"
  ON "field_offline_operation_receipts" ("organisation_id", "site_id", "user_id", "device_id", "device_sequence");

-- OPERATION_ID_REUSED enforced below the service layer: one offline operation
-- id may occupy exactly one queue position in its namespace, so a
-- service-bypassing writer cannot smuggle the same operation in twice.
CREATE UNIQUE INDEX "field_offline_receipt_operation_key"
  ON "field_offline_operation_receipts" ("organisation_id", "site_id", "user_id", "device_id", "offline_operation_id");

-- Recovery sweep: find operations left in a non-finalized status.
CREATE INDEX "field_offline_receipt_recovery_idx"
  ON "field_offline_operation_receipts" ("status", "updated_at");
