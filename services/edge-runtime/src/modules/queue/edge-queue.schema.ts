import { EDGE_QUEUE_MAX_MONOTONIC_POSITION, EDGE_QUEUE_SCHEMA_VERSION } from './edge-queue.constants';
import {
  EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES,
  EDGE_QUEUE_FAILURE_CATEGORIES,
  EDGE_QUEUE_SETTLED_STATES,
  EDGE_QUEUE_STATES,
} from './edge-queue.state';

/**
 * ============================================================================
 * WP-29B / LANE B — THE DURABLE QUEUE'S SCHEMA, AND WHY THE DATABASE ITSELF
 * ENFORCES THE SECURITY RULES.
 *
 * WHY SQLITE, AND WHY THE ONE IN THE RUNTIME
 * ------------------------------------------
 * The store has to survive a process restart, a container restart, and the
 * cleaner unplugging the box mid-write. That is a transactional, crash-safe,
 * embedded database, and on a hardened Linux Edge appliance SQLite is the
 * answer — the same engine, the same WAL, the same durability semantics that
 * `better-sqlite3` would have wrapped.
 *
 * It is reached through `node:sqlite` rather than through `better-sqlite3`, and
 * the reason is the deployment rather than the API:
 *
 *   - `better-sqlite3` is a NATIVE ADDON. Installing it on the appliance means
 *     either a compiler toolchain on a hardened box or a prebuilt binary
 *     downloaded at deploy time and executed with the runtime's full
 *     privileges. This repository's pnpm already refuses install scripts by
 *     default (`Ignored build scripts: ...` on every install); admitting one so
 *     that a security appliance can fetch and run an unsigned binary is a
 *     supply-chain decision, not a dependency choice.
 *
 *   - `node:sqlite` ships INSIDE the Node runtime that is already pinned
 *     (`.nvmrc` 24.18.0, CI on node 24). It adds no package, no lockfile entry
 *     to audit, no postinstall, and no second copy of SQLite to patch when a
 *     CVE lands — it is patched by the Node upgrade the appliance takes anyway.
 *
 * The cost is honest and is stated so nobody discovers it later: it requires
 * Node >= 22.13 for the unflagged module, so `services/edge-runtime/package.json`
 * declares `engines.node >= 24.0.0` to match the pinned runtime. The only
 * dependency change this lane makes is bumping that package's `@types/node`
 * devDependency to the version that carries `node:sqlite`'s types.
 *
 * WHAT IS EMPHATICALLY NOT USED
 * -----------------------------
 * Not a JSON file — the Android outbox uses one and its own comment says why
 * that only works there: a handset queue is small enough to rewrite whole on
 * every operation. An Edge holds a whole site's shift, and rewriting a
 * multi-megabyte document per acknowledgement is both slow and the exact write
 * a power cut lands in the middle of. Not an in-memory queue — it does not
 * survive the first restart, which is the entire requirement. And not central
 * PostgreSQL, which is unreachable in precisely the situation this store exists
 * for.
 *
 * ============================================================================
 * THE RULES THE DATABASE ENFORCES, AND WHY THEY ARE NOT ONLY IN TYPESCRIPT
 * ============================================================================
 * Every constraint and trigger below also exists as a check in the store, and
 * that is not redundancy. The store is one writer among the several that can
 * reach a file on a box in a wiring closet: an operator with `sqlite3` on the
 * appliance, a future maintenance script, a half-finished migration, a
 * second process someone starts by accident. A rule that lives only in the
 * TypeScript is a rule that stops at the first writer who does not use it.
 *
 * So the schema refuses, at the storage engine:
 *
 *   1. A row that CLAIMS CENTRAL COMMITTED WITHOUT CARRYING CENTRAL'S ANSWER.
 *      `edge_queue_settlement_matches_state` makes the settled states and a
 *      non-null settlement exactly equivalent, and
 *      `edge_queue_settlement_proves_state` goes further: CENTRAL_APPLIED
 *      requires an answer whose outcome is literally CENTRAL_ACCEPTED, and
 *      FAILED_TERMINAL one whose outcome is CENTRAL_REFUSED. There is no
 *      sequence of SQL that produces a locally-committed-looking row.
 *
 *   2. DELETING AN OPERATION CENTRAL HAS NOT ANSWERED. The trigger
 *      `edge_queue_no_unsettled_delete` aborts it. Capacity pressure, an
 *      over-broad cleanup, a mistyped WHERE clause — all of them stop here.
 *      This is the structural half of "no deleting an unresolved operation to
 *      make room".
 *
 *   3. REWRITING AN ENTRY CENTRAL HAS ALREADY ANSWERED, or rewriting the SIGNED
 *      BYTES of any entry. The signature covers the envelope; an UPDATE that
 *      changed one byte of it would leave a signature over bytes that no longer
 *      exist, and the refusal would come back hours later naming nothing anyone
 *      could act on.
 *
 *   4. A COUNTER THAT MOVES BACKWARDS, or an entry holding a position the
 *      counter has not yet spent. Together these are the Android outbox's
 *      "the counter is persisted, not derived" rule, enforced by the storage
 *      engine instead of by a convention: a derived counter restarts at zero
 *      once a queue drains and silently re-spends positions central already
 *      settled.
 * ============================================================================
 */

/** SQL string literal list, e.g. `'A', 'B'`. Values here are compile-time constants, never input. */
function sqlLiterals(values: readonly string[]): string {
  return values.map((value) => `'${value}'`).join(', ');
}

/**
 * THE ORDERING NAMESPACE, AND THE ONE PLACE IT IS WRITTEN DOWN.
 *
 * `(organisation_id, site_id, actor_user_id, device_id)` is not an invention:
 * it is central's `organisationId_siteId_userId_deviceId` offline cursor key,
 * copied exactly. Ordering inside it is by `device_sequence`, which WP-20 says
 * is contiguous, per-device and never reset.
 *
 * EDGE INVENTS NO GLOBAL ORDER, and the absence is load-bearing. A single
 * Edge-wide FIFO would make every site, every operative and every device share
 * one head of line, so one operation central cannot yet resolve would stall a
 * different site's duress signal — a coupling that does not exist anywhere in
 * the system today and that Edge would be adding for the convenience of having
 * one cursor.
 */
export const EDGE_QUEUE_NAMESPACE_COLUMNS = ['organisation_id', 'site_id', 'actor_user_id', 'device_id'] as const;

/**
 * EVERY COLUMN THE QUEUE PERSISTS, in the order the table declares them.
 *
 * Named as data, exactly as `OfflineOutboxEntry.PERSISTED_FIELDS` is on the
 * Android side and for the same reason: adding a field means adding a name
 * here, which is a visible, reviewable act, and `edge-queue.schema.spec.ts`
 * holds this list against a forbidden-word check AND against what the DDL
 * actually creates. The second half is the part the Android test cannot do —
 * here the list is proven to BE the schema, so it cannot drift into describing
 * a table that no longer exists.
 *
 * WHAT MUST NEVER APPEAR IN THIS LIST
 * -----------------------------------
 * No private key material. No bearer credential. No session credential. No
 * enrolment grant. The queue is the one structure on an Edge that is written to
 * disk and SURVIVES — across a restart, across a power cut, across the box
 * being carried out of the building — so it is exactly the structure into which
 * somebody would eventually tuck "the thing we need in order to send it later".
 *
 * There is nothing to tuck, and the schema is shaped so there is nowhere to
 * tuck it. The device signature is already made and travels in `envelope_json`.
 * The Edge receipt is already signed and travels in `receipt_json`. Forwarding
 * to central needs Edge's own credentials, which belong to whatever opens the
 * connection and are never an attribute of a queued row. Not one column below
 * is a place a secret would fit.
 *
 * WHY THE LIST NAMES SECRETS RATHER THAN THE WORD "KEY". `OfflineOutboxEntry`
 * had to permit `key_id` and `signature` because it flattens the envelope. This
 * schema composes the envelope instead, so no signed field is a column at all
 * and the words happen not to appear — but the guard still forbids SECRETS
 * specifically, because a list that forbade "key" would be proving a fact about
 * spelling rather than about what is on the disk.
 */
export const EDGE_QUEUE_OPERATION_COLUMNS = [
  /** The envelope's `offline_operation_id`. THE identity — there is no second key. */
  'offline_operation_id',
  'schema_version',
  /** The signed envelope, whole. COMPOSED, NOT FLATTENED — the frozen contract's rule. */
  'envelope_json',
  /** The canonical payload TEXT the device digested. Byte-preserved, never re-serialised. */
  'payload_canonical_json',
  /** Derived index. Verified against the envelope on every read. */
  'payload_digest',
  /** The Edge provenance receipt, or NULL when Edge had no trusted time to witness with. */
  'receipt_json',
  /** The four namespace columns. Derived index; see the read-time agreement check. */
  'organisation_id',
  'site_id',
  'actor_user_id',
  'device_id',
  /** Ordering within the namespace. Derived index. */
  'device_sequence',
  /** The authority the operation named. Derived index, for operator diagnosis. */
  'policy_lease_id',
  /** Edge's own monotonic position at enqueue. A witness ordinal, never a time. */
  'enqueued_edge_monotonic_position',
  'queue_state',
  /** Central's proven answer, or NULL. The only thing that may end an entry. */
  'settlement_json',
  'attempt_count',
  /** A fact about the wire. Never a verdict about the operation. */
  'failure_category',
  /** Durable monotonic milliseconds. NOT a wall clock — see `EdgeDurableMonotonicClock`. */
  'first_stored_monotonic_ms',
  'last_attempt_monotonic_ms',
  'next_attempt_monotonic_ms',
] as const;

/** Every column of the single-row counter table, in declaration order. */
export const EDGE_QUEUE_COUNTER_COLUMNS = [
  'id',
  'schema_version',
  /** Persisted, never derived. The Android outbox's first rule. */
  'next_edge_monotonic_position',
  /** The durable monotonic clock's high-water mark. Never a wall clock. */
  'last_observed_monotonic_ms',
  /** Aggregate link health, durable so six hours of WAN outage is still visible after a restart. */
  'consecutive_unknown_transport_results',
] as const;

export const EDGE_QUEUE_OPERATION_TABLE = 'edge_queued_operation';
export const EDGE_QUEUE_COUNTER_TABLE = 'edge_queue_counter';

/**
 * THE PRAGMAS, AND WHY `synchronous = FULL` RATHER THAN THE USUAL `NORMAL`.
 *
 * WAL is chosen for the ordinary reason — readers do not block the writer, and
 * a metrics scrape must never stall an enqueue. The durability setting is the
 * one worth arguing about.
 *
 * In WAL mode, `synchronous = NORMAL` does not fsync on every commit. It cannot
 * corrupt the database, and for almost every application it is the right
 * trade — but what it CAN do is lose the last few committed transactions when
 * the power goes. For this store those transactions are Field operations an
 * operative has already been told are safe. `FULL` costs one fsync per commit,
 * which on a queue measured in operations-per-minute is free, and it buys the
 * property the whole store exists for: once `admit()` has returned, the
 * operation is on the disk, and pulling the plug does not take it back.
 *
 * `foreign_keys` is on for completeness; there are no foreign keys, because the
 * counter is a singleton row rather than a parent, and a FK from every entry to
 * it would only add a way for a cascade to delete queued work.
 */
export const EDGE_QUEUE_PRAGMAS: readonly string[] = [
  'PRAGMA journal_mode = WAL',
  'PRAGMA synchronous = FULL',
  'PRAGMA foreign_keys = ON',
  // A second writer must wait rather than fail instantly; five seconds is far
  // longer than any transaction here and far shorter than a health probe.
  'PRAGMA busy_timeout = 5000',
];

/**
 * The whole schema, idempotent, applied on every open.
 *
 * `IF NOT EXISTS` everywhere so that opening an existing store is a no-op, and
 * the version check in the store — not this DDL — is what refuses a database
 * written by a different schema version. A box on a customer LAN does not
 * migrate itself.
 */
export const EDGE_QUEUE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS ${EDGE_QUEUE_COUNTER_TABLE} (
  -- One row, forever. The CHECK is what makes "the counter" a singular thing:
  -- a second counter row is a second sequence namespace, and the two would
  -- hand out the same position to different entries.
  id INTEGER PRIMARY KEY CHECK (id = 1),
  schema_version INTEGER NOT NULL,
  next_edge_monotonic_position INTEGER NOT NULL
    CHECK (next_edge_monotonic_position >= 0 AND next_edge_monotonic_position <= ${EDGE_QUEUE_MAX_MONOTONIC_POSITION}),
  last_observed_monotonic_ms INTEGER NOT NULL CHECK (last_observed_monotonic_ms >= 0),
  consecutive_unknown_transport_results INTEGER NOT NULL CHECK (consecutive_unknown_transport_results >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS ${EDGE_QUEUE_OPERATION_TABLE} (
  offline_operation_id TEXT PRIMARY KEY NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = ${EDGE_QUEUE_SCHEMA_VERSION}),

  -- The signed envelope, whole and unflattened. json_valid rather than a bare
  -- TEXT so a truncated write is refused by the engine rather than discovered
  -- at reconnect.
  envelope_json TEXT NOT NULL CHECK (json_valid(envelope_json)),

  -- The canonical payload TEXT. Deliberately NOT validated as JSON-with-an-
  -- opinion and never normalised: the contract's refinement re-canonicalises it
  -- and re-digests it on every read, and a store that "helpfully" reordered
  -- keys would produce a PAYLOAD_DIGEST_MISMATCH nobody could reconstruct.
  payload_canonical_json TEXT NOT NULL CHECK (length(payload_canonical_json) >= 2),

  payload_digest TEXT NOT NULL CHECK (length(payload_digest) > 0),
  receipt_json TEXT CHECK (receipt_json IS NULL OR json_valid(receipt_json)),

  organisation_id TEXT NOT NULL CHECK (length(organisation_id) > 0),
  site_id TEXT NOT NULL CHECK (length(site_id) > 0),
  actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) > 0),
  device_id TEXT NOT NULL CHECK (length(device_id) > 0),
  device_sequence INTEGER NOT NULL
    CHECK (device_sequence >= 0 AND device_sequence <= ${EDGE_QUEUE_MAX_MONOTONIC_POSITION}),
  policy_lease_id TEXT NOT NULL CHECK (length(policy_lease_id) > 0),

  enqueued_edge_monotonic_position INTEGER NOT NULL
    CHECK (enqueued_edge_monotonic_position >= 0 AND enqueued_edge_monotonic_position <= ${EDGE_QUEUE_MAX_MONOTONIC_POSITION}),

  queue_state TEXT NOT NULL CHECK (queue_state IN (${sqlLiterals(EDGE_QUEUE_STATES)})),
  settlement_json TEXT CHECK (settlement_json IS NULL OR json_valid(settlement_json)),

  attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
  failure_category TEXT CHECK (failure_category IS NULL OR failure_category IN (${sqlLiterals(EDGE_QUEUE_FAILURE_CATEGORIES)})),

  first_stored_monotonic_ms INTEGER NOT NULL CHECK (first_stored_monotonic_ms >= 0),
  last_attempt_monotonic_ms INTEGER CHECK (last_attempt_monotonic_ms IS NULL OR last_attempt_monotonic_ms >= 0),
  next_attempt_monotonic_ms INTEGER NOT NULL CHECK (next_attempt_monotonic_ms >= 0),

  -- ------------------------------------------------------------------------
  -- NO LOCAL STATE MAY FALSELY MEAN CENTRAL COMMITTED.
  --
  -- The settled states and the presence of central's answer are made EXACTLY
  -- EQUIVALENT, in both directions. A CENTRAL_APPLIED row with no settlement is
  -- Edge having decided something on its own; a QUEUED-mapped row that carries
  -- an answer is an entry that will be re-sent after central already ruled.
  -- This is the frozen contract's own superRefine, restated where a writer that
  -- never touches TypeScript still has to obey it.
  -- ------------------------------------------------------------------------
  CONSTRAINT edge_queue_settlement_matches_state
    CHECK ((queue_state IN (${sqlLiterals(EDGE_QUEUE_SETTLED_STATES)})) = (settlement_json IS NOT NULL)),

  -- ------------------------------------------------------------------------
  -- AND THE ANSWER MUST BE THE RIGHT KIND OF ANSWER.
  --
  -- The check above stops a settled row with no evidence. This one stops a
  -- settled row whose evidence says something else: CENTRAL_APPLIED demands an
  -- answer whose outcome is literally CENTRAL_ACCEPTED, FAILED_TERMINAL one
  -- whose outcome is CENTRAL_REFUSED. Without it, an "applied" row could be
  -- justified by a refusal, which is the most dangerous possible mislabelling —
  -- an operation central REJECTED, shown locally as committed.
  -- ------------------------------------------------------------------------
  CONSTRAINT edge_queue_settlement_proves_state
    CHECK (
      (queue_state <> 'CENTRAL_APPLIED' OR json_extract(settlement_json, '$.outcome') = 'CENTRAL_ACCEPTED')
      AND (queue_state <> 'FAILED_TERMINAL' OR json_extract(settlement_json, '$.outcome') = 'CENTRAL_REFUSED')
    ),

  -- ------------------------------------------------------------------------
  -- CENTRAL'S WORD AND EDGE'S EXCUSE ARE NEVER BOTH ON THE SAME ROW, AND AN
  -- ENTRY CENTRAL HAS SAID NOTHING ABOUT ALWAYS CARRIES THE EXCUSE.
  --
  -- Two halves, and each names a different defect.
  --
  -- NEVER BOTH: a row that holds central's answer AND a transport failure can
  -- be described two contradictory ways depending on which column a reader
  -- reaches for, and the one that gets read on a bad night is the one that
  -- sends a settled operation again.
  --
  -- NEVER NEITHER, while central has said nothing: a row with no answer and no
  -- reason is an entry about which nothing whatsoever can be said. That is how
  -- an operation goes quiet — it is not failing, it is not progressing, and no
  -- dashboard has a word for it, so nobody chases it. Every unacknowledged row
  -- must state, in the frozen wire vocabulary, why Edge has no answer yet.
  -- ------------------------------------------------------------------------
  CONSTRAINT edge_queue_answer_or_reason
    CHECK (
      (settlement_json IS NULL OR failure_category IS NULL)
      AND (queue_state IN (${sqlLiterals(EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES)}) OR failure_category IS NOT NULL)
    )
) STRICT;

-- The forwarding index: the head of each namespace, cheaply. PARTIAL, on the
-- unsettled rows only, because settled rows are retained provenance and must
-- never be considered for forwarding again.
CREATE INDEX IF NOT EXISTS edge_queue_unsettled_namespace_order
  ON ${EDGE_QUEUE_OPERATION_TABLE} (${EDGE_QUEUE_NAMESPACE_COLUMNS.join(', ')}, device_sequence)
  WHERE settlement_json IS NULL;

-- TWO ENVELOPES FOR ONE POSITION ARE UNSTORABLE.
--
-- WP-20's cursor refuses to step over a position it has not seen, so a device
-- position is spent exactly once. A second operation claiming a position this
-- namespace already holds is either a client bug or a replay, and both are
-- better refused at the door than forwarded for central to disentangle.
CREATE UNIQUE INDEX IF NOT EXISTS edge_queue_one_operation_per_position
  ON ${EDGE_QUEUE_OPERATION_TABLE} (${EDGE_QUEUE_NAMESPACE_COLUMNS.join(', ')}, device_sequence);

-- Reclamation and metrics both sweep by state; retention sweeps the settled
-- rows oldest-first.
CREATE INDEX IF NOT EXISTS edge_queue_state_age
  ON ${EDGE_QUEUE_OPERATION_TABLE} (queue_state, first_stored_monotonic_ms);

-- ---------------------------------------------------------------------------
-- AN OPERATION CENTRAL HAS NOT ANSWERED CANNOT BE DELETED. BY ANYONE.
--
-- This is the capacity policy's teeth. Reclaiming space, tidying a queue,
-- clearing a "stuck" entry, a cleanup script with a WHERE clause that matched
-- more than its author expected — every one of them aborts here. The only rows
-- that can leave this table are rows central has ruled on, whose evidence lives
-- at central anyway.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_no_unsettled_delete
BEFORE DELETE ON ${EDGE_QUEUE_OPERATION_TABLE}
FOR EACH ROW WHEN OLD.settlement_json IS NULL
BEGIN
  SELECT RAISE(ABORT, 'edge queue: an operation central has not answered may not be deleted');
END;

-- ---------------------------------------------------------------------------
-- CENTRAL'S ANSWER IS FINAL.
--
-- A settled row is immutable. Not "should not be changed" — cannot be. The
-- defect this prevents is an entry being un-settled and re-forwarded, which
-- produces a second effect for one act by an operative.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_settlement_is_final
BEFORE UPDATE ON ${EDGE_QUEUE_OPERATION_TABLE}
FOR EACH ROW WHEN OLD.settlement_json IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'edge queue: central has answered this operation and its record is final');
END;

-- ---------------------------------------------------------------------------
-- THE SIGNED BYTES, AND THE POSITION THEY WERE STORED AT, ARE IMMUTABLE.
--
-- The device signature covers the envelope. An UPDATE that altered one byte of
-- it leaves a signature over bytes that no longer exist, and the refusal comes
-- back hours later as SIGNATURE_NOT_VERIFIED — the least diagnosable refusal
-- there is. Local bookkeeping columns are freely updatable; nothing that was
-- signed, and nothing that identifies the entry, is.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_signed_bytes_immutable
BEFORE UPDATE ON ${EDGE_QUEUE_OPERATION_TABLE}
FOR EACH ROW WHEN
  NEW.offline_operation_id <> OLD.offline_operation_id
  OR NEW.envelope_json <> OLD.envelope_json
  OR NEW.payload_canonical_json <> OLD.payload_canonical_json
  OR NEW.payload_digest <> OLD.payload_digest
  OR NEW.organisation_id <> OLD.organisation_id
  OR NEW.site_id <> OLD.site_id
  OR NEW.actor_user_id <> OLD.actor_user_id
  OR NEW.device_id <> OLD.device_id
  OR NEW.device_sequence <> OLD.device_sequence
  OR NEW.policy_lease_id <> OLD.policy_lease_id
  OR NEW.enqueued_edge_monotonic_position <> OLD.enqueued_edge_monotonic_position
  OR NEW.first_stored_monotonic_ms <> OLD.first_stored_monotonic_ms
BEGIN
  SELECT RAISE(ABORT, 'edge queue: the signed envelope and the identity of a stored operation are immutable');
END;

-- ---------------------------------------------------------------------------
-- THE EDGE RECEIPT IS WRITE-ONCE.
--
-- receipt is nullable in the frozen contract and null is a FIRST-CLASS,
-- CORRECT outcome: with no valid trusted-time anchor Edge has nothing truthful
-- to put in edge_trusted_time, and central fails the operation closed at
-- NO_TRUSTWORTHY_TIME_WITNESS. So an entry may acquire a receipt it did not
-- have. What it may never do is have one REPLACED or CLEARED: the receipt is
-- signed over this exact operation's fingerprint and Edge's monotonic position,
-- and swapping one for another is how a witness ends up filed against the wrong
-- operation — WITNESS_FINGERPRINT_MISMATCH, discovered at reconciliation.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_receipt_is_write_once
BEFORE UPDATE ON ${EDGE_QUEUE_OPERATION_TABLE}
FOR EACH ROW WHEN
  OLD.receipt_json IS NOT NULL AND (NEW.receipt_json IS NULL OR NEW.receipt_json <> OLD.receipt_json)
BEGIN
  SELECT RAISE(ABORT, 'edge queue: an Edge receipt is written once and never replaced');
END;

-- ---------------------------------------------------------------------------
-- THE COUNTER NEVER MOVES BACKWARDS.
--
-- "The counter is persisted, not derived" is the Android outbox's first rule,
-- and this is the failure it names: a counter that has moved backwards hands
-- out a position it already spent, and the device sends a perfectly valid
-- envelope for work central settled hours ago. Same for the durable monotonic
-- clock, whose entire value is that it only ever increases.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_counter_never_rewinds
BEFORE UPDATE ON ${EDGE_QUEUE_COUNTER_TABLE}
FOR EACH ROW WHEN
  NEW.next_edge_monotonic_position < OLD.next_edge_monotonic_position
  OR NEW.last_observed_monotonic_ms < OLD.last_observed_monotonic_ms
BEGIN
  SELECT RAISE(ABORT, 'edge queue: the monotonic counter and clock may not move backwards');
END;

-- ---------------------------------------------------------------------------
-- NOTHING IS STORED AT A POSITION THE COUNTER HAS NOT YET SPENT.
--
-- The mirror of the rule above, and the reason the store advances the counter
-- BEFORE inserting the row inside one transaction: this trigger makes that
-- order mandatory rather than customary. An entry at or beyond the counter is
-- the exact condition the Android load() refuses to operate on, caught here
-- one layer earlier — at the write, where it can still be prevented.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS edge_queue_position_below_counter
BEFORE INSERT ON ${EDGE_QUEUE_OPERATION_TABLE}
FOR EACH ROW WHEN
  NEW.enqueued_edge_monotonic_position >= (SELECT next_edge_monotonic_position FROM ${EDGE_QUEUE_COUNTER_TABLE} WHERE id = 1)
BEGIN
  SELECT RAISE(ABORT, 'edge queue: refusing an entry at or beyond the next monotonic position');
END;
`;
