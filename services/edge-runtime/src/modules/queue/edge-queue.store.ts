import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync, type SQLOutputValue } from 'node:sqlite';
import { Logger } from '@nestjs/common';
import {
  EdgeQueueMetricsSchema,
  EdgeStoredOperationSchema,
  EdgeTransportResultSchema,
  type DeviceEdgeReceipt,
  type DeviceOfflineOperationEnvelope,
  type EdgeQueueMetrics,
  type EdgeStoredOperation,
} from '@sentinel/contracts';
import {
  EDGE_QUEUE_DATABASE_FILENAME,
  EDGE_QUEUE_DEGRADED_FRACTION,
  EDGE_QUEUE_MAX_MONOTONIC_POSITION,
  EDGE_QUEUE_MAX_UNSETTLED,
  EDGE_QUEUE_SCHEMA_VERSION,
  EDGE_QUEUE_SETTLED_RETENTION,
  edgeQueueRetryDelayMs,
} from './edge-queue.constants';
import {
  EDGE_QUEUE_COUNTER_TABLE,
  EDGE_QUEUE_OPERATION_TABLE,
  EDGE_QUEUE_PRAGMAS,
  EDGE_QUEUE_SCHEMA_SQL,
} from './edge-queue.schema';
import {
  EDGE_QUEUE_CRASH_INTERRUPTED_STATE,
  EDGE_QUEUE_CRASH_RECOVERY_CATEGORY,
  EDGE_QUEUE_FORWARDABLE_STATES,
  EDGE_QUEUE_INITIAL_FAILURE_CATEGORY,
  EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY,
  canTransitionEdgeQueueState,
  isEdgeQueueSettledState,
  toEdgeOperationState,
  type EdgeQueueFailureCategory,
  type EdgeQueueState,
  type EdgeTransportTerminalAnswer,
} from './edge-queue.state';

/**
 * ============================================================================
 * WP-29B / LANE B — THE EDGE-LOCAL DURABLE OPERATION STORE.
 *
 * The policy half of the queue. The storage engine is SQLite through
 * `node:sqlite`; the argument for that choice, and the argument for every CHECK
 * and TRIGGER it relies on, is in `edge-queue.schema.ts`.
 *
 * THE THREE RULES THIS CLASS INHERITS FROM `OfflineOutbox`
 * -------------------------------------------------------
 * The Android outbox is the specification for this file, and its three rules
 * transplant without modification because the defect each one prevents is a
 * property of durable queues rather than of handsets:
 *
 *   1. THE COUNTER IS PERSISTED, NOT DERIVED. `next_edge_monotonic_position`
 *      lives in `edge_queue_counter`. It is emphatically NOT computed as
 *      `MAX(enqueued_edge_monotonic_position) + 1`, because settled entries are
 *      eventually reclaimed: a queue that has fully drained holds no rows at
 *      all, and a derived counter would restart at zero and re-spend every
 *      position it had already issued. Those positions go into
 *      `DeviceEdgeReceipt.edge_monotonic_position`, which is inside Edge's
 *      signature, so re-spending one produces two differently-signed receipts
 *      claiming the same place in Edge's own history — and the second is
 *      indistinguishable from a forgery.
 *
 *   2. THE COUNTER AND THE ENTRY ARE WRITTEN TOGETHER, OR NEITHER IS. One
 *      `BEGIN IMMEDIATE` transaction covers the counter advance and the insert.
 *      A crash cannot land the increment without the entry (a burnt position)
 *      or the entry without the increment (two entries, one position).
 *
 *   3. NOTHING IS ALLOCATED THAT IS NOT ENQUEUED. There is no public
 *      `allocate()`. Every refusal — duplicate id, occupied device position,
 *      capacity, exhausted position space — happens BEFORE the draw, and if the
 *      caller's witness callback throws after the draw, the transaction rolls
 *      back and the counter is untouched.
 *
 * WHY THERE IS NO IN-MEMORY COPY OF THE QUEUE
 * -------------------------------------------
 * Same reason the Android outbox holds none, and it survives the change of
 * storage engine: A FAILED WRITE MUST LEAVE NOTHING AHEAD OF DISK. A position
 * cached in RAM, a write that failed, and the next allocation handing out the
 * same number is the ugliest defect available here. Every method below reads
 * the database and writes the database; SQLite's own page cache is the only
 * cache, and it is coherent with the file by construction.
 *
 * The one piece of process state is the durable monotonic clock's base, and it
 * is derived FROM the database at open and only ever moves forward — see
 * `durableNowMs`.
 * ============================================================================
 */

/**
 * A clock that only ever moves forward and has no opinion about what time it
 * is.
 *
 * Deliberately not a wall clock, and the store has no wall clock anywhere.
 * `EdgeQueueMetrics.oldest_queued_monotonic_age_ms` is specified as monotonic
 * "deliberately: this number must stay meaningful on an Edge that has no
 * trusted time at all", and the same argument applies to every timestamp the
 * queue keeps. A host wall clock on a box in a wiring closet is settable by
 * anyone who can reach the box; storing one in a column called
 * `first_stored_at` would produce a value that LOOKS like evidence, gets read
 * as evidence, and is worth nothing.
 *
 * So the columns are named `*_monotonic_ms` and nothing downstream can mistake
 * one for a time of day.
 */
export interface EdgeMonotonicClock {
  /** Milliseconds since an arbitrary, process-local origin. Never decreases. */
  nowMs(): number;
}

/** The default: the process's own high-resolution monotonic clock. */
export const systemEdgeMonotonicClock: EdgeMonotonicClock = {
  nowMs: () => Math.floor(performance.now()),
};

/**
 * The stored queue cannot be read as a queue.
 *
 * THROWN, NEVER RECOVERED FROM BY EMPTYING THE STORE. This is the Android
 * `MalformedOutbox` ruling and it is the most important error in the file: a
 * corrupt, truncated or version-mismatched database must not be answered with
 * "empty queue, position zero", because that silently resets the counter and
 * re-issues every position Edge already spent. Refusing to operate is
 * recoverable — the readiness probe goes down, an operator looks at the box.
 * Quietly restarting the count is not recoverable, because nobody finds out.
 */
export class MalformedEdgeQueueError extends Error {
  constructor(message: string) {
    super(`edge queue: ${message}`);
    this.name = 'MalformedEdgeQueueError';
  }
}

/**
 * A caller asked for a state change the model does not permit.
 *
 * A THROW RATHER THAN A `false`, because an illegal transition is a bug in the
 * forwarder, not a condition it can encounter. Above all this is what a caller
 * meets if it tries to record a central answer for an entry that was never
 * forwarded — a reply to a question nobody asked.
 */
export class EdgeQueueTransitionError extends Error {
  constructor(from: EdgeQueueState, to: EdgeQueueState) {
    super(`edge queue: ${from} may not become ${to}`);
    this.name = 'EdgeQueueTransitionError';
  }
}

/** The operation offered for storage is not one this store can hold intact. */
export class EdgeQueueOperationNotStorableError extends Error {
  constructor(message: string, readonly detail?: unknown) {
    super(`edge queue: ${message}`);
    this.name = 'EdgeQueueOperationNotStorableError';
  }
}

/**
 * One row, as the runtime reads it: the frozen stored shape, plus the local
 * bookkeeping the frozen shape deliberately does not carry.
 *
 * The split is the point. `stored` is `EdgeStoredOperation` and is what gets
 * forwarded and reasoned about; everything beside it is Edge's own record of
 * what it has tried, is not signed, is not sent, and is not authority.
 */
export interface EdgeQueueEntry {
  readonly stored: EdgeStoredOperation;
  /** Operational detail inside the frozen `stored.state`. See `edge-queue.state.ts`. */
  readonly queueState: EdgeQueueState;
  readonly attemptCount: number;
  /** Why Edge has no answer from central yet. Null once central has spoken. */
  readonly failureCategory: EdgeQueueFailureCategory | null;
  readonly firstStoredMonotonicMs: number;
  readonly lastAttemptMonotonicMs: number | null;
  readonly nextAttemptMonotonicMs: number;
}

/**
 * Why an admission did or did not take.
 *
 * EVERY REFUSAL IS NAMED AND RETURNED. There is no outcome that means "we
 * dropped it", and there is no code path that admits an operation by removing
 * another. A caller that receives anything but `ADMITTED` has NOT had its work
 * stored, and must say so to whoever handed it the operation — an ingress that
 * answered 202 on `AT_CAPACITY` would be telling a Field device its work is
 * safe when the store refused it.
 */
export type EdgeQueueAdmission =
  | { readonly outcome: 'ADMITTED'; readonly entry: EdgeQueueEntry }
  /** This exact operation is already stored. A retrying device is expected to do this. */
  | { readonly outcome: 'DUPLICATE_OPERATION_ID' }
  /** A DIFFERENT operation already holds this device position. See the unique index. */
  | { readonly outcome: 'SEQUENCE_POSITION_ALREADY_HELD' }
  | { readonly outcome: 'AT_CAPACITY'; readonly unsettled: number; readonly capacity: number }
  | { readonly outcome: 'POSITION_SPACE_EXHAUSTED' };

/**
 * How much room is left, as a state rather than as a number a caller has to
 * interpret.
 *
 * DEGRADED_NEAR_CAPACITY is the one that earns its place: it is the only chance
 * anybody gets to notice before a Field operation is refused. An Edge that goes
 * straight from healthy to refusing tells its operator about saturation through
 * a complaint from the site.
 */
export type EdgeQueueCapacityState = 'ACCEPTING' | 'DEGRADED_NEAR_CAPACITY' | 'REFUSING_AT_CAPACITY';

/** Central progress that is NOT an answer. There is no `APPLIED` here, on purpose. */
export type EdgeCentralProgress = 'CENTRAL_RECEIVED' | 'CENTRAL_APPLYING';

export interface EdgeQueueAdmissionInput {
  /** The device-signed envelope, whole. Its `offline_operation_id` is the entry's identity. */
  readonly envelope: DeviceOfflineOperationEnvelope;
  /** The canonical JSON TEXT the device digested. Stored byte for byte. */
  readonly payloadCanonicalJson: string;
  /**
   * Mints the Edge receipt for this operation, GIVEN THE POSITION THE STORE HAS
   * JUST ALLOCATED.
   *
   * A callback rather than a finished receipt, and for the same reason
   * `OfflineOutbox.enqueue` takes a lambda: `edge_monotonic_position` is inside
   * the receipt's signature, so the caller cannot sign before the store has
   * decided the position, and the store must not decide the position before it
   * has checked that the operation is one it will accept. Handing the number to
   * the minter inside the transaction closes the loop with no window in which a
   * position is spent but nothing was written.
   *
   * Returning `null` — or omitting the callback — is a FIRST-CLASS, CORRECT
   * outcome, not a gap: an Edge with no valid trusted-time anchor has nothing
   * truthful to put in `edge_trusted_time`, central fails the operation closed
   * at NO_TRUSTWORTHY_TIME_WITNESS, and that refusal is the designed behaviour.
   * An Edge that manufactured a receipt from its host wall clock would convert a
   * visible refusal into an invisible forgery.
   */
  readonly witness?: (edgeMonotonicPosition: number) => DeviceEdgeReceipt | null;
}

export interface EdgeQueueStoreOptions {
  /** The directory `EDGE_QUEUE_PATH` names. The database file is created inside it. */
  readonly directory: string;
  readonly clock?: EdgeMonotonicClock;
  /**
   * TEST SEAM, NOT CONFIGURATION. There is no environment variable for either
   * bound and there must never be one — see `edge-queue.constants.ts`. A spec
   * that wants to prove a full queue refuses cannot afford to store four
   * thousand fsync'd operations to get there.
   */
  readonly maxUnsettled?: number;
  readonly settledRetention?: number;
}

interface CounterRow {
  readonly schemaVersion: number;
  readonly nextPosition: number;
  readonly lastObservedMonotonicMs: number;
  readonly consecutiveUnknown: number;
}

const SELECT_ENTRY_COLUMNS = `
  offline_operation_id, envelope_json, payload_canonical_json, payload_digest, receipt_json,
  organisation_id, site_id, actor_user_id, device_id, device_sequence, policy_lease_id,
  enqueued_edge_monotonic_position, queue_state, settlement_json, attempt_count, failure_category,
  first_stored_monotonic_ms, last_attempt_monotonic_ms, next_attempt_monotonic_ms
`;

function requireText(row: Record<string, SQLOutputValue>, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw new MalformedEdgeQueueError(`'${column}' is not readable text`);
  return value;
}

function optionalText(row: Record<string, SQLOutputValue>, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw new MalformedEdgeQueueError(`'${column}' is not readable text`);
  return value;
}

function requireInteger(row: Record<string, SQLOutputValue>, column: string): number {
  const value = row[column];
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  if (typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  throw new MalformedEdgeQueueError(`'${column}' is not a readable integer`);
}

function optionalInteger(row: Record<string, SQLOutputValue>, column: string): number | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  return requireInteger(row, column);
}

function parseJsonColumn(text: string, column: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new MalformedEdgeQueueError(`'${column}' is not readable JSON`);
  }
}

export class SqliteEdgeOperationStore {
  private readonly logger = new Logger(SqliteEdgeOperationStore.name);
  private readonly db: DatabaseSync;
  private readonly clock: EdgeMonotonicClock;
  private readonly maxUnsettled: number;
  private readonly settledRetention: number;

  /**
   * The durable monotonic clock's two halves.
   *
   * `base` is the high-water mark read out of the database at open; `origin` is
   * the process clock's reading at that same instant. `durableNowMs` is
   * `base + (now - origin)`, so the value resumes where the last process left
   * it instead of restarting at zero. Without this, every restart would make
   * every stored entry look freshly enqueued and
   * `oldest_queued_monotonic_age_ms` would reset to nothing — hiding exactly the
   * backlog an operator restarts the service to investigate.
   *
   * THE HONEST LIMIT, STATED SO NOBODY DISCOVERS IT LATER: time spent powered
   * off is invisible to this clock. Ages are therefore LOWER BOUNDS. That is
   * the correct trade for a store that must never consult a wall clock, and a
   * lower bound on a backlog age is a number an operator can act on; a host
   * clock reading is not.
   */
  private readonly origin: number;
  private readonly base: number;

  constructor(options: EdgeQueueStoreOptions) {
    this.clock = options.clock ?? systemEdgeMonotonicClock;
    this.maxUnsettled = options.maxUnsettled ?? EDGE_QUEUE_MAX_UNSETTLED;
    this.settledRetention = options.settledRetention ?? EDGE_QUEUE_SETTLED_RETENTION;

    mkdirSync(options.directory, { recursive: true });
    this.db = new DatabaseSync(join(options.directory, EDGE_QUEUE_DATABASE_FILENAME));
    for (const pragma of EDGE_QUEUE_PRAGMAS) this.db.exec(pragma);
    this.db.exec(EDGE_QUEUE_SCHEMA_SQL);

    // The counter row is created exactly once, at the first open, and never
    // again. `INSERT OR IGNORE` rather than an existence check because the two
    // are the same statement here and only one of them has a race.
    this.db
      .prepare(
        `INSERT OR IGNORE INTO ${EDGE_QUEUE_COUNTER_TABLE}
           (id, schema_version, next_edge_monotonic_position, last_observed_monotonic_ms, consecutive_unknown_transport_results)
         VALUES (1, ?, 0, 0, 0)`,
      )
      .run(EDGE_QUEUE_SCHEMA_VERSION);

    const counter = this.readCounter();
    if (counter.schemaVersion !== EDGE_QUEUE_SCHEMA_VERSION) {
      this.db.close();
      throw new MalformedEdgeQueueError(
        `the stored queue is schema version ${counter.schemaVersion}, not ${EDGE_QUEUE_SCHEMA_VERSION}; a box on a site LAN does not migrate itself`,
      );
    }

    this.origin = this.clock.nowMs();
    this.base = counter.lastObservedMonotonicMs;

    this.assertCounterAheadOfEveryEntry(counter.nextPosition);
    this.recoverInterruptedAttempts();
  }

  // -------------------------------------------------------------------------
  // Opening: refuse a queue that cannot be trusted, then repair what a crash
  // provably left behind — and NOTHING more.
  // -------------------------------------------------------------------------

  /**
   * The Android `load()` integrity rule, run against the whole table.
   *
   * An entry at or beyond the counter means the counter has moved BACKWARDS at
   * some point, which is the precise condition that leads to a re-used
   * position. It is refused here, loudly, rather than allowed to produce a
   * duplicate receipt later. (The `edge_queue_position_below_counter` trigger
   * makes this unreachable through any writer that obeys SQL; this check is
   * what catches a file that arrived some other way — restored from a backup
   * taken mid-write, or edited.)
   */
  private assertCounterAheadOfEveryEntry(nextPosition: number): void {
    const row = this.db
      .prepare(`SELECT MAX(enqueued_edge_monotonic_position) AS highest FROM ${EDGE_QUEUE_OPERATION_TABLE}`)
      .get();
    const highest = row === undefined ? null : optionalInteger(row, 'highest');
    if (highest !== null && highest >= nextPosition) {
      this.db.close();
      throw new MalformedEdgeQueueError(
        `a stored entry holds monotonic position ${highest}, at or beyond the next position ${nextPosition}`,
      );
    }
  }

  /**
   * WHAT A CRASH LEAVES BEHIND, AND THE ONLY HONEST THING TO DO WITH IT.
   *
   * A row in FORWARDING means an attempt was in flight when the process died.
   * Central may have received it, may have applied it, or may never have seen a
   * byte — that is UNKNOWN, and it is the one interpretation that is true in
   * every case.
   *
   * WHAT THIS SWEEP DELIBERATELY DOES NOT TOUCH:
   *
   *   `attempt_count` and `next_attempt_monotonic_ms` are left exactly as
   *   `claimForForwarding` wrote them BEFORE the request went out. That
   *   write-ahead is what makes a crash safe here: an attempt that was made but
   *   not recorded is an attempt the backoff cannot see, and an Edge that came
   *   back from a crash with a reset backoff would hammer central with the same
   *   operation at full rate — turning one bad night into a self-inflicted
   *   outage on the link it is waiting for.
   *
   *   `failure_category` is likewise already `TRANSPORT_ERROR`, written ahead
   *   of the attempt for the same reason. The sweep asserts it rather than
   *   setting it, so a row that says something else is a signal that some other
   *   writer has been here.
   *
   *   `consecutive_unknown_transport_results` is NOT incremented. That gauge
   *   distinguishes "the WAN is down" from "central is refusing our work", and a
   *   process crash is a fact about neither. Counting it would make a restart
   *   look like a link failure to whoever is watching.
   */
  private recoverInterruptedAttempts(): void {
    const changes = this.db
      .prepare(
        `UPDATE ${EDGE_QUEUE_OPERATION_TABLE}
            SET queue_state = ?, failure_category = ?
          WHERE queue_state = ? AND settlement_json IS NULL`,
      )
      .run(
        EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY[EDGE_QUEUE_CRASH_RECOVERY_CATEGORY],
        EDGE_QUEUE_CRASH_RECOVERY_CATEGORY,
        EDGE_QUEUE_CRASH_INTERRUPTED_STATE,
      ).changes;
    if (Number(changes) > 0) {
      // Aggregate only. A per-entry line here would be a per-device activity
      // trace in a log file, which is the WP-18 rule applied to diagnostics.
      this.logger.warn(`${changes} in-flight operation(s) resumed as UNKNOWN after an interrupted attempt`);
    }
  }

  // -------------------------------------------------------------------------
  // The durable monotonic clock
  // -------------------------------------------------------------------------

  /** Never decreases, within a process or across restarts. Never a time of day. */
  durableNowMs(): number {
    const elapsed = Math.max(0, this.clock.nowMs() - this.origin);
    return this.base + elapsed;
  }

  /**
   * Advances the persisted high-water mark.
   *
   * `MAX()` in SQL rather than a bare assignment, so the statement is safe even
   * if a caller's clock went sideways; the `edge_queue_counter_never_rewinds`
   * trigger would abort the transaction otherwise, taking a legitimate enqueue
   * down with it.
   */
  private markClock(): void {
    const now = this.durableNowMs();
    this.db
      .prepare(
        `UPDATE ${EDGE_QUEUE_COUNTER_TABLE}
            SET last_observed_monotonic_ms = MAX(last_observed_monotonic_ms, ?)
          WHERE id = 1`,
      )
      .run(now);
  }

  // -------------------------------------------------------------------------
  // Transactions
  // -------------------------------------------------------------------------

  /**
   * The ONE transaction wrapper. `BEGIN IMMEDIATE` rather than a deferred
   * `BEGIN`: the write lock is taken up front, so a second writer waits at the
   * start instead of failing halfway through with `SQLITE_BUSY` after it has
   * already decided what to write.
   *
   * A rollback that itself fails is logged and swallowed — the original error is
   * the one worth propagating, and masking it with a rollback error is how the
   * actual cause of a bad night disappears.
   */
  private transact<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    let result: T;
    try {
      result = work();
    } catch (error) {
      try {
        this.db.exec('ROLLBACK');
      } catch (rollbackError) {
        this.logger.error(`rollback failed: ${String(rollbackError)}`);
      }
      throw error;
    }
    this.db.exec('COMMIT');
    return result;
  }

  private readCounter(): CounterRow {
    const row = this.db
      .prepare(
        `SELECT schema_version, next_edge_monotonic_position, last_observed_monotonic_ms, consecutive_unknown_transport_results
           FROM ${EDGE_QUEUE_COUNTER_TABLE} WHERE id = 1`,
      )
      .get();
    if (row === undefined) throw new MalformedEdgeQueueError('the stored queue has no counter row');
    return {
      schemaVersion: requireInteger(row, 'schema_version'),
      nextPosition: requireInteger(row, 'next_edge_monotonic_position'),
      lastObservedMonotonicMs: requireInteger(row, 'last_observed_monotonic_ms'),
      consecutiveUnknown: requireInteger(row, 'consecutive_unknown_transport_results'),
    };
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  /**
   * ONE ROW BECOMES ONE `EdgeStoredOperation`, AND THE CONTRACT RE-VERIFIES IT
   * ON THE WAY OUT.
   *
   * `EdgeStoredOperationSchema.parse` is not ceremony on a read path. Its
   * refinement re-canonicalises `payload_canonical_json` and re-digests it
   * against the value inside the device signature, so bit rot, a partial write
   * or a hand edit of the queue file is caught HERE — at the parse boundary, on
   * this box, where it can be reported — rather than hours later at
   * reconciliation as a PAYLOAD_DIGEST_MISMATCH nobody can reconstruct.
   *
   * THE DERIVED COLUMNS ARE AN INDEX, NOT A SECOND SOURCE OF TRUTH.
   * `EdgeStoredOperationSchema` composes the envelope and never flattens it,
   * for the stated reason that a convenience copy of a signed field is a second
   * place to read it from and the two will eventually disagree. This table
   * nevertheless has `device_id`, `device_sequence` and the rest as columns,
   * because a namespace head query cannot parse every row's JSON to find one
   * entry. The reconciliation is that they are WRITTEN from the envelope in one
   * place and CHECKED against the envelope on every read: a column that has
   * drifted — or been edited to point an entry at another device — makes the
   * row unreadable rather than making it lie.
   */
  private toEntry(row: Record<string, SQLOutputValue>): EdgeQueueEntry {
    const envelopeJson = requireText(row, 'envelope_json');
    const envelope = parseJsonColumn(envelopeJson, 'envelope_json');
    const receiptJson = optionalText(row, 'receipt_json');
    const settlementJson = optionalText(row, 'settlement_json');
    const queueState = requireText(row, 'queue_state') as EdgeQueueState;

    let stored: EdgeStoredOperation;
    try {
      stored = EdgeStoredOperationSchema.parse({
        schema_version: EDGE_QUEUE_SCHEMA_VERSION,
        envelope,
        payload_canonical_json: requireText(row, 'payload_canonical_json'),
        receipt: receiptJson === null ? null : parseJsonColumn(receiptJson, 'receipt_json'),
        enqueued_edge_monotonic_position: requireInteger(row, 'enqueued_edge_monotonic_position'),
        state: toEdgeOperationState(queueState),
        settlement: settlementJson === null ? null : parseJsonColumn(settlementJson, 'settlement_json'),
      });
    } catch (error) {
      throw new MalformedEdgeQueueError(
        `a stored entry no longer satisfies the frozen contract: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    this.assertDerivedColumnsAgree(row, stored);

    return {
      stored,
      queueState,
      attemptCount: requireInteger(row, 'attempt_count'),
      failureCategory: optionalText(row, 'failure_category') as EdgeQueueFailureCategory | null,
      firstStoredMonotonicMs: requireInteger(row, 'first_stored_monotonic_ms'),
      lastAttemptMonotonicMs: optionalInteger(row, 'last_attempt_monotonic_ms'),
      nextAttemptMonotonicMs: requireInteger(row, 'next_attempt_monotonic_ms'),
    };
  }

  private assertDerivedColumnsAgree(row: Record<string, SQLOutputValue>, stored: EdgeStoredOperation): void {
    const expected: Readonly<Record<string, string | number>> = {
      offline_operation_id: stored.envelope.offline_operation_id,
      organisation_id: stored.envelope.organisation_id,
      site_id: stored.envelope.site_id,
      actor_user_id: stored.envelope.actor_user_id,
      device_id: stored.envelope.device_id,
      device_sequence: stored.envelope.device_sequence,
      policy_lease_id: stored.envelope.policy_lease_id,
      payload_digest: stored.envelope.payload_digest,
    };
    for (const [column, value] of Object.entries(expected)) {
      if (row[column] !== value) {
        throw new MalformedEdgeQueueError(
          `the indexed '${column}' does not match the signed envelope; the stored entry has been altered`,
        );
      }
    }
  }

  /** One entry by its operation id, or null. */
  find(offlineOperationId: string): EdgeQueueEntry | null {
    const row = this.db
      .prepare(`SELECT ${SELECT_ENTRY_COLUMNS} FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE offline_operation_id = ?`)
      .get(offlineOperationId);
    return row === undefined ? null : this.toEntry(row);
  }

  /** Entries central has not answered. */
  unsettledCount(): number {
    return requireInteger(
      this.db.prepare(`SELECT COUNT(*) AS n FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE settlement_json IS NULL`).get() ?? {},
      'n',
    );
  }

  /** Answered entries still held as local provenance. */
  settledCount(): number {
    return requireInteger(
      this.db.prepare(`SELECT COUNT(*) AS n FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE settlement_json IS NOT NULL`).get() ?? {},
      'n',
    );
  }

  /** The position the next admission will take. NEVER DECREASES. */
  nextMonotonicPosition(): number {
    return this.readCounter().nextPosition;
  }

  // -------------------------------------------------------------------------
  // ORDERING — the head of each namespace, and never one global head
  // -------------------------------------------------------------------------

  /**
   * THE OPERATIONS EDGE MAY FORWARD RIGHT NOW: at most one per namespace, and
   * only if it is that namespace's OLDEST UNSETTLED ENTRY.
   *
   * THE ORDERING ARGUMENT, IN FULL, BECAUSE IT IS THE SUBTLEST RULE HERE
   * ===================================================================
   * The namespace is `(organisation_id, site_id, actor_user_id, device_id)` —
   * central's own offline cursor key, not an Edge invention — and ordering
   * inside it is by `device_sequence`.
   *
   * WITHIN A NAMESPACE, EDGE DOES NOT SKIP PAST AN UNSETTLED POSITION.
   * The inner `MIN(device_sequence)` finds the head over ALL unsettled rows,
   * and only then is the head tested for eligibility — so an entry that is not
   * yet witnessed, or is inside its backoff, holds its place rather than being
   * stepped over. That is not Edge inventing a rule; it is Edge declining to
   * spend a WAN it may not have. C10-08 is explicit that an UNKNOWN outcome
   * HOLDS central's cursor, and C10-07 that only a finalized receipt advances
   * it, so an operation sent ahead of an unresolved predecessor is an operation
   * central will hold anyway. Forwarding it buys nothing and costs the one
   * scarce resource a cut-off site has.
   *
   * A POISONED OPERATION THEREFORE BLOCKS ITS OWN DEVICE'S LATER WORK, AND
   * NOTHING ELSE. This is worth stating plainly rather than hiding, because it
   * sounds like a flaw:
   *
   *   - It is the EXISTING semantics, not a new one. The Android outbox's
   *     comment says it exactly: "A GAP IS NOT A DELAY; IT IS A STALL", and
   *     C10-03 refuses a sequence reset because the alternative is a namespace
   *     in which positions repeat.
   *
   *   - It is not permanent by Edge's choice. C10-07 gives the escape: a
   *     DETERMINISTIC refusal from central finalizes as REJECTED and ADVANCES
   *     the cursor, "otherwise a rejected entry wedges the queue behind a
   *     position nothing can ever fill". Edge mirrors that exactly — a refusal
   *     settles the entry, the settled entry leaves the unsettled set, and the
   *     namespace's head moves on. The unblocking answer comes from central,
   *     which is the party that can actually judge the operation.
   *
   *   - It is bounded by construction. Nothing about one namespace's head
   *     appears in another namespace's query. A device wedged on a poisoned
   *     operation at site A cannot delay a duress signal from a different
   *     operative, a different device, or a different site, and no shared
   *     counter, shared lock or global sequence exists that could couple them.
   *     An Edge-wide FIFO would have coupled all of them, which is the reason
   *     there isn't one.
   *
   * The `ORDER BY enqueued_edge_monotonic_position` ACROSS namespaces is
   * fairness only — oldest-stored first, so no namespace starves — and carries
   * no semantics whatsoever. Nothing downstream may read it as an order central
   * expects.
   */
  forwardableHeads(limit = 64): readonly EdgeQueueEntry[] {
    const now = this.durableNowMs();
    const states = EDGE_QUEUE_FORWARDABLE_STATES.map((state) => `'${state}'`).join(', ');
    const rows = this.db
      .prepare(
        `SELECT ${SELECT_ENTRY_COLUMNS}
           FROM ${EDGE_QUEUE_OPERATION_TABLE} AS o
          WHERE o.settlement_json IS NULL
            AND o.queue_state IN (${states})
            AND o.next_attempt_monotonic_ms <= ?
            AND o.device_sequence = (
              SELECT MIN(h.device_sequence)
                FROM ${EDGE_QUEUE_OPERATION_TABLE} AS h
               WHERE h.settlement_json IS NULL
                 AND h.organisation_id = o.organisation_id
                 AND h.site_id = o.site_id
                 AND h.actor_user_id = o.actor_user_id
                 AND h.device_id = o.device_id
            )
          ORDER BY o.enqueued_edge_monotonic_position ASC
          LIMIT ?`,
      )
      .all(now, limit);
    return rows.map((row) => this.toEntry(row));
  }

  // -------------------------------------------------------------------------
  // CAPACITY
  // -------------------------------------------------------------------------

  /**
   * THE CAPACITY POLICY, IN ONE PLACE.
   *
   * The bound counts UNSETTLED entries — operations central has not answered —
   * because those are the ones that represent work nobody else is holding.
   * Settled rows are Edge's copy of a finished conversation and are bounded
   * separately, by reclamation.
   *
   * AT THE BOUND, ADMISSION IS REFUSED AND SAID SO. Not evicted, not
   * overwritten, not silently dropped. Losing a queued acknowledgement silently
   * is strictly worse than refusing to take a new one: the operative who was
   * refused finds out and can act, while the operative whose duress signal was
   * evicted to make room finds out never. And the eviction would also be
   * self-defeating — the position it burned would stall the whole namespace
   * behind it.
   */
  capacityState(): EdgeQueueCapacityState {
    const unsettled = this.unsettledCount();
    if (unsettled >= this.maxUnsettled) return 'REFUSING_AT_CAPACITY';
    return unsettled >= Math.floor(this.maxUnsettled * EDGE_QUEUE_DEGRADED_FRACTION) ? 'DEGRADED_NEAR_CAPACITY' : 'ACCEPTING';
  }

  /**
   * Reclaims the OLDEST SETTLED entries, and only those.
   *
   * THE ONLY DELETION IN THE STORE, AND THE DATABASE ENFORCES ITS SCOPE. The
   * `edge_queue_no_unsettled_delete` trigger aborts any delete of a row central
   * has not answered, so this statement's `WHERE settlement_json IS NOT NULL`
   * is a filter, not the safety property — a future edit that dropped the
   * filter would fail loudly at the first unsettled row rather than quietly
   * destroying queued work.
   *
   * Oldest-first by `first_stored_monotonic_ms`, so what is discarded is the
   * conversation that has been finished longest.
   */
  pruneSettled(limit: number): number {
    if (limit <= 0) return 0;
    return this.transact(() => {
      const changes = this.db
        .prepare(
          `DELETE FROM ${EDGE_QUEUE_OPERATION_TABLE}
            WHERE offline_operation_id IN (
              SELECT offline_operation_id FROM ${EDGE_QUEUE_OPERATION_TABLE}
               WHERE settlement_json IS NOT NULL
               ORDER BY first_stored_monotonic_ms ASC, enqueued_edge_monotonic_position ASC
               LIMIT ?
            )`,
        )
        .run(limit).changes;
      return Number(changes);
    });
  }

  // -------------------------------------------------------------------------
  // ADMISSION
  // -------------------------------------------------------------------------

  /**
   * Stores one operation, allocating its Edge monotonic position.
   *
   * THE ORDER OF OPERATIONS INSIDE THE TRANSACTION IS THE WHOLE DESIGN:
   *
   *   1. reclaim settled rows if retention is exceeded — never an unsettled one;
   *   2. every refusal, BEFORE the draw, so a refused admission leaves no hole;
   *   3. advance the counter;
   *   4. mint the receipt with the allocated position — inside the transaction,
   *      so a witness that throws rolls the counter back with it;
   *   5. validate the whole thing against the FROZEN contract;
   *   6. insert.
   *
   * Step 5 is where a payload whose bytes do not digest to the value the device
   * signature covers is refused — at enqueue, on this box, which the contract
   * says is the point. Storing it and finding out at reconciliation leaves an
   * operation that can never be admitted and whose original bytes are gone.
   */
  admit(input: EdgeQueueAdmissionInput): EdgeQueueAdmission {
    const { envelope, payloadCanonicalJson } = input;
    return this.transact<EdgeQueueAdmission>(() => {
      const excess = this.settledCount() - this.settledRetention;
      if (excess > 0) this.reclaimSettledInTransaction(excess);

      if (this.find(envelope.offline_operation_id) !== null) {
        return { outcome: 'DUPLICATE_OPERATION_ID' } as const;
      }

      const positionHolder = this.db
        .prepare(
          `SELECT offline_operation_id FROM ${EDGE_QUEUE_OPERATION_TABLE}
            WHERE organisation_id = ? AND site_id = ? AND actor_user_id = ? AND device_id = ? AND device_sequence = ?`,
        )
        .get(
          envelope.organisation_id,
          envelope.site_id,
          envelope.actor_user_id,
          envelope.device_id,
          envelope.device_sequence,
        );
      if (positionHolder !== undefined) {
        return { outcome: 'SEQUENCE_POSITION_ALREADY_HELD' } as const;
      }

      const unsettled = this.unsettledCount();
      if (unsettled >= this.maxUnsettled) {
        // Truthful refusal, with the numbers, so the caller can say something
        // true to the device rather than a generic failure.
        this.logger.warn(`refusing admission: ${unsettled} unsettled operations, capacity ${this.maxUnsettled}`);
        return { outcome: 'AT_CAPACITY', unsettled, capacity: this.maxUnsettled } as const;
      }

      const counter = this.readCounter();
      if (counter.nextPosition >= EDGE_QUEUE_MAX_MONOTONIC_POSITION) {
        // Unreachable in practice and refused anyway, because the alternative
        // is wrapping — and a wrapped position re-uses one Edge already signed.
        return { outcome: 'POSITION_SPACE_EXHAUSTED' } as const;
      }

      const allocated = counter.nextPosition;
      const now = this.durableNowMs();
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_COUNTER_TABLE}
              SET next_edge_monotonic_position = ?, last_observed_monotonic_ms = MAX(last_observed_monotonic_ms, ?)
            WHERE id = 1`,
        )
        .run(allocated + 1, now);

      const receipt = input.witness?.(allocated) ?? null;

      // VALIDATION, NOT STORAGE. The parsed value is discarded: what goes to
      // disk is the text that was handed in, byte for byte. Re-serialising the
      // parsed form would defeat the whole reason the payload is stored as text.
      try {
        EdgeStoredOperationSchema.parse({
          schema_version: EDGE_QUEUE_SCHEMA_VERSION,
          envelope,
          payload_canonical_json: payloadCanonicalJson,
          receipt,
          enqueued_edge_monotonic_position: allocated,
          state: 'QUEUED',
          settlement: null,
        });
      } catch (error) {
        throw new EdgeQueueOperationNotStorableError(
          'the operation does not satisfy the frozen stored-operation contract; nothing was allocated',
          error,
        );
      }

      this.db
        .prepare(
          `INSERT INTO ${EDGE_QUEUE_OPERATION_TABLE} (
             offline_operation_id, schema_version, envelope_json, payload_canonical_json, payload_digest, receipt_json,
             organisation_id, site_id, actor_user_id, device_id, device_sequence, policy_lease_id,
             enqueued_edge_monotonic_position, queue_state, settlement_json, attempt_count, failure_category,
             first_stored_monotonic_ms, last_attempt_monotonic_ms, next_attempt_monotonic_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, NULL, ?)`,
        )
        .run(
          envelope.offline_operation_id,
          EDGE_QUEUE_SCHEMA_VERSION,
          JSON.stringify(envelope),
          payloadCanonicalJson,
          envelope.payload_digest,
          receipt === null ? null : JSON.stringify(receipt),
          envelope.organisation_id,
          envelope.site_id,
          envelope.actor_user_id,
          envelope.device_id,
          envelope.device_sequence,
          envelope.policy_lease_id,
          allocated,
          // A stored operation begins STORED_LOCAL, not READY_TO_FORWARD:
          // whether it is forwardable depends on whether it has been witnessed,
          // and that is the caller's decision, made after this returns.
          'STORED_LOCAL' satisfies EdgeQueueState,
          EDGE_QUEUE_INITIAL_FAILURE_CATEGORY,
          now,
          now,
        );

      const entry = this.find(envelope.offline_operation_id);
      if (entry === null) throw new MalformedEdgeQueueError('the admitted operation is not readable back');
      return { outcome: 'ADMITTED', entry } as const;
    });
  }

  private reclaimSettledInTransaction(limit: number): void {
    this.db
      .prepare(
        `DELETE FROM ${EDGE_QUEUE_OPERATION_TABLE}
          WHERE offline_operation_id IN (
            SELECT offline_operation_id FROM ${EDGE_QUEUE_OPERATION_TABLE}
             WHERE settlement_json IS NOT NULL
             ORDER BY first_stored_monotonic_ms ASC, enqueued_edge_monotonic_position ASC
             LIMIT ?
          )`,
      )
      .run(limit);
  }

  // -------------------------------------------------------------------------
  // STATE CHANGES
  // -------------------------------------------------------------------------

  private currentState(offlineOperationId: string): { state: EdgeQueueState; attemptCount: number; settled: boolean } | null {
    const row = this.db
      .prepare(
        `SELECT queue_state, attempt_count, settlement_json FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE offline_operation_id = ?`,
      )
      .get(offlineOperationId);
    if (row === undefined) return null;
    return {
      state: requireText(row, 'queue_state') as EdgeQueueState,
      attemptCount: requireInteger(row, 'attempt_count'),
      settled: optionalText(row, 'settlement_json') !== null,
    };
  }

  /**
   * The single gate every state change goes through.
   *
   * It refuses an illegal transition by THROWING, and it refuses to touch a
   * settled entry at all. The second refusal is not redundant with the
   * `edge_queue_settlement_is_final` trigger: the trigger is what stops a writer
   * that never came through here, and this is what gives a caller a sensible
   * `false` instead of an aborted transaction when it re-reports an answer it
   * has already reported.
   */
  private transitionTo(
    offlineOperationId: string,
    to: EdgeQueueState,
    apply: (current: { state: EdgeQueueState; attemptCount: number }) => void,
  ): boolean {
    return this.transact(() => {
      const current = this.currentState(offlineOperationId);
      if (current === null) return false;
      if (current.settled) return false;
      // A SELF-TRANSITION IS NOT A TRANSITION. Two timeouts in a row, or two
      // attempts, are two facts about the same state, and both must be recorded
      // — a store that treated the second as a no-op would leave the backoff and
      // the consecutive-unknown gauge one behind reality for as long as a link
      // stayed broken, which is exactly when they are read. The transition table
      // is consulted only when the state actually changes.
      if (current.state !== to && !canTransitionEdgeQueueState(current.state, to)) {
        throw new EdgeQueueTransitionError(current.state, to);
      }
      apply(current);
      this.markClock();
      return true;
    });
  }

  /**
   * The operation has been witnessed (or has been determined not to be
   * witnessable) and may now be offered to the transport.
   */
  markReadyToForward(offlineOperationId: string): boolean {
    return this.transitionTo(offlineOperationId, 'READY_TO_FORWARD', () => {
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET queue_state = 'READY_TO_FORWARD' WHERE offline_operation_id = ?`,
        )
        .run(offlineOperationId);
    });
  }

  /**
   * Records that this entry is BEING HANDED TO THE TRANSPORT — before the
   * request goes out, never after the answer comes back.
   *
   * THE WRITE-AHEAD IS THE CRASH-SAFETY PROPERTY, and it does three things at
   * once:
   *
   *   `attempt_count` is incremented and `next_attempt_monotonic_ms` is pushed
   *   out by the backoff BEFORE the risk is taken, so a process that dies
   *   mid-request comes back with the delay already applied. An attempt that was
   *   made but not recorded is an attempt the backoff cannot see, and an Edge
   *   that crashed mid-request would otherwise return and hammer the same
   *   operation with no delay at all.
   *
   *   `failure_category` is set to TRANSPORT_ERROR — the honest answer if the
   *   power goes out one instruction from now. The pessimistic truth is written
   *   ahead of the attempt, so the recovery sweep has nothing to invent.
   *
   *   The state becomes FORWARDING, which is what the sweep looks for.
   */
  claimForForwarding(offlineOperationId: string): boolean {
    return this.transitionTo(offlineOperationId, 'FORWARDING', (current) => {
      const attempt = current.attemptCount + 1;
      const now = this.durableNowMs();
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE}
              SET queue_state = 'FORWARDING',
                  attempt_count = ?,
                  failure_category = ?,
                  last_attempt_monotonic_ms = ?,
                  next_attempt_monotonic_ms = ?
            WHERE offline_operation_id = ?`,
        )
        .run(attempt, EDGE_QUEUE_CRASH_RECOVERY_CATEGORY, now, now + edgeQueueRetryDelayMs(attempt), offlineOperationId);
    });
  }

  /**
   * Central has said something, and it is NOT an answer.
   *
   * THE TYPE IS THE ENFORCEMENT: `EdgeCentralProgress` has two members and
   * neither of them is APPLIED. There is no argument to this method by which a
   * caller could record "central committed", and there is no other method that
   * takes a state name at all. Reaching CENTRAL_APPLIED requires `settle()`,
   * which requires a central answer carrying a `central_reference`.
   *
   * This is what stops the most plausible version of the local lie: a forwarder
   * that sees WP-20's RECEIVED, treats "central has it" as "central did it", and
   * stops chasing an operation whose effect may never commit — because
   * `OFFLINE_PROCESSING_LEASE_MS` exists precisely so that an APPLYING receipt
   * left by a dead process is reclaimed and retried.
   */
  recordCentralProgress(offlineOperationId: string, progress: EdgeCentralProgress): boolean {
    return this.transitionTo(offlineOperationId, progress, () => {
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE}
              SET queue_state = ?, failure_category = NULL
            WHERE offline_operation_id = ?`,
        )
        .run(progress, offlineOperationId);
      // We have heard from central, so the link is not the problem.
      this.db
        .prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET consecutive_unknown_transport_results = 0 WHERE id = 1`)
        .run();
    });
  }

  /**
   * The attempt produced no answer from central.
   *
   * THE CALLER SUPPLIES THE WIRE FACT AND THE STORE DERIVES THE STATE. There is
   * no state parameter, so a transport author cannot file a timeout — which may
   * already have been applied — as a clean failure that looks free to retry.
   * `EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY` draws that line and this method is
   * the only place it is read.
   *
   * Neither resulting state is TERMINAL. An entry stays queued INDEFINITELY on
   * unknown outcomes, deliberately, because a site that has been cut off for six
   * hours must still be holding its operations when the WAN returns.
   */
  recordTransportUnknown(offlineOperationId: string, reason: EdgeQueueFailureCategory): boolean {
    const to = EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY[reason];
    return this.transitionTo(offlineOperationId, to, () => {
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET queue_state = ?, failure_category = ? WHERE offline_operation_id = ?`,
        )
        .run(to, reason, offlineOperationId);
      if (reason !== 'NOT_ATTEMPTED') {
        this.db
          .prepare(
            `UPDATE ${EDGE_QUEUE_COUNTER_TABLE}
                SET consecutive_unknown_transport_results = consecutive_unknown_transport_results + 1
              WHERE id = 1`,
          )
          .run();
      }
    });
  }

  /**
   * CENTRAL HAS ANSWERED. The only thing in this file that can end an entry.
   *
   * THREE INDEPENDENT LAYERS STOP A LOCAL "COMMITTED", and they are independent
   * on purpose — each catches a writer the others do not:
   *
   *   TYPE      the parameter is `EdgeTransportTerminalAnswer`, extracted from
   *             the frozen union as the members with `terminal: true`. An
   *             UNKNOWN result is not assignable, so the ambiguous case cannot
   *             be passed here at all.
   *
   *   CONTRACT  the value is re-parsed with `EdgeTransportResultSchema` and the
   *             `terminal` discriminant re-checked at runtime, because the type
   *             stops a TypeScript caller and nothing else.
   *
   *   DATABASE  `edge_queue_settlement_matches_state` and
   *             `edge_queue_settlement_proves_state` make the settled state and
   *             the outcome inside central's answer exactly equivalent, so no
   *             SQL — from here or from a shell on the appliance — produces a
   *             committed-looking row without central's acceptance in it.
   *
   * The resulting state is DERIVED from the outcome. There is no parameter for
   * it, so no caller can pair CENTRAL_APPLIED with a refusal.
   */
  settle(offlineOperationId: string, answer: EdgeTransportTerminalAnswer): boolean {
    const parsed = EdgeTransportResultSchema.parse(answer);
    if (parsed.terminal !== true) {
      throw new EdgeQueueTransitionError('FORWARDING', 'CENTRAL_APPLIED');
    }
    const to: EdgeQueueState = parsed.outcome === 'CENTRAL_ACCEPTED' ? 'CENTRAL_APPLIED' : 'FAILED_TERMINAL';
    return this.transitionTo(offlineOperationId, to, () => {
      this.db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE}
              SET queue_state = ?, settlement_json = ?, failure_category = NULL
            WHERE offline_operation_id = ?`,
        )
        .run(to, JSON.stringify(parsed), offlineOperationId);
      this.db
        .prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET consecutive_unknown_transport_results = 0 WHERE id = 1`)
        .run();
    });
  }

  // -------------------------------------------------------------------------
  // METRICS
  // -------------------------------------------------------------------------

  /**
   * The frozen `EdgeQueueMetrics`, and nothing that is not in it.
   *
   * AGGREGATE ONLY. The contract's comment explains at length why a queue depth
   * labelled by `device_id` is a per-operative activity trace exported from the
   * least access-controlled surface a service has, so this method returns the
   * `.strict()` frozen shape and there is no variant that takes a grouping.
   *
   * `trustedTimeAvailable` is handed in rather than looked up: the queue does
   * not own the trusted-time anchor and must not acquire a dependency on the
   * module that does, or a store that cannot be constructed without a keyring
   * becomes a store no test can construct.
   */
  metrics(input: { readonly trustedTimeAvailable: boolean }): EdgeQueueMetrics {
    const counter = this.readCounter();
    const oldest = this.db
      .prepare(
        `SELECT MIN(first_stored_monotonic_ms) AS oldest FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE settlement_json IS NULL`,
      )
      .get();
    const oldestMs = oldest === undefined ? null : optionalInteger(oldest, 'oldest');
    return EdgeQueueMetricsSchema.parse({
      schema_version: 1,
      queued_count: this.unsettledCount(),
      terminal_count: this.settledCount(),
      capacity: this.maxUnsettled,
      oldest_queued_monotonic_age_ms: oldestMs === null ? null : Math.max(0, this.durableNowMs() - oldestMs),
      trusted_time_available: input.trustedTimeAvailable,
      consecutive_unknown_transport_results: counter.consecutiveUnknown,
    });
  }

  /** Closes the database. A store that is not open answers nothing. */
  close(): void {
    if (this.db.isOpen) this.db.close();
  }
}

/**
 * Exported for the state model's consumers: whether an entry the store returned
 * is one central has ended.
 *
 * Re-exported here rather than made a method so that a caller holding a plain
 * `EdgeQueueEntry` — from a log, from a test fixture — answers the question the
 * same way the store does.
 */
export function isSettledEdgeQueueEntry(entry: EdgeQueueEntry): boolean {
  return isEdgeQueueSettledState(entry.queueState);
}
