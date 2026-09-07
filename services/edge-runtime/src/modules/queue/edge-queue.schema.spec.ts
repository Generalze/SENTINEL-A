import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EDGE_QUEUE_SCHEMA_VERSION } from './edge-queue.constants';
import {
  EDGE_QUEUE_COUNTER_COLUMNS,
  EDGE_QUEUE_COUNTER_TABLE,
  EDGE_QUEUE_NAMESPACE_COLUMNS,
  EDGE_QUEUE_OPERATION_COLUMNS,
  EDGE_QUEUE_OPERATION_TABLE,
  EDGE_QUEUE_PRAGMAS,
  EDGE_QUEUE_SCHEMA_SQL,
} from './edge-queue.schema';

/**
 * ============================================================================
 * THE SCHEMA'S OWN GUARANTEES, PROVEN AGAINST A REAL DATABASE AND NOT THROUGH
 * THE STORE.
 *
 * Every statement here is raw SQL. That is the entire point: the store's rules
 * are only worth what the STORAGE ENGINE enforces once somebody with a shell on
 * the appliance, a maintenance script, or a half-finished migration writes to
 * this file without going through TypeScript. A rule the store checks and the
 * database does not is a rule that stops at the first writer who does not use
 * the store.
 * ============================================================================
 */

const NAMESPACE = { organisation_id: 'org-1', site_id: 'site-1', actor_user_id: 'user-1', device_id: 'device-1' };
const ACCEPTED = JSON.stringify({ outcome: 'CENTRAL_ACCEPTED', terminal: true, central_reference: 'central-1' });
const REFUSED = JSON.stringify({ outcome: 'CENTRAL_REFUSED', terminal: true, refusal_code: 'LEASE_NOT_IN_FORCE' });

describe('edge queue schema', () => {
  let db: DatabaseSync;

  function insert(overrides: Record<string, string | number | null> = {}): void {
    const row: Record<string, string | number | null> = {
      offline_operation_id: 'op-1',
      schema_version: EDGE_QUEUE_SCHEMA_VERSION,
      envelope_json: '{"a":1}',
      payload_canonical_json: '{}',
      payload_digest: 'e'.repeat(64),
      receipt_json: null,
      ...NAMESPACE,
      device_sequence: 0,
      policy_lease_id: 'lease-1',
      enqueued_edge_monotonic_position: 0,
      queue_state: 'STORED_LOCAL',
      settlement_json: null,
      attempt_count: 0,
      failure_category: 'NOT_ATTEMPTED',
      first_stored_monotonic_ms: 0,
      last_attempt_monotonic_ms: null,
      next_attempt_monotonic_ms: 0,
      ...overrides,
    };
    const columns = Object.keys(row);
    db.prepare(
      `INSERT INTO ${EDGE_QUEUE_OPERATION_TABLE} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`,
    ).run(...columns.map((column) => row[column]));
  }

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    for (const pragma of EDGE_QUEUE_PRAGMAS) {
      // journal_mode has no meaning for an in-memory database; the rest apply.
      if (!pragma.includes('journal_mode')) db.exec(pragma);
    }
    db.exec(EDGE_QUEUE_SCHEMA_SQL);
    db.prepare(
      `INSERT INTO ${EDGE_QUEUE_COUNTER_TABLE} (id, schema_version, next_edge_monotonic_position, last_observed_monotonic_ms, consecutive_unknown_transport_results)
       VALUES (1, ?, 8, 0, 0)`,
    ).run(EDGE_QUEUE_SCHEMA_VERSION);
  });

  afterEach(() => {
    db.close();
  });

  // -------------------------------------------------------------------------
  // The no-secret-field guard
  // -------------------------------------------------------------------------

  /**
   * `OfflineOutboxEntryTest`'s forbidden-word approach, transplanted.
   *
   * THE LIST NAMES SECRETS SPECIFICALLY, and the difference from the Android
   * one is deliberate. `ClientStateStoreTest` forbids `key` and `signature`
   * outright; `OfflineOutboxEntryTest` cannot, because it flattens the envelope
   * and must name `key_id` and `signature`. This schema COMPOSES the envelope,
   * so no signed field is a column and neither word appears — but the guard
   * still forbids secrets rather than spellings, because a list that forbade
   * "key" would be proving a fact about vocabulary rather than about what is on
   * the disk.
   */
  it('persists no column whose name could hold a secret', () => {
    const forbidden = [
      'credential',
      'password',
      'passphrase',
      'session',
      'bearer',
      'private',
      'secret',
      'token',
      'cookie',
      'grant',
      'authorization',
      'authorisation',
    ];
    for (const column of [...EDGE_QUEUE_OPERATION_COLUMNS, ...EDGE_QUEUE_COUNTER_COLUMNS]) {
      for (const word of forbidden) {
        expect(column.toLowerCase(), `'${column}' is persisted by the queue and names a secret ('${word}')`).not.toContain(word);
      }
    }
  });

  /**
   * THE LIST IS PROVEN TO BE THE SCHEMA.
   *
   * This is the half the Android test cannot do. There, `PERSISTED_FIELDS` is a
   * hand-maintained list beside a hand-written codec, and the two could drift.
   * Here the list is checked against what the DDL ACTUALLY CREATES, so a column
   * added to the table without being added to the reviewed list — the exact way
   * a place for a secret would appear — fails this test.
   */
  it('declares exactly the reviewed columns, in the order the list names them', () => {
    const actual = db.prepare(`PRAGMA table_info('${EDGE_QUEUE_OPERATION_TABLE}')`).all().map((row) => row.name);
    expect(actual).toEqual([...EDGE_QUEUE_OPERATION_COLUMNS]);

    const counter = db.prepare(`PRAGMA table_info('${EDGE_QUEUE_COUNTER_TABLE}')`).all().map((row) => row.name);
    expect(counter).toEqual([...EDGE_QUEUE_COUNTER_COLUMNS]);
  });

  it('orders by central’s own cursor namespace and not by an Edge invention', () => {
    expect([...EDGE_QUEUE_NAMESPACE_COLUMNS]).toEqual(['organisation_id', 'site_id', 'actor_user_id', 'device_id']);
    for (const column of EDGE_QUEUE_NAMESPACE_COLUMNS) {
      expect(EDGE_QUEUE_OPERATION_COLUMNS).toContain(column);
    }
  });

  // -------------------------------------------------------------------------
  // NO LOCAL STATE MAY FALSELY MEAN CENTRAL COMMITTED
  // -------------------------------------------------------------------------

  it('refuses a CENTRAL_APPLIED row that carries no answer from central', () => {
    expect(() => insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: null, failure_category: null })).toThrow(
      /edge_queue_settlement_matches_state|CHECK/u,
    );
  });

  it('refuses a FAILED_TERMINAL row that carries no answer from central', () => {
    expect(() => insert({ queue_state: 'FAILED_TERMINAL', settlement_json: null, failure_category: null })).toThrow(/CHECK/u);
  });

  /**
   * The worst possible mislabelling: an operation central REJECTED, stored
   * locally as committed. The evidence and the state are bound to each other,
   * so the row cannot exist.
   */
  it('refuses a CENTRAL_APPLIED row justified by a REFUSAL', () => {
    expect(() =>
      insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: REFUSED, failure_category: null }),
    ).toThrow(/edge_queue_settlement_proves_state|CHECK/u);
  });

  it('refuses a FAILED_TERMINAL row justified by an ACCEPTANCE', () => {
    expect(() =>
      insert({ queue_state: 'FAILED_TERMINAL', settlement_json: ACCEPTED, failure_category: null }),
    ).toThrow(/CHECK/u);
  });

  it('refuses a queued row that carries a central answer, because an answered entry is not queued', () => {
    expect(() => insert({ queue_state: 'UNKNOWN', settlement_json: ACCEPTED, failure_category: null })).toThrow(/CHECK/u);
  });

  it('accepts the one shape that is true: a settled state, its matching answer, and no wire excuse', () => {
    expect(() => insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: ACCEPTED, failure_category: null })).not.toThrow();
  });

  it('refuses an unacknowledged row with no reason for having no answer', () => {
    expect(() => insert({ queue_state: 'UNKNOWN', failure_category: null })).toThrow(/edge_queue_answer_or_reason|CHECK/u);
  });

  it('refuses a row that holds both central’s answer and a transport failure', () => {
    expect(() =>
      insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: ACCEPTED, failure_category: 'TIMED_OUT' }),
    ).toThrow(/CHECK/u);
  });

  it('refuses a state name the model does not know', () => {
    expect(() => insert({ queue_state: 'DONE' })).toThrow(/CHECK/u);
  });

  it('refuses a failure category the frozen contract does not have', () => {
    expect(() => insert({ failure_category: 'GAVE_UP' })).toThrow(/CHECK/u);
  });

  // -------------------------------------------------------------------------
  // Deletion, immutability, and the counter
  // -------------------------------------------------------------------------

  it('refuses to delete an operation central has not answered, however the delete is written', () => {
    insert();
    expect(() => db.prepare(`DELETE FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE offline_operation_id = 'op-1'`).run()).toThrow(
      /may not be deleted/u,
    );
    // Not even a whole-table wipe gets past it.
    expect(() => db.prepare(`DELETE FROM ${EDGE_QUEUE_OPERATION_TABLE}`).run()).toThrow(/may not be deleted/u);
    expect(db.prepare(`SELECT COUNT(*) AS n FROM ${EDGE_QUEUE_OPERATION_TABLE}`).get()?.n).toBe(1);
  });

  it('permits deleting an entry central HAS answered — that is the only reclaimable row', () => {
    insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: ACCEPTED, failure_category: null });
    expect(() => db.prepare(`DELETE FROM ${EDGE_QUEUE_OPERATION_TABLE}`).run()).not.toThrow();
  });

  it('refuses to rewrite an entry central has already answered', () => {
    insert({ queue_state: 'CENTRAL_APPLIED', settlement_json: ACCEPTED, failure_category: null });
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET queue_state = 'UNKNOWN' WHERE offline_operation_id = 'op-1'`).run(),
    ).toThrow(/final/u);
  });

  it('refuses to rewrite the signed envelope of a stored operation', () => {
    insert();
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET envelope_json = '{"a":2}' WHERE offline_operation_id = 'op-1'`).run(),
    ).toThrow(/immutable/u);
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET device_sequence = 9 WHERE offline_operation_id = 'op-1'`).run(),
    ).toThrow(/immutable/u);
  });

  it('lets the local bookkeeping be updated, because that is what it is for', () => {
    insert();
    expect(() =>
      db
        .prepare(
          `UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET attempt_count = 3, failure_category = 'TIMED_OUT', queue_state = 'UNKNOWN'
             WHERE offline_operation_id = 'op-1'`,
        )
        .run(),
    ).not.toThrow();
  });

  it('refuses to replace or clear an Edge receipt once one has been written', () => {
    insert({ receipt_json: '{"r":1}' });
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET receipt_json = '{"r":2}' WHERE offline_operation_id = 'op-1'`).run(),
    ).toThrow(/written once/u);
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET receipt_json = NULL WHERE offline_operation_id = 'op-1'`).run(),
    ).toThrow(/written once/u);
  });

  it('refuses a second counter row, because a second counter is a second sequence namespace', () => {
    expect(() =>
      db
        .prepare(
          `INSERT INTO ${EDGE_QUEUE_COUNTER_TABLE} (id, schema_version, next_edge_monotonic_position, last_observed_monotonic_ms, consecutive_unknown_transport_results)
           VALUES (2, 1, 0, 0, 0)`,
        )
        .run(),
    ).toThrow(/CHECK/u);
  });

  it('refuses a counter that moves backwards, and a durable clock that does', () => {
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET next_edge_monotonic_position = 7 WHERE id = 1`).run(),
    ).toThrow(/backwards/u);
    db.prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET last_observed_monotonic_ms = 500 WHERE id = 1`).run();
    expect(() =>
      db.prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET last_observed_monotonic_ms = 499 WHERE id = 1`).run(),
    ).toThrow(/backwards/u);
  });

  it('refuses an entry stored at a position the counter has not yet spent', () => {
    expect(() => insert({ enqueued_edge_monotonic_position: 8 })).toThrow(/at or beyond/u);
    expect(() => insert({ enqueued_edge_monotonic_position: 7 })).not.toThrow();
  });

  it('refuses a second operation claiming a device position this namespace already holds', () => {
    insert({ offline_operation_id: 'op-1', device_sequence: 3, enqueued_edge_monotonic_position: 0 });
    expect(() => insert({ offline_operation_id: 'op-2', device_sequence: 3, enqueued_edge_monotonic_position: 1 })).toThrow(
      /UNIQUE/u,
    );
    // A different device at the same position is a different namespace entirely.
    expect(() =>
      insert({ offline_operation_id: 'op-3', device_id: 'device-2', device_sequence: 3, enqueued_edge_monotonic_position: 2 }),
    ).not.toThrow();
  });
});
