import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EDGE_QUEUE_DATABASE_FILENAME, EDGE_QUEUE_SCHEMA_VERSION } from './edge-queue.constants';
import {
  EDGE_QUEUE_COUNTER_TABLE,
  EDGE_QUEUE_OPERATION_TABLE,
  EDGE_QUEUE_PRAGMAS,
  EDGE_QUEUE_SCHEMA_SQL,
} from './edge-queue.schema';
import { SqliteEdgeOperationStore } from './edge-queue.store';
import { temporaryQueueDirectory } from './edge-queue.test-support';

/**
 * ============================================================================
 * THE POWER GOES OUT MID-WRITE.
 *
 * Every other spec simulates a crash by closing a handle, which is honest about
 * SQLite's rollback semantics but is still an ORDERLY end: buffers flush, the
 * process unwinds, and the operating system is told what is happening. A
 * cleaner pulling the plug on a box in a wiring closet does none of that.
 *
 * So this spec kills a real child process with SIGKILL — TerminateProcess on
 * Windows, an uncatchable signal on Linux — WHILE IT IS INSIDE AN OPEN
 * TRANSACTION that has already written both the counter advance and the entry.
 * That is the exact boundary the whole design turns on, and the property being
 * proven is the one the store cannot check for itself:
 *
 *   AFTER AN ABRUPT KILL, THE STORE IS NEVER AHEAD OF DURABLE STATE.
 *   The half-written entry is absent, the counter never spent its position, the
 *   database is readable, and everything committed before the kill is intact.
 *
 * It runs the write path in raw SQL rather than through the store, for the same
 * reason `edge-queue.schema.spec.ts` does: what is being tested is the storage
 * engine's durability contract under WAL with `synchronous = FULL`, and routing
 * it through TypeScript would only add a layer that cannot influence the answer.
 * The DDL is the store's own, written to a file and applied by the child, so
 * there is no second copy of the schema to drift.
 * ============================================================================
 */

const ROUNDS = 4;
const COMMITS_PER_ROUND = 3;

function childScript(operationTable: string, counterTable: string): string {
  return `
'use strict';
const { DatabaseSync } = require('node:sqlite');
const { readFileSync } = require('node:fs');
const [databasePath, ddlPath, commitsArgument] = process.argv.slice(2);

const db = new DatabaseSync(databasePath);
${EDGE_QUEUE_PRAGMAS.map((pragma) => `db.exec(${JSON.stringify(pragma)});`).join('\n')}
db.exec(readFileSync(ddlPath, 'utf8'));
db.prepare(
  'INSERT OR IGNORE INTO ${counterTable} (id, schema_version, next_edge_monotonic_position, last_observed_monotonic_ms, consecutive_unknown_transport_results) VALUES (1, ${EDGE_QUEUE_SCHEMA_VERSION}, 0, 0, 0)'
).run();

const advance = db.prepare('UPDATE ${counterTable} SET next_edge_monotonic_position = ? WHERE id = 1');
const insert = db.prepare(
  \`INSERT INTO ${operationTable} (
     offline_operation_id, schema_version, envelope_json, payload_canonical_json, payload_digest, receipt_json,
     organisation_id, site_id, actor_user_id, device_id, device_sequence, policy_lease_id,
     enqueued_edge_monotonic_position, queue_state, settlement_json, attempt_count, failure_category,
     first_stored_monotonic_ms, last_attempt_monotonic_ms, next_attempt_monotonic_ms
   ) VALUES (?, ${EDGE_QUEUE_SCHEMA_VERSION}, '{"a":1}', '{}', 'e', NULL, 'org-1', 'site-1', 'user-1', 'device-1', ?, 'lease-1',
             ?, 'STORED_LOCAL', NULL, 0, 'NOT_ATTEMPTED', 0, NULL, 0)\`
);

/** One admission: the counter advance and the entry, together or not at all. */
function write(position) {
  advance.run(position + 1);
  insert.run('crash-' + position, position, position);
}

let position = Number(db.prepare('SELECT next_edge_monotonic_position AS n FROM ${counterTable} WHERE id = 1').get().n);
for (let i = 0; i < Number(commitsArgument); i += 1) {
  db.exec('BEGIN IMMEDIATE');
  write(position);
  db.exec('COMMIT');
  position += 1;
}

// The transaction that never commits. Both writes have landed in the
// connection's view; nothing has reached a durable, committed state.
db.exec('BEGIN IMMEDIATE');
write(position);
process.kill(process.pid, 'SIGKILL');
`;
}

describe('the durable queue under an abrupt process kill', () => {
  let directory: { path: string; remove: () => void };

  beforeEach(() => {
    directory = temporaryQueueDirectory();
  });

  afterEach(() => {
    directory.remove();
  });

  it('is never left ahead of durable state, however many times it is killed mid-transaction', () => {
    const databasePath = join(directory.path, EDGE_QUEUE_DATABASE_FILENAME);
    const ddlPath = join(directory.path, 'schema.sql');
    const scriptPath = join(directory.path, 'crash-writer.cjs');
    writeFileSync(ddlPath, EDGE_QUEUE_SCHEMA_SQL, 'utf8');
    writeFileSync(scriptPath, childScript(EDGE_QUEUE_OPERATION_TABLE, EDGE_QUEUE_COUNTER_TABLE), 'utf8');

    for (let round = 1; round <= ROUNDS; round += 1) {
      const result = spawnSync(process.execPath, [scriptPath, databasePath, ddlPath, String(COMMITS_PER_ROUND)], {
        encoding: 'utf8',
      });
      // The child must have DIED, not exited. A clean exit would mean the kill
      // never happened and this spec would be proving nothing.
      expect(result.status, `round ${round} stderr: ${result.stderr}`).not.toBe(0);

      const committed = round * COMMITS_PER_ROUND;

      // 1. The database is readable, and the store will open it — which means
      //    its integrity check passed: no entry holds a position at or beyond
      //    the counter.
      const store = new SqliteEdgeOperationStore({ directory: directory.path });
      try {
        expect(store.nextMonotonicPosition()).toBe(committed);
        expect(store.unsettledCount()).toBe(committed);
      } finally {
        store.close();
      }

      // 2. Everything committed before the kill survived, exactly once each,
      //    and the interrupted admission left NOTHING — no row, and no spent
      //    position.
      const db = new DatabaseSync(databasePath);
      try {
        const positions = db
          .prepare(`SELECT enqueued_edge_monotonic_position AS p FROM ${EDGE_QUEUE_OPERATION_TABLE} ORDER BY p ASC`)
          .all()
          .map((row) => Number(row.p));
        expect(positions).toEqual(Array.from({ length: committed }, (_, index) => index));
        expect(new Set(positions).size).toBe(positions.length);
        expect(db.prepare(`SELECT COUNT(*) AS n FROM ${EDGE_QUEUE_OPERATION_TABLE} WHERE offline_operation_id = ?`).get(
          `crash-${committed}`,
        )?.n).toBe(0);
      } finally {
        db.close();
      }
    }
  }, 60_000);
});
