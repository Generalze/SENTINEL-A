import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EDGE_QUEUE_DATABASE_FILENAME, EDGE_QUEUE_SCHEMA_VERSION, edgeQueueRetryDelayMs } from './edge-queue.constants';
import { EDGE_QUEUE_COUNTER_TABLE, EDGE_QUEUE_OPERATION_TABLE, EDGE_QUEUE_PRAGMAS } from './edge-queue.schema';
import {
  EdgeQueueTransitionError,
  MalformedEdgeQueueError,
  SqliteEdgeOperationStore,
  type EdgeQueueAdmission,
} from './edge-queue.store';
import { FixtureClock, fixtureOperation, fixtureReceipt, temporaryQueueDirectory } from './edge-queue.test-support';

const ACCEPTED = { outcome: 'CENTRAL_ACCEPTED', terminal: true, central_reference: 'central-1' } as const;
const REFUSED = { outcome: 'CENTRAL_REFUSED', terminal: true, refusal_code: 'LEASE_NOT_IN_FORCE' } as const;

describe('SqliteEdgeOperationStore', () => {
  let directory: { path: string; remove: () => void };
  let clock: FixtureClock;
  let store: SqliteEdgeOperationStore;

  function open(options: { maxUnsettled?: number; settledRetention?: number } = {}): SqliteEdgeOperationStore {
    return new SqliteEdgeOperationStore({ directory: directory.path, clock, ...options });
  }

  /** Closes and reopens: a process restart, with the disk left exactly as it was. */
  function restart(options: { maxUnsettled?: number; settledRetention?: number } = {}): void {
    store.close();
    store = open(options);
  }

  function admitted(admission: EdgeQueueAdmission): string {
    expect(admission.outcome).toBe('ADMITTED');
    if (admission.outcome !== 'ADMITTED') throw new Error('unreachable');
    return admission.entry.stored.envelope.offline_operation_id;
  }

  /** Stores an operation and takes it all the way to "eligible to forward". */
  function queueReady(overrides: Record<string, unknown> = {}): string {
    const operation = fixtureOperation(overrides);
    const id = admitted(store.admit(operation));
    store.markReadyToForward(id);
    return id;
  }

  beforeEach(() => {
    directory = temporaryQueueDirectory();
    clock = new FixtureClock();
    store = open();
  });

  afterEach(() => {
    store.close();
    directory.remove();
  });

  // -------------------------------------------------------------------------
  // Admission, and the three rules inherited from OfflineOutbox
  // -------------------------------------------------------------------------

  it('stores an operation with its signed envelope, its payload bytes and its receipt', () => {
    const operation = fixtureOperation();
    const admission = store.admit({ ...operation, witness: (position) => fixtureReceipt(position) });
    expect(admission.outcome).toBe('ADMITTED');
    if (admission.outcome !== 'ADMITTED') return;

    const entry = admission.entry;
    expect(entry.queueState).toBe('STORED_LOCAL');
    expect(entry.stored.state).toBe('QUEUED');
    expect(entry.stored.settlement).toBeNull();
    // The payload is the bytes the device digested, byte for byte.
    expect(entry.stored.payload_canonical_json).toBe(operation.payloadCanonicalJson);
    // The witness was handed the position the store allocated, and the receipt
    // it signed carries that exact number.
    expect(entry.stored.receipt?.edge_monotonic_position).toBe(entry.stored.enqueued_edge_monotonic_position);
    expect(entry.failureCategory).toBe('NOT_ATTEMPTED');
  });

  it('accepts an operation with no receipt, because an Edge with no trusted time still queues', () => {
    const admission = store.admit(fixtureOperation());
    expect(admission.outcome).toBe('ADMITTED');
    if (admission.outcome !== 'ADMITTED') return;
    expect(admission.entry.stored.receipt).toBeNull();
  });

  it('refuses a duplicate operation id without allocating anything', () => {
    const operation = fixtureOperation();
    admitted(store.admit(operation));
    const before = store.nextMonotonicPosition();
    expect(store.admit(operation).outcome).toBe('DUPLICATE_OPERATION_ID');
    expect(store.nextMonotonicPosition()).toBe(before);
  });

  it('refuses a second operation at a device position this namespace already holds', () => {
    admitted(store.admit(fixtureOperation({ device_sequence: 3 })));
    const before = store.nextMonotonicPosition();
    expect(store.admit(fixtureOperation({ device_sequence: 3 })).outcome).toBe('SEQUENCE_POSITION_ALREADY_HELD');
    expect(store.nextMonotonicPosition()).toBe(before);
  });

  /**
   * Rule 3, and the reason `witness` is a callback. If the minter throws after
   * the position has been drawn, the whole transaction rolls back — the counter
   * included — so a failed witness cannot leave a burnt position behind it.
   */
  it('allocates nothing when the witness throws', () => {
    const before = store.nextMonotonicPosition();
    expect(() =>
      store.admit({
        ...fixtureOperation(),
        witness: () => {
          throw new Error('no trusted time');
        },
      }),
    ).toThrow(/no trusted time/u);
    expect(store.nextMonotonicPosition()).toBe(before);
    expect(store.unsettledCount()).toBe(0);
  });

  /**
   * The frozen contract re-derives the digest from the stored bytes. A payload
   * that does not digest to the value inside the device signature is refused
   * HERE, at enqueue, rather than becoming a PAYLOAD_DIGEST_MISMATCH hours later
   * whose original bytes nobody can reconstruct.
   */
  it('refuses a payload whose bytes do not digest to the value the signature covers', () => {
    const operation = fixtureOperation({ payload_digest: 'f'.repeat(64) });
    expect(() => store.admit(operation)).toThrow(/frozen stored-operation contract/u);
    expect(store.unsettledCount()).toBe(0);
    expect(store.nextMonotonicPosition()).toBe(0);
  });

  // -------------------------------------------------------------------------
  // RESTART RECONSTRUCTION
  // -------------------------------------------------------------------------

  it('reconstructs the queue and the counter across a restart', () => {
    const first = queueReady();
    const second = queueReady({ device_sequence: 1 });
    const positionBefore = store.nextMonotonicPosition();

    restart();

    expect(store.unsettledCount()).toBe(2);
    expect(store.nextMonotonicPosition()).toBe(positionBefore);
    expect(store.find(first)?.queueState).toBe('READY_TO_FORWARD');
    expect(store.find(second)?.stored.envelope.device_sequence).toBe(1);
  });

  /**
   * THE DEFECT THE PERSISTED COUNTER PREVENTS, DEMONSTRATED.
   *
   * The queue is drained to empty — every entry settled and reclaimed — and then
   * restarted. A counter derived as `MAX(position) + 1` would find no rows and
   * answer zero, re-spending every position Edge has already signed a receipt
   * for. The persisted counter does not move.
   */
  it('never rewinds the counter, even after the queue has fully drained and been reclaimed', () => {
    for (let i = 0; i < 5; i += 1) {
      const id = queueReady({ device_sequence: i });
      store.claimForForwarding(id);
      store.settle(id, ACCEPTED);
    }
    const spent = store.nextMonotonicPosition();
    expect(spent).toBe(5);

    expect(store.pruneSettled(5)).toBe(5);
    expect(store.unsettledCount()).toBe(0);
    expect(store.settledCount()).toBe(0);

    restart();
    expect(store.nextMonotonicPosition()).toBe(spent);

    const next = admitted(store.admit(fixtureOperation({ device_sequence: 99 })));
    expect(store.find(next)?.stored.enqueued_edge_monotonic_position).toBe(spent);
  });

  it('hands out no position twice across many restarts', () => {
    const seen = new Set<number>();
    for (let round = 0; round < 12; round += 1) {
      for (let i = 0; i < 3; i += 1) {
        const id = admitted(store.admit(fixtureOperation({ device_sequence: round * 3 + i })));
        const position = store.find(id)?.stored.enqueued_edge_monotonic_position;
        expect(position).toBeDefined();
        expect(seen.has(position as number)).toBe(false);
        seen.add(position as number);
      }
      restart();
    }
    expect(seen.size).toBe(36);
  });

  /**
   * The durable monotonic clock resumes rather than restarting, so a backlog
   * that has been sitting for an hour does not look freshly enqueued to the
   * operator who restarted the service to look at it.
   */
  it('resumes the durable monotonic clock across a restart instead of restarting it', () => {
    queueReady();
    clock.advance(60_000);
    queueReady({ device_sequence: 1 });
    const before = store.metrics({ trustedTimeAvailable: false }).oldest_queued_monotonic_age_ms;
    expect(before).toBe(60_000);

    // A restart resets the PROCESS clock to zero; the durable one must not.
    clock = new FixtureClock();
    restart();
    expect(store.metrics({ trustedTimeAvailable: false }).oldest_queued_monotonic_age_ms).toBeGreaterThanOrEqual(60_000);
  });

  // -------------------------------------------------------------------------
  // CRASH AT A WRITE BOUNDARY
  // -------------------------------------------------------------------------

  /**
   * INTERRUPTED BETWEEN THE WRITE AND THE COMMIT.
   *
   * A second connection opens the same file, begins a transaction, writes the
   * counter advance and the row, and is then dropped without committing — which
   * is what a process death between those two points looks like on disk.
   *
   * The store must come back with NOTHING AHEAD OF DURABLE STATE: no row, and a
   * counter that never spent the position.
   */
  it('is not left ahead of durable state when a write is interrupted before its commit', () => {
    const surviving = queueReady();
    const positionBefore = store.nextMonotonicPosition();
    store.close();

    const raw = new DatabaseSync(join(directory.path, EDGE_QUEUE_DATABASE_FILENAME));
    for (const pragma of EDGE_QUEUE_PRAGMAS) raw.exec(pragma);
    raw.exec('BEGIN IMMEDIATE');
    raw
      .prepare(`UPDATE ${EDGE_QUEUE_COUNTER_TABLE} SET next_edge_monotonic_position = ? WHERE id = 1`)
      .run(positionBefore + 1);
    raw
      .prepare(
        `INSERT INTO ${EDGE_QUEUE_OPERATION_TABLE} (
           offline_operation_id, schema_version, envelope_json, payload_canonical_json, payload_digest, receipt_json,
           organisation_id, site_id, actor_user_id, device_id, device_sequence, policy_lease_id,
           enqueued_edge_monotonic_position, queue_state, settlement_json, attempt_count, failure_category,
           first_stored_monotonic_ms, last_attempt_monotonic_ms, next_attempt_monotonic_ms
         ) VALUES ('half-written', ?, '{"a":1}', '{}', ?, NULL, 'org-1', 'site-1', 'user-1', 'device-9', 0, 'lease-1',
                   ?, 'STORED_LOCAL', NULL, 0, 'NOT_ATTEMPTED', 0, NULL, 0)`,
      )
      .run(EDGE_QUEUE_SCHEMA_VERSION, 'e'.repeat(64), positionBefore);
    // The power goes out here. No COMMIT is ever issued.
    raw.close();

    store = open();
    expect(store.find('half-written')).toBeNull();
    expect(store.nextMonotonicPosition()).toBe(positionBefore);
    expect(store.find(surviving)).not.toBeNull();
  });

  /**
   * A process that died with a request in flight.
   *
   * The recovery sweep resumes it as UNKNOWN — never as ready, which would erase
   * the ambiguity, and never as failed, which would be Edge inventing a verdict
   * out of its own crash — and leaves the backoff exactly where
   * `claimForForwarding` wrote it BEFORE the request went out.
   */
  it('resumes an interrupted attempt as UNKNOWN, with its backoff intact', () => {
    const id = queueReady();
    store.claimForForwarding(id);
    const inFlight = store.find(id);
    expect(inFlight?.queueState).toBe('FORWARDING');
    expect(inFlight?.attemptCount).toBe(1);
    expect(inFlight?.nextAttemptMonotonicMs).toBe(clock.nowMs() + edgeQueueRetryDelayMs(1));

    restart();

    const recovered = store.find(id);
    expect(recovered?.queueState).toBe('UNKNOWN');
    expect(recovered?.stored.state).toBe('QUEUED');
    // The backoff survived. An Edge that came back with a reset delay would
    // hammer central with the same operation the moment it started.
    expect(recovered?.attemptCount).toBe(1);
    expect(recovered?.nextAttemptMonotonicMs).toBe(inFlight?.nextAttemptMonotonicMs);
    expect(recovered?.failureCategory).toBe('TRANSPORT_ERROR');
    // A crash is not a fact about the link, so the link gauge is untouched.
    expect(store.metrics({ trustedTimeAvailable: false }).consecutive_unknown_transport_results).toBe(0);
  });

  it('refuses to open a queue holding a position the counter has not spent, rather than resetting it', () => {
    queueReady();
    store.close();

    const raw = new DatabaseSync(join(directory.path, EDGE_QUEUE_DATABASE_FILENAME));
    for (const pragma of EDGE_QUEUE_PRAGMAS) raw.exec(pragma);
    // A counter rewind is refused by a trigger, so the only way to reach this
    // state is a file that arrived some other way. Recreate it by inserting an
    // entry at a position beyond the counter with the trigger dropped.
    raw.exec('DROP TRIGGER edge_queue_position_below_counter');
    raw
      .prepare(
        `INSERT INTO ${EDGE_QUEUE_OPERATION_TABLE} (
           offline_operation_id, schema_version, envelope_json, payload_canonical_json, payload_digest, receipt_json,
           organisation_id, site_id, actor_user_id, device_id, device_sequence, policy_lease_id,
           enqueued_edge_monotonic_position, queue_state, settlement_json, attempt_count, failure_category,
           first_stored_monotonic_ms, last_attempt_monotonic_ms, next_attempt_monotonic_ms
         ) VALUES ('ahead', ?, '{"a":1}', '{}', ?, NULL, 'org-1', 'site-1', 'user-1', 'device-9', 0, 'lease-1',
                   9999, 'STORED_LOCAL', NULL, 0, 'NOT_ATTEMPTED', 0, NULL, 0)`,
      )
      .run(EDGE_QUEUE_SCHEMA_VERSION, 'e'.repeat(64));
    raw.close();

    // Refusing to operate is recoverable — the readiness probe goes down and an
    // operator looks at the box. Quietly restarting the count is not, because
    // nobody finds out.
    expect(() => open()).toThrow(MalformedEdgeQueueError);
  });

  // -------------------------------------------------------------------------
  // NO LOCAL PATH TO "CENTRAL COMMITTED"
  // -------------------------------------------------------------------------

  it('refuses to record a central answer for an operation that was never forwarded', () => {
    const id = queueReady();
    expect(() => store.settle(id, ACCEPTED)).toThrow(EdgeQueueTransitionError);
    expect(store.find(id)?.stored.state).toBe('QUEUED');
    expect(store.find(id)?.stored.settlement).toBeNull();
  });

  it('settles only into the state central’s own answer proves', () => {
    const accepted = queueReady();
    store.claimForForwarding(accepted);
    store.settle(accepted, ACCEPTED);
    expect(store.find(accepted)?.queueState).toBe('CENTRAL_APPLIED');
    expect(store.find(accepted)?.stored.state).toBe('TERMINAL');
    expect(store.find(accepted)?.stored.settlement).toEqual(ACCEPTED);

    const refused = queueReady({ device_sequence: 1 });
    store.claimForForwarding(refused);
    store.settle(refused, REFUSED);
    expect(store.find(refused)?.queueState).toBe('FAILED_TERMINAL');
    expect(store.find(refused)?.stored.state).toBe('TERMINAL');
  });

  it('keeps an entry QUEUED while central has only acknowledged it', () => {
    const id = queueReady();
    store.claimForForwarding(id);
    store.recordCentralProgress(id, 'CENTRAL_RECEIVED');
    expect(store.find(id)?.stored.state).toBe('QUEUED');
    store.recordCentralProgress(id, 'CENTRAL_APPLYING');
    expect(store.find(id)?.stored.state).toBe('QUEUED');

    // And still forwardable once the backoff from the last attempt elapses:
    // central holding an APPLYING receipt is exactly the case WP-20's
    // processing lease exists to reclaim and retry, so Edge must ask again
    // rather than treat the acknowledgement as the answer.
    expect(store.forwardableHeads()).toHaveLength(0);
    clock.advance(edgeQueueRetryDelayMs(1));
    expect(store.forwardableHeads().map((entry) => entry.stored.envelope.offline_operation_id)).toContain(id);
  });

  it('never settles an entry on an unknown outcome, however many attempts fail', () => {
    const id = queueReady();
    for (let attempt = 0; attempt < 20; attempt += 1) {
      store.claimForForwarding(id);
      store.recordTransportUnknown(id, 'TIMED_OUT');
    }
    const entry = store.find(id);
    expect(entry?.stored.state).toBe('QUEUED');
    expect(entry?.stored.settlement).toBeNull();
    expect(entry?.attemptCount).toBe(20);
    expect(store.metrics({ trustedTimeAvailable: false }).consecutive_unknown_transport_results).toBe(20);
  });

  it('files a connection that never established as retryable, and a timeout as unknown', () => {
    const clean = queueReady();
    store.claimForForwarding(clean);
    store.recordTransportUnknown(clean, 'CONNECT_FAILED');
    expect(store.find(clean)?.queueState).toBe('FAILED_RETRYABLE');

    const ambiguous = queueReady({ device_sequence: 1 });
    store.claimForForwarding(ambiguous);
    store.recordTransportUnknown(ambiguous, 'TIMED_OUT');
    expect(store.find(ambiguous)?.queueState).toBe('UNKNOWN');
  });

  it('will not touch an entry central has already answered', () => {
    const id = queueReady();
    store.claimForForwarding(id);
    store.settle(id, ACCEPTED);
    expect(store.settle(id, REFUSED)).toBe(false);
    expect(store.claimForForwarding(id)).toBe(false);
    expect(store.recordTransportUnknown(id, 'TIMED_OUT')).toBe(false);
    expect(store.find(id)?.stored.settlement).toEqual(ACCEPTED);
  });

  // -------------------------------------------------------------------------
  // CAPACITY
  // -------------------------------------------------------------------------

  it('refuses admission at capacity rather than evicting anything', () => {
    store.close();
    store = open({ maxUnsettled: 3 });

    const stored = [0, 1, 2].map((sequence) => queueReady({ device_sequence: sequence }));
    expect(store.capacityState()).toBe('REFUSING_AT_CAPACITY');

    const refused = store.admit(fixtureOperation({ device_sequence: 3 }));
    expect(refused.outcome).toBe('AT_CAPACITY');

    // Nothing was evicted, nothing was overwritten, and the oldest entry — the
    // one an eviction policy would have taken — is exactly where it was.
    expect(store.unsettledCount()).toBe(3);
    for (const id of stored) expect(store.find(id)).not.toBeNull();
  });

  it('reports a degraded band before it starts refusing', () => {
    store.close();
    store = open({ maxUnsettled: 10 });
    expect(store.capacityState()).toBe('ACCEPTING');
    for (let i = 0; i < 9; i += 1) queueReady({ device_sequence: i });
    expect(store.capacityState()).toBe('DEGRADED_NEAR_CAPACITY');
    queueReady({ device_sequence: 9 });
    expect(store.capacityState()).toBe('REFUSING_AT_CAPACITY');
  });

  /**
   * The bound is on UNSETTLED entries, so central answering makes room. That is
   * the only thing that does — the store never makes room for itself by
   * discarding work nobody else is holding.
   */
  it('makes room only when central answers, never by discarding queued work', () => {
    store.close();
    store = open({ maxUnsettled: 2, settledRetention: 8 });
    const first = queueReady({ device_sequence: 0 });
    queueReady({ device_sequence: 1 });
    expect(store.admit(fixtureOperation({ device_sequence: 2 })).outcome).toBe('AT_CAPACITY');

    store.claimForForwarding(first);
    store.settle(first, ACCEPTED);
    expect(store.admit(fixtureOperation({ device_sequence: 2 })).outcome).toBe('ADMITTED');
    // The settled entry is still there as provenance; it simply no longer counts.
    expect(store.find(first)).not.toBeNull();
  });

  it('reclaims only settled rows when retention is exceeded, oldest conversation first', () => {
    store.close();
    store = open({ maxUnsettled: 32, settledRetention: 2 });

    const settled: string[] = [];
    for (let i = 0; i < 3; i += 1) {
      const id = queueReady({ device_sequence: i });
      store.claimForForwarding(id);
      store.settle(id, ACCEPTED);
      settled.push(id);
      clock.advance(1_000);
    }
    expect(store.settledCount()).toBe(3);

    // Admitting one more trims the settled set back to retention.
    admitted(store.admit(fixtureOperation({ device_sequence: 3 })));
    expect(store.settledCount()).toBe(2);
    expect(store.find(settled[0])).toBeNull();
    expect(store.find(settled[1])).not.toBeNull();
    expect(store.find(settled[2])).not.toBeNull();
  });

  it('refuses to delete an unresolved operation even when asked directly', () => {
    queueReady();
    // `pruneSettled` filters, and the database trigger is what makes the filter
    // a guarantee. Nothing unsettled leaves the table.
    expect(store.pruneSettled(100)).toBe(0);
    expect(store.unsettledCount()).toBe(1);
  });

  // -------------------------------------------------------------------------
  // ORDERING
  // -------------------------------------------------------------------------

  it('offers only the oldest unsettled position in each namespace', () => {
    queueReady({ device_sequence: 0 });
    queueReady({ device_sequence: 1 });
    queueReady({ device_sequence: 2 });

    const heads = store.forwardableHeads();
    expect(heads).toHaveLength(1);
    expect(heads[0].stored.envelope.device_sequence).toBe(0);
  });

  /**
   * THE ORDERING-INDEPENDENCE PROPERTY, WHICH IS THE ONE THAT MATTERS.
   *
   * One device is wedged on an operation that will not resolve. Every other
   * namespace — a different device, a different operative, a different site —
   * keeps making progress, because nothing about one namespace's head appears in
   * another's query and there is no global Edge order to share.
   */
  it('lets a wedged namespace block only itself', () => {
    const wedged = queueReady({ device_id: 'device-1', device_sequence: 0 });
    queueReady({ device_id: 'device-1', device_sequence: 1 });
    const otherDevice = queueReady({ device_id: 'device-2', device_sequence: 0 });
    const otherActor = queueReady({ actor_user_id: 'user-2', device_id: 'device-3', device_sequence: 0 });
    const otherSite = queueReady({ site_id: 'site-2', device_id: 'device-4', device_sequence: 0 });

    // The wedged device's head is in flight and never answers.
    store.claimForForwarding(wedged);

    const heads = store.forwardableHeads().map((entry) => entry.stored.envelope.offline_operation_id);
    expect(heads).toEqual(expect.arrayContaining([otherDevice, otherActor, otherSite]));
    expect(heads).toHaveLength(3);
    // And the wedged device's SECOND operation waits — a gap is a stall, and
    // sending past it would only be work central holds anyway.
    expect(heads).not.toContain(wedged);
  });

  /**
   * C10-07's escape, mirrored. A deterministic refusal from central settles the
   * head, the settled entry leaves the unsettled set, and the namespace moves
   * on. The unblocking answer comes from the party that can judge the operation.
   */
  it('unblocks a namespace when central answers its head, even with a refusal', () => {
    const poisoned = queueReady({ device_sequence: 0 });
    const behind = queueReady({ device_sequence: 1 });
    store.claimForForwarding(poisoned);
    expect(store.forwardableHeads().map((entry) => entry.stored.envelope.offline_operation_id)).toEqual([]);

    store.settle(poisoned, REFUSED);
    expect(store.forwardableHeads().map((entry) => entry.stored.envelope.offline_operation_id)).toEqual([behind]);
  });

  it('holds an entry back until its backoff has elapsed, then offers it again', () => {
    const id = queueReady();
    store.claimForForwarding(id);
    store.recordTransportUnknown(id, 'TIMED_OUT');
    expect(store.forwardableHeads()).toHaveLength(0);

    clock.advance(edgeQueueRetryDelayMs(1));
    expect(store.forwardableHeads().map((entry) => entry.stored.envelope.offline_operation_id)).toEqual([id]);
  });

  it('does not offer an operation that has not been witnessed yet', () => {
    admitted(store.admit(fixtureOperation()));
    expect(store.forwardableHeads()).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // METRICS
  // -------------------------------------------------------------------------

  it('reports aggregate metrics that satisfy the frozen shape', () => {
    const settled = queueReady({ device_sequence: 0 });
    queueReady({ device_sequence: 1 });
    store.claimForForwarding(settled);
    store.settle(settled, ACCEPTED);

    const metrics = store.metrics({ trustedTimeAvailable: true });
    expect(metrics.queued_count).toBe(1);
    expect(metrics.terminal_count).toBe(1);
    expect(metrics.trusted_time_available).toBe(true);
    expect(metrics.oldest_queued_monotonic_age_ms).toBe(0);
    // Aggregate only: there is no field whose cardinality is a person, a device
    // or a site, and `.strict()` refuses one being added.
    expect(Object.keys(metrics).sort()).toEqual(
      [
        'capacity',
        'consecutive_unknown_transport_results',
        'oldest_queued_monotonic_age_ms',
        'queued_count',
        'schema_version',
        'terminal_count',
        'trusted_time_available',
      ].sort(),
    );
  });

  it('reports an empty queue as having no oldest entry rather than as age zero', () => {
    expect(store.metrics({ trustedTimeAvailable: false }).oldest_queued_monotonic_age_ms).toBeNull();
  });

  it('clears the link gauge as soon as central says anything at all', () => {
    const id = queueReady();
    store.claimForForwarding(id);
    store.recordTransportUnknown(id, 'TIMED_OUT');
    expect(store.metrics({ trustedTimeAvailable: false }).consecutive_unknown_transport_results).toBe(1);
    store.claimForForwarding(id);
    store.recordCentralProgress(id, 'CENTRAL_RECEIVED');
    expect(store.metrics({ trustedTimeAvailable: false }).consecutive_unknown_transport_results).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Integrity on the way out
  // -------------------------------------------------------------------------

  /**
   * The derived columns are an INDEX, not a second source of truth. One edited
   * to point an entry at another device makes the row unreadable rather than
   * making it lie.
   */
  it('refuses to read back an entry whose indexed columns no longer match the signed envelope', () => {
    const id = queueReady();
    store.close();

    const raw = new DatabaseSync(join(directory.path, EDGE_QUEUE_DATABASE_FILENAME));
    for (const pragma of EDGE_QUEUE_PRAGMAS) raw.exec(pragma);
    raw.exec('DROP TRIGGER edge_queue_signed_bytes_immutable');
    raw.prepare(`UPDATE ${EDGE_QUEUE_OPERATION_TABLE} SET device_id = 'device-stolen' WHERE offline_operation_id = ?`).run(id);
    raw.close();

    store = open();
    expect(() => store.find(id)).toThrow(MalformedEdgeQueueError);
  });
});
