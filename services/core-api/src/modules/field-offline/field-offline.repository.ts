import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { MAX_OFFLINE_DEVICE_SEQUENCE, type OfflineReplayNamespace } from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import {
  AUDIT_OFFLINE_OPERATION_FINALIZED,
  AUDIT_OFFLINE_OPERATION_RECEIVED,
  OFFLINE_PROCESSING_LEASE_MS,
  RECEIPT_STATUS_APPLYING,
  RECEIPT_STATUS_RECEIVED,
  RECEIPT_STATUS_UNKNOWN,
} from './field-offline.constants';
import type { OfflineStoredReceipt } from './field-offline.types';

/**
 * WP-20 Checkpoint B persistence primitives.
 *
 * This repository holds NO replay policy. Classification, fingerprint
 * comparison and the C10-02 identity binding all live in the service, because
 * they are decisions; what lives here is the set of storage operations those
 * decisions need, each carrying exactly the concurrency guarantee the ruling
 * requires. The service composes tx1 through `transaction`, so the cursor
 * lock, the receipt reads it classifies against, and the receipt insert all
 * commit or roll back as one unit (C10-08).
 */

export type Tx = Prisma.TransactionClient;

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

/**
 * BigInt boundary. `device_sequence` is BIGINT in Postgres but the contract's
 * arithmetic (`last_finalized + 1`) is JavaScript number arithmetic, so every
 * crossing asserts the safe-integer range rather than letting `Number()`
 * quietly round a sequence into a DIFFERENT queue position — which would
 * re-admit a consumed position, the exact duplication WP-20 forbids.
 */
export function sequenceFromDb(value: bigint): number {
  if (value < 0n || value > BigInt(MAX_OFFLINE_DEVICE_SEQUENCE)) {
    throw new RangeError('offline device_sequence is outside the safe-integer range');
  }
  return Number(value);
}

export function nullableSequenceFromDb(value: bigint | null): number | null {
  return value === null ? null : sequenceFromDb(value);
}

export function sequenceToDb(value: number): bigint {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_OFFLINE_DEVICE_SEQUENCE) {
    throw new RangeError('offline device_sequence is outside the safe-integer range');
  }
  return BigInt(value);
}

interface NamespaceColumns {
  organisationId: string;
  siteId: string;
  userId: string;
  deviceId: string;
}

/** The authenticated namespace (C10-02) expressed as Prisma column names. */
function namespaceWhere(namespace: OfflineReplayNamespace): NamespaceColumns {
  return {
    organisationId: namespace.organisation_id,
    siteId: namespace.site_id,
    userId: namespace.user_id,
    deviceId: namespace.device_id,
  };
}

const receiptProjection = {
  id: true,
  offlineOperationId: true,
  deviceSequence: true,
  operationKind: true,
  requestFingerprint: true,
  downstreamIdempotencyKey: true,
  status: true,
  outcome: true,
  conflictCode: true,
  resultRef: true,
  resultSnapshot: true,
  finalizedAt: true,
} as const;

interface ReceiptRow {
  id: string;
  offlineOperationId: string;
  deviceSequence: bigint;
  operationKind: string;
  requestFingerprint: string;
  downstreamIdempotencyKey: string;
  status: string;
  outcome: string | null;
  conflictCode: string | null;
  resultRef: string | null;
  resultSnapshot: Prisma.JsonValue | null;
  finalizedAt: Date | null;
}

function mapReceipt(row: ReceiptRow): OfflineStoredReceipt {
  return { ...row, deviceSequence: sequenceFromDb(row.deviceSequence) };
}

export interface CreateReceiptInput {
  namespace: OfflineReplayNamespace;
  offlineOperationId: string;
  deviceSequence: number;
  operationKind: string;
  requestFingerprint: string;
  downstreamIdempotencyKey: string;
  /** C10-06: the client's CLAIM of when it queued the operation. Telemetry. */
  clientCreatedAt: Date;
  firstTraceId: string;
}

export interface FinalizeInput {
  namespace: OfflineReplayNamespace;
  receiptId: string;
  offlineOperationId: string;
  deviceSequence: number;
  operationKind: string;
  requestFingerprint: string;
  outcome: 'APPLIED' | 'REJECTED';
  conflictCode: string | null;
  resultRef: string | null;
  resultSnapshot: Record<string, unknown> | null;
  traceId: string;
  /**
   * B10-01: the `attemptCount` this worker's claim established. Every write
   * this attempt makes to the receipt is fenced on it, so a worker whose lease
   * was legally stolen cannot land a write behind the newer attempt's back.
   */
  claimGeneration: number;
}

export interface MarkUnknownInput {
  namespace: OfflineReplayNamespace;
  receiptId: string;
  offlineOperationId: string;
  deviceSequence: number;
  operationKind: string;
  requestFingerprint: string;
  traceId: string;
  /** B10-01: see FinalizeInput.claimGeneration. */
  claimGeneration: number;
}

/**
 * B10-01. `lost` means the CAS fence did not match: this attempt no longer
 * owns the receipt, so it mutated NOTHING — not the receipt, not the cursor,
 * not the audit trail — and its caller must report what the owning attempt
 * recorded rather than its own stale verdict.
 */
export type FinalizeOutcome =
  | {
      kind: 'finalized';
      /** Server clock, taken inside the finalizing transaction. */
      finalizedAt: Date;
      /** The cursor value AFTER the forward-only advance. */
      lastFinalizedSequence: number | null;
    }
  | { kind: 'lost' };

/** B10-01: same fence, same two answers, for the infrastructure-fault path. */
export type MarkUnknownOutcome = { kind: 'marked' } | { kind: 'lost' };

@Injectable()
export class FieldOfflineRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  // -------------------------------------------------------------------------
  // Shared primitives
  // -------------------------------------------------------------------------

  /**
   * Runs the caller's unit of work in one interactive transaction. tx1 needs
   * the cursor lock, the receipt reads and the receipt insert to be atomic: a
   * classification made against receipts read OUTSIDE the lock could already
   * be stale by the time the insert lands, which is how a second effect gets
   * authorised.
   */
  async transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(work);
  }

  /**
   * The authoritative server clock, per the WP-19/C9-06 patrol precedent:
   * `clock_timestamp()` and never `now()`. Postgres pins `now()` to
   * transaction START, which is BEFORE the cursor row lock was acquired — a
   * receipt time taken from it would predate the serialization boundary the
   * receipt claims to have crossed.
   */
  private async dbNow(tx: Tx): Promise<Date> {
    const rows = await tx.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const first = rows[0];
    if (!first) throw new Error('clock_timestamp returned no row');
    return first.now;
  }

  /**
   * Identity and disposition ONLY (C10-11). No body, no recipients, no
   * need-to-know summary, no domain error text — an audit row is read by
   * oversight, and a §62.1 access guard cannot re-evaluate content the row was
   * never meant to hold in the first place.
   */
  private async audit(tx: Tx, namespace: OfflineReplayNamespace, kind: string, payload: Prisma.InputJsonObject): Promise<void> {
    await tx.fieldAuditLog.create({
      data: {
        organisationId: namespace.organisation_id,
        siteId: namespace.site_id,
        // C10-02: the AUTHENTICATED actor, never an envelope claim.
        actorUserId: namespace.user_id,
        kind,
        payload,
      },
    });
  }

  /**
   * WP-17A/C7-07 write-time integrity check. FieldOfflineOperationReceipt
   * deliberately carries no Site foreign key (it is a reliability artefact),
   * so the site's existence in the organisation is proven HERE, before the
   * transaction that creates a cursor row and a receipt — otherwise the
   * cursor's own composite Restrict relation would surface as a raw FK error
   * mid-flight instead of a safe conflict code.
   */
  async siteExistsInOrganisation(organisationId: string, siteId: string): Promise<boolean> {
    const site = await this.prisma.site.findFirst({ where: { id: siteId, organisationId }, select: { id: true } });
    return site !== null;
  }

  // -------------------------------------------------------------------------
  // Cursor
  // -------------------------------------------------------------------------

  /**
   * Materialises the cursor row so tx1 always has something to lock.
   *
   * Deliberately OUTSIDE the locking transaction: a P2002 raised inside a
   * Prisma interactive transaction aborts the whole Postgres transaction (no
   * savepoint is taken), so a create/create race handled in place would poison
   * the very transaction that must go on to classify and insert. Losing the
   * race here is a no-op — the winner's row is the one both callers then lock.
   */
  async ensureCursor(namespace: OfflineReplayNamespace): Promise<void> {
    try {
      await this.prisma.fieldOfflineDeviceCursor.create({ data: { ...namespaceWhere(namespace), lastFinalizedSequence: null } });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
    }
  }

  /**
   * C10-08 serialization boundary: every decision about a device's queue
   * position is taken while holding this row. Two reconnects from the same
   * device therefore cannot both classify their sequence as FRESH.
   */
  async lockCursor(tx: Tx, namespace: OfflineReplayNamespace): Promise<{ lastFinalizedSequence: number | null } | null> {
    const rows = await tx.$queryRaw<Array<{ lastFinalizedSequence: bigint | null }>>(Prisma.sql`
      SELECT last_finalized_sequence AS "lastFinalizedSequence"
      FROM field_offline_device_cursors
      WHERE organisation_id = ${namespace.organisation_id}
        AND site_id = ${namespace.site_id}
        AND user_id = ${namespace.user_id}
        AND device_id = ${namespace.device_id}
      FOR UPDATE`);
    const first = rows[0];
    if (!first) return null;
    return { lastFinalizedSequence: nullableSequenceFromDb(first.lastFinalizedSequence) };
  }

  // -------------------------------------------------------------------------
  // Receipts
  // -------------------------------------------------------------------------

  /** The durable proof that makes REPLAY / SEQUENCE_REUSED / STALE distinguishable. */
  async findReceiptBySequence(tx: Tx, namespace: OfflineReplayNamespace, deviceSequence: number): Promise<OfflineStoredReceipt | null> {
    const row = await tx.fieldOfflineOperationReceipt.findUnique({
      where: {
        organisationId_siteId_userId_deviceId_deviceSequence: { ...namespaceWhere(namespace), deviceSequence: sequenceToDb(deviceSequence) },
      },
      select: receiptProjection,
    });
    return row === null ? null : mapReceipt(row);
  }

  /**
   * C10-03 OPERATION_ID_REUSED pre-check. The composite unique index is the
   * real backstop, but reading first lets the service answer with the safe
   * machine-readable code instead of surfacing a raw P2002.
   */
  async findReceiptByOperationId(tx: Tx, namespace: OfflineReplayNamespace, offlineOperationId: string): Promise<OfflineStoredReceipt | null> {
    const row = await tx.fieldOfflineOperationReceipt.findUnique({
      where: { organisationId_siteId_userId_deviceId_offlineOperationId: { ...namespaceWhere(namespace), offlineOperationId } },
      select: receiptProjection,
    });
    return row === null ? null : mapReceipt(row);
  }

  /**
   * C10-08 step tx1. The fingerprint and the server-derived downstream
   * idempotency key become durable BEFORE any domain effect is attempted, so
   * a crash between here and the domain call leaves a recoverable record
   * rather than an invisible one.
   */
  async createReceipt(tx: Tx, input: CreateReceiptInput): Promise<OfflineStoredReceipt> {
    const firstReceivedAt = await this.dbNow(tx);
    const row = await tx.fieldOfflineOperationReceipt.create({
      data: {
        ...namespaceWhere(input.namespace),
        deviceSequence: sequenceToDb(input.deviceSequence),
        offlineOperationId: input.offlineOperationId,
        operationKind: input.operationKind,
        requestFingerprint: input.requestFingerprint,
        downstreamIdempotencyKey: input.downstreamIdempotencyKey,
        clientCreatedAt: input.clientCreatedAt,
        firstReceivedAt,
        status: RECEIPT_STATUS_RECEIVED,
        firstTraceId: input.firstTraceId,
      },
      select: receiptProjection,
    });
    await this.audit(tx, input.namespace, AUDIT_OFFLINE_OPERATION_RECEIVED, {
      offline_operation_id: input.offlineOperationId,
      device_id: input.namespace.device_id,
      device_sequence: input.deviceSequence,
      operation_kind: input.operationKind,
      disposition: RECEIPT_STATUS_RECEIVED,
      request_fingerprint: input.requestFingerprint,
      trace_id: input.firstTraceId,
    });
    return mapReceipt(row);
  }

  /**
   * C10-08 step tx2: compare-and-set claim with a recovery lease.
   *
   * RECEIVED and UNKNOWN are claimable outright. APPLYING is claimable only
   * once its claim has aged past the lease — a NEWER claim belongs to a live
   * attempt, and stealing it would be the double-fire this work package
   * exists to prevent. APPLIED and REJECTED appear in no branch, so a
   * finalized receipt can never be re-claimed. The whole predicate lives in
   * the WHERE clause, so the winner is decided by the database's row lock
   * rather than by a read-then-write the loser could interleave with.
   *
   * B10-01: returns the CLAIM GENERATION — `attemptCount` as it stands after
   * this claim's increment — or null when the claim was lost. The generation
   * is the fencing token every subsequent write by this attempt carries, so a
   * worker that stalls past its lease cannot later overwrite the outcome of
   * the attempt that legally reclaimed the receipt.
   *
   * The read happens INSIDE the claiming transaction, after the CAS: the row
   * this updateMany touched is write-locked until commit, so no competing
   * claim can increment between the update and the read. A read outside the
   * transaction could observe a LATER attempt's count and hand this worker a
   * fencing token belonging to someone else — which would defeat the fence.
   */
  async claimForProcessing(receiptId: string): Promise<number | null> {
    return this.prisma.$transaction(async (tx) => {
      const now = await this.dbNow(tx);
      const leaseExpiry = new Date(now.getTime() - OFFLINE_PROCESSING_LEASE_MS);
      const claim = await tx.fieldOfflineOperationReceipt.updateMany({
        where: {
          id: receiptId,
          OR: [
            { status: { in: [RECEIPT_STATUS_RECEIVED, RECEIPT_STATUS_UNKNOWN] } },
            { status: RECEIPT_STATUS_APPLYING, processingClaimedAt: { lt: leaseExpiry } },
          ],
        },
        data: { status: RECEIPT_STATUS_APPLYING, processingClaimedAt: now, attemptCount: { increment: 1 } },
      });
      if (claim.count !== 1) return null;
      const claimed = await tx.fieldOfflineOperationReceipt.findUnique({ where: { id: receiptId }, select: { attemptCount: true } });
      // The row was just updated inside this very transaction, so its absence
      // is an integrity fault, not a race. Fail loudly rather than invent a
      // fencing token no write could ever match.
      if (claimed === null) throw new Error('offline receipt vanished inside its own claim transaction');
      return claimed.attemptCount;
    });
  }

  /**
   * C10-08 step tx3, success or DETERMINISTIC rejection.
   *
   * The receipt update and the cursor advance are ONE transaction: an
   * operation whose outcome is durable but whose queue position is not would
   * be reclassified FRESH on reconnect and re-executed. C10-07 is why a
   * rejection advances too — a rejected entry that kept its position would
   * wedge the queue behind a slot nothing could ever fill.
   *
   * The advance is forward-only. A stale finalizer that somehow arrives after
   * the cursor has moved on updates nothing rather than rewinding the queue.
   *
   * B10-01 CLAIM FENCE. The receipt write is a compare-and-set on
   * `(id, status = APPLYING, attemptCount = claimGeneration)`, and it runs
   * FIRST — before the cursor advance and before the audit row — so a lost
   * fence leaves the transaction having mutated nothing at all. The cursor
   * lock is still taken ahead of it to keep tx1's lock order and avoid a
   * deadlock; acquiring a lock is not a mutation, so ordering it first costs
   * the fence nothing.
   */
  async finalizeAndAdvance(input: FinalizeInput): Promise<FinalizeOutcome> {
    return this.prisma.$transaction(async (tx) => {
      // Same lock order as tx1 — cursor first — so the two paths cannot deadlock.
      await this.lockCursor(tx, input.namespace);
      const finalizedAt = await this.dbNow(tx);
      const sequence = sequenceToDb(input.deviceSequence);

      const fenced = await tx.fieldOfflineOperationReceipt.updateMany({
        // B10-01: `id` alone is NOT enough. A worker whose lease expired and
        // was legally reclaimed would otherwise overwrite the newer attempt's
        // finalized outcome — stale REJECTED landing on top of a real APPLIED.
        where: { id: input.receiptId, status: RECEIPT_STATUS_APPLYING, attemptCount: input.claimGeneration },
        data: {
          status: input.outcome,
          outcome: input.outcome,
          conflictCode: input.conflictCode,
          resultRef: input.resultRef,
          // The service builds this from a per-kind allowlist (C10-11/R6); this
          // cast is the single JSON boundary, not a licence to widen it.
          resultSnapshot: input.resultSnapshot === null ? Prisma.DbNull : (input.resultSnapshot as Prisma.InputJsonObject),
          finalizedAt,
        },
      });
      // Fence lost. NOTHING has been written yet — no cursor advance, no audit
      // row — so returning here leaves the newer attempt's record untouched
      // and its queue position exactly where that attempt put it.
      if (fenced.count === 0) return { kind: 'lost' };

      await tx.fieldOfflineDeviceCursor.updateMany({
        where: {
          ...namespaceWhere(input.namespace),
          OR: [{ lastFinalizedSequence: null }, { lastFinalizedSequence: { lt: sequence } }],
        },
        data: { lastFinalizedSequence: sequence },
      });

      const cursor = await tx.fieldOfflineDeviceCursor.findUnique({
        where: { organisationId_siteId_userId_deviceId: namespaceWhere(input.namespace) },
        select: { lastFinalizedSequence: true },
      });

      await this.audit(tx, input.namespace, AUDIT_OFFLINE_OPERATION_FINALIZED, {
        offline_operation_id: input.offlineOperationId,
        device_id: input.namespace.device_id,
        device_sequence: input.deviceSequence,
        operation_kind: input.operationKind,
        disposition: input.outcome,
        outcome: input.outcome,
        conflict_code: input.conflictCode,
        request_fingerprint: input.requestFingerprint,
        trace_id: input.traceId,
      });

      return { kind: 'finalized', finalizedAt, lastFinalizedSequence: nullableSequenceFromDb(cursor?.lastFinalizedSequence ?? null) };
    });
  }

  /**
   * C10-08 step tx3, INFRASTRUCTURE failure. The receipt records that the
   * outcome is unknown and the cursor does NOT move: an operation that died
   * mid-flight is retried into convergence, never skipped past. The retry
   * reclaims this receipt under the lease and re-invokes the domain with the
   * SAME stored downstream key, so the domain's own idempotency — not this
   * module — decides whether the first attempt had already landed.
   *
   * B10-01: fenced identically to `finalizeAndAdvance`, and for a sharper
   * reason. Unfenced, a stale worker's markUnknown would DOWNGRADE a newer
   * attempt's finalized APPLIED back to UNKNOWN — re-opening a queue position
   * whose effect has already committed, and inviting a third attempt to fire
   * it again. A lost fence writes no receipt change and no audit row.
   */
  async markUnknown(input: MarkUnknownInput): Promise<MarkUnknownOutcome> {
    return this.prisma.$transaction(async (tx) => {
      const fenced = await tx.fieldOfflineOperationReceipt.updateMany({
        where: { id: input.receiptId, status: RECEIPT_STATUS_APPLYING, attemptCount: input.claimGeneration },
        data: { status: RECEIPT_STATUS_UNKNOWN },
      });
      if (fenced.count === 0) return { kind: 'lost' };
      await this.audit(tx, input.namespace, AUDIT_OFFLINE_OPERATION_FINALIZED, {
        offline_operation_id: input.offlineOperationId,
        device_id: input.namespace.device_id,
        device_sequence: input.deviceSequence,
        operation_kind: input.operationKind,
        disposition: RECEIPT_STATUS_UNKNOWN,
        outcome: null,
        conflict_code: 'UNKNOWN_OUTCOME',
        request_fingerprint: input.requestFingerprint,
        trace_id: input.traceId,
      });
      return { kind: 'marked' };
    });
  }

  /**
   * B10-01 lost-fence recovery read. A fresh, NON-transactional read of the
   * receipt as it stands right now, so an attempt that lost its fence can
   * report what the owning attempt actually recorded instead of its own stale
   * verdict. Deliberately outside any transaction: the point is to observe the
   * OTHER attempt's committed work.
   */
  async getReceiptById(receiptId: string): Promise<OfflineStoredReceipt | null> {
    const row = await this.prisma.fieldOfflineOperationReceipt.findUnique({ where: { id: receiptId }, select: receiptProjection });
    return row === null ? null : mapReceipt(row);
  }

  /**
   * B10-01: the namespace's current cursor value, read without a lock. Used
   * only to rebuild `next_expected_sequence` for a reply whose outcome was
   * decided by ANOTHER attempt — the cursor is not being decided here, merely
   * reported, so the serialization boundary is not needed.
   */
  async readCursor(namespace: OfflineReplayNamespace): Promise<number | null> {
    const cursor = await this.prisma.fieldOfflineDeviceCursor.findUnique({
      where: { organisationId_siteId_userId_deviceId: namespaceWhere(namespace) },
      select: { lastFinalizedSequence: true },
    });
    return nullableSequenceFromDb(cursor?.lastFinalizedSequence ?? null);
  }
}
