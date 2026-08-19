import type { FieldOfflineOperationKind } from '@sentinel/contracts';

/**
 * WP-20 Checkpoint B constants (directive C10-02..C10-11).
 *
 * This module is the OFFLINE REPLAY EXECUTOR. It owns ordering, receipts and
 * effectively-once delivery; it owns NO domain rule. Every admitted operation
 * is handed to the existing WP-16/WP-18 service that already owns its
 * transaction, its idempotency table and its authorisation chain (C10-10).
 */

/**
 * C10-02: the action a principal must hold for each admitted operation kind.
 * These are the SAME actions the live HTTP routes require — replay must never
 * be a softer door into a capability than the online path, so the offline
 * executor re-checks the identical action rather than inventing an
 * `offline.*` vocabulary that could drift from §62.
 */
export const ACTION_FIELD_ASSIGNMENT_ACT = 'field.assignment.act';
export const ACTION_MESSAGE_SEND = 'field.message.send';
export const ACTION_MESSAGE_ACKNOWLEDGE = 'field.message.acknowledge';

export const REQUIRED_ACTION_FOR_KIND: Readonly<Record<FieldOfflineOperationKind, string>> = {
  FIELD_ASSIGNMENT_ACCEPT: ACTION_FIELD_ASSIGNMENT_ACT,
  FIELD_ASSIGNMENT_DECLINE: ACTION_FIELD_ASSIGNMENT_ACT,
  FIELD_ASSIGNMENT_START: ACTION_FIELD_ASSIGNMENT_ACT,
  FIELD_ASSIGNMENT_COMPLETE: ACTION_FIELD_ASSIGNMENT_ACT,
  INCIDENT_FIELD_MESSAGE_SEND: ACTION_MESSAGE_SEND,
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: ACTION_MESSAGE_ACKNOWLEDGE,
};

/**
 * Audit kinds written to FieldAuditLog — offline replay is a Field capability
 * and its trail rides the same site-scoped append-only table as WP-16..WP-19.
 *
 * IDENTITY AND DISPOSITION ONLY. A receipt is read back on reconnect and an
 * audit row is read by oversight, so neither may carry message bodies,
 * recipient lists or need-to-know summaries (§62.1, C10-11).
 */
export const AUDIT_OFFLINE_OPERATION_RECEIVED = 'OFFLINE_OPERATION_RECEIVED';
export const AUDIT_OFFLINE_OPERATION_FINALIZED = 'OFFLINE_OPERATION_FINALIZED';

/**
 * C10-08 crash recovery lease. A receipt left in APPLYING by a process that
 * died is reclaimable once its claim is older than this; a claim NEWER than
 * this belongs to a live attempt and yields OPERATION_IN_PROGRESS instead.
 *
 * The lease is what makes "effectively once" honest rather than "at most
 * once": the retry re-invokes the domain with the SAME stored downstream
 * idempotency key, so the domain's own idempotency converges the second
 * attempt onto the first result instead of double-firing.
 */
export const OFFLINE_PROCESSING_LEASE_MS = 60_000;

/** C10-08 receipt lifecycle statuses, as persisted in `status`. */
export const RECEIPT_STATUS_RECEIVED = 'RECEIVED';
export const RECEIPT_STATUS_APPLYING = 'APPLYING';
export const RECEIPT_STATUS_APPLIED = 'APPLIED';
export const RECEIPT_STATUS_REJECTED = 'REJECTED';
export const RECEIPT_STATUS_UNKNOWN = 'UNKNOWN';
