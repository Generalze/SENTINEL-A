import type { OfflineOperationResult, OfflineReplayConflict } from '@sentinel/contracts';

/**
 * WP-20 Checkpoint B submission outcome.
 *
 * THREE OUTCOMES, NEVER A THROWN DOMAIN ERROR. The executor is a reliability
 * layer, so a domain refusal is DATA (a durable REJECTED receipt the device
 * can replay), not an exception that would leave the queue position ambiguous.
 * The only exceptions that escape `submit` are genuine infrastructure faults
 * raised before a receipt could be written.
 *
 *  - `result`   a finalized outcome (APPLIED or deterministic REJECTED),
 *               round-tripped through OfflineOperationResultSchema (C10-11);
 *  - `conflict` a refused or unfinalized submission described WITHOUT domain
 *               disclosure, round-tripped through OfflineReplayConflictSchema;
 *  - `invalid`  the raw envelope failed FieldOfflineOperationV2Schema, so it
 *               never reached persistence at all (C10-01). It carries no
 *               `trace_id` because an unparsed envelope has no trusted one.
 */
export type OfflineSubmissionOutcome =
  | { kind: 'result'; result: OfflineOperationResult }
  | { kind: 'conflict'; conflict: OfflineReplayConflict }
  | { kind: 'invalid'; issues: string[] };

/**
 * What a domain invocation is allowed to contribute to a receipt (C10-11/R6).
 *
 * An executor returns ONLY these two allowlisted values. It never hands back
 * the domain view itself, so no future edit can widen a snapshot by
 * accidentally serialising a message body, a recipient list or a
 * need-to-know summary into a record that is replayed on reconnect.
 */
export interface OfflineExecutionEffect {
  /** The primary identifier of the entity the operation acted on. */
  resultRef: string;
  /** Bounded, allowlist-built safe metadata. Identifiers and states only. */
  resultSnapshot: Record<string, unknown>;
}

/**
 * A receipt as the executor reads it back: the repository's own projection,
 * deliberately NOT the Prisma row type. `deviceSequence` has already crossed
 * the BigInt boundary with its safe-integer assertion applied, so no caller
 * can silently truncate a queue position.
 */
export interface OfflineStoredReceipt {
  id: string;
  offlineOperationId: string;
  deviceSequence: number;
  operationKind: string;
  requestFingerprint: string;
  downstreamIdempotencyKey: string;
  status: string;
  outcome: string | null;
  conflictCode: string | null;
  resultRef: string | null;
  resultSnapshot: unknown;
  finalizedAt: Date | null;
}

/**
 * The decision taken under the cursor lock in tx1 (C10-03/C10-08).
 *
 *  - `proceed` a durable receipt exists at this sequence carrying THIS
 *              request's fingerprint and is not finalized; the operation may
 *              be claimed and executed. Covers both a freshly created receipt
 *              and the resumption of an attempt that crashed in RECEIVED,
 *              APPLYING or UNKNOWN.
 *  - `replay`  a finalized receipt with the same fingerprint already answers
 *              this request; the stored outcome is returned verbatim (C10-11),
 *              never refetched from current domain state.
 *  - `refuse`  no effect may occur; the code is already safe to return.
 */
export type OfflineAdmission =
  | { kind: 'proceed'; receipt: OfflineStoredReceipt; lastFinalizedSequence: number | null }
  | { kind: 'replay'; receipt: OfflineStoredReceipt; lastFinalizedSequence: number | null }
  | { kind: 'refuse'; conflictCode: OfflineReplayConflict['conflict_code']; expectedSequence: number | null };
