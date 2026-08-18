import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  FieldAssignmentStatusSchema,
  isWithinJsonByteBudget,
  MAX_BOUNDED_JSON_BYTES,
  MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES,
  MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS,
} from './field.js';

/**
 * WP-20 offline operation contracts (directive C10-01..C10-11).
 *
 * THE INVARIANT
 * -------------
 * A reconnect may DELAY an authorised operation. It must never duplicate it,
 * reorder it, weaken its authorization, backdate server authority, or let a
 * changed request hide behind an old idempotency identity.
 *
 * V1 VERSUS V2 (C10-01)
 * ---------------------
 * `FieldOfflineOperationSchema` (schema_version 1, in field.ts) remains
 * parseable as legacy contract history; its wire meaning never changes
 * silently. THIS file defines the executable replay contract: schema_version
 * 2, a discriminated union in which every admitted operation kind carries its
 * own strict payload. An arbitrary string plus arbitrary JSON never reaches
 * the replay executor.
 *
 * WHAT THE ALLOWLIST DELIBERATELY EXCLUDES (C10-05)
 * -------------------------------------------------
 * Patrol start/verify, field state updates, route management, scheduling,
 * command abandonment, assignment creation/cancellation, oversight, incident
 * lifecycle, Whisper, evidence and Constitution approvals are NOT admitted.
 * WP-19 made SERVER receipt time authoritative for checkpoint timing; an
 * offline verification replayed later with a pretend-authoritative device
 * timestamp would destroy that invariant. Field state upserts the arriving
 * value into CURRENT state, so a stale offline sample could regress newer
 * live truth. We will not solve offline behavior by lying about time.
 *
 * CLIENT TIME IS TELEMETRY (C10-06)
 * ---------------------------------
 * `created_at` says when the client claims it queued the operation. It is
 * part of the semantic request identity, and it is NEVER server authority:
 * it cannot backdate a transition, become a message's sent_at, manufacture an
 * earlier acknowledgement, or override policy evaluated at replay time.
 */

const scopedId = z.string().min(1).max(256);
const traceId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

/** C10-03: per-device queues begin here; there is no reset endpoint. */
export const OFFLINE_SEQUENCE_START = 0;

/** Upper bound keeps a sequence inside JS safe-integer arithmetic. */
export const MAX_OFFLINE_DEVICE_SEQUENCE = 9_007_199_254_740_991;

const deviceSequence = z.number().int().nonnegative().max(MAX_OFFLINE_DEVICE_SEQUENCE);

// ---------------------------------------------------------------------------
// Admitted operation kinds and their strict payloads (C10-05)
// ---------------------------------------------------------------------------

export const FIELD_OFFLINE_OPERATION_KINDS = [
  'FIELD_ASSIGNMENT_ACCEPT',
  'FIELD_ASSIGNMENT_DECLINE',
  'FIELD_ASSIGNMENT_START',
  'FIELD_ASSIGNMENT_COMPLETE',
  'INCIDENT_FIELD_MESSAGE_SEND',
  'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
] as const;
export const FieldOfflineOperationKindSchema = z.enum(FIELD_OFFLINE_OPERATION_KINDS);
export type FieldOfflineOperationKind = z.infer<typeof FieldOfflineOperationKindSchema>;

/**
 * Assignment transitions reuse the WP-16 expected-status CAS shape. The
 * existing operative-only action boundary and status machine stay
 * authoritative (C10-10) — this payload only names the intent.
 */
export const OfflineAssignmentTransitionPayloadSchema = z
  .object({
    assignment_id: z.string().uuid(),
    expected_status: FieldAssignmentStatusSchema,
  })
  .strict();
export type OfflineAssignmentTransitionPayload = z.infer<typeof OfflineAssignmentTransitionPayloadSchema>;

/**
 * Message send carries the WP-18 strict send fields except the
 * server-injected replay idempotency/trace (the V2 envelope owns those).
 * Bounds are AT LEAST as strict as WP-18: recipient count, media count and
 * body byte budget are identical, and the domain service re-validates on
 * replay — this contract never widens what WP-18 accepts.
 */
export const OfflineIncidentMessageSendPayloadSchema = z
  .object({
    incident_id: z.string().uuid(),
    recipient_user_ids: z.array(scopedId).min(1).max(128),
    body: z.string().min(1).nullable().optional(),
    media_refs: z.array(z.string().min(1).max(512)).max(MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS).optional(),
    retention_class: z.string().min(1).max(128),
    expires_at: timestamp.nullable().optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (new Set(value.recipient_user_ids).size !== value.recipient_user_ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['recipient_user_ids'], message: 'recipient_user_ids must be unique' });
    }
    const body = value.body ?? null;
    const mediaRefs = value.media_refs ?? [];
    if (body === null && mediaRefs.length === 0) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['body'], message: 'a message requires body or media_refs' });
    }
    if (body !== null && Buffer.byteLength(body, 'utf8') > MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['body'], message: `body must be at most ${MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES} bytes` });
    }
  });
export type OfflineIncidentMessageSendPayload = z.infer<typeof OfflineIncidentMessageSendPayloadSchema>;

export const OfflineIncidentMessageAcknowledgePayloadSchema = z
  .object({
    message_id: z.string().uuid(),
  })
  .strict();
export type OfflineIncidentMessageAcknowledgePayload = z.infer<typeof OfflineIncidentMessageAcknowledgePayloadSchema>;

// ---------------------------------------------------------------------------
// The V2 envelope (C10-01, C10-02, C10-06)
// ---------------------------------------------------------------------------

/**
 * Envelope fields shared by every admitted kind.
 *
 * `organisation_id`, `site_id` and `device_id` are the CLIENT'S claim of its
 * namespace. They are bound — fail-closed — against the authenticated
 * principal and the authenticated device context before any receipt lookup or
 * replay result is returned (C10-02). No HTTP surface may treat `device_id`
 * from a JSON body as authenticated device identity.
 */
const offlineEnvelopeShape = {
  schema_version: z.literal(2),
  offline_operation_id: z.string().uuid(),
  organisation_id: scopedId,
  site_id: scopedId,
  device_id: scopedId,
  device_sequence: deviceSequence,
  idempotency_key: scopedId,
  /** Client telemetry only — never server authority (C10-06). */
  created_at: timestamp,
  /** Non-semantic: a legitimate retry may carry a fresh trace (C10-04). */
  trace_id: traceId,
} as const;

function offlineVariant<K extends FieldOfflineOperationKind, P extends z.ZodTypeAny>(kind: K, payload: P) {
  return z.object({ ...offlineEnvelopeShape, operation_kind: z.literal(kind), payload }).strict();
}

/**
 * C10-01: the executable replay contract. A kind outside the C10-05 allowlist
 * — or a payload that does not match its kind exactly — fails to parse, so it
 * can never reach the replay executor.
 */
export const FieldOfflineOperationV2Schema = z.discriminatedUnion('operation_kind', [
  offlineVariant('FIELD_ASSIGNMENT_ACCEPT', OfflineAssignmentTransitionPayloadSchema),
  offlineVariant('FIELD_ASSIGNMENT_DECLINE', OfflineAssignmentTransitionPayloadSchema),
  offlineVariant('FIELD_ASSIGNMENT_START', OfflineAssignmentTransitionPayloadSchema),
  offlineVariant('FIELD_ASSIGNMENT_COMPLETE', OfflineAssignmentTransitionPayloadSchema),
  offlineVariant('INCIDENT_FIELD_MESSAGE_SEND', OfflineIncidentMessageSendPayloadSchema),
  offlineVariant('INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', OfflineIncidentMessageAcknowledgePayloadSchema),
]);
export type FieldOfflineOperationV2 = z.infer<typeof FieldOfflineOperationV2Schema>;

// ---------------------------------------------------------------------------
// Sequence classification (C10-03)
// ---------------------------------------------------------------------------

export const OfflineSequenceClassificationSchema = z.enum(['FRESH', 'SEQUENCE_GAP', 'REPLAY', 'SEQUENCE_REUSED', 'SEQUENCE_STALE']);
export type OfflineSequenceClassification = z.infer<typeof OfflineSequenceClassificationSchema>;

/**
 * What the classifier is allowed to know: the cursor's last FINALIZED
 * sequence (null when the namespace has no cursor yet), the incoming
 * sequence, and — for already-consumed positions — whether a durable receipt
 * exists and whether its stored fingerprint matches this request.
 */
export interface OfflineSequenceObservation {
  last_finalized_sequence: number | null;
  incoming_sequence: number;
  receipt: { exists: false } | { exists: true; same_semantic_request: boolean };
}

/**
 * C10-03: contiguous, not merely increasing. The next admissible sequence is
 * exactly `last_finalized + 1` (or OFFLINE_SEQUENCE_START on a fresh
 * namespace). Anything beyond it is a GAP — a queue entry at N+1 must never
 * leapfrog N — and anything at or below the cursor is judged by its receipt:
 * same request replays the recorded outcome, a different request under the
 * same position is reuse, and a consumed position with no receipt is stale.
 * None of the non-FRESH classifications may produce a domain effect.
 */
export function classifyOfflineSequence(observation: OfflineSequenceObservation): OfflineSequenceClassification {
  const nextExpected = observation.last_finalized_sequence === null ? OFFLINE_SEQUENCE_START : observation.last_finalized_sequence + 1;
  if (observation.incoming_sequence === nextExpected) return 'FRESH';
  if (observation.incoming_sequence > nextExpected) return 'SEQUENCE_GAP';
  if (observation.receipt.exists) return observation.receipt.same_semantic_request ? 'REPLAY' : 'SEQUENCE_REUSED';
  return 'SEQUENCE_STALE';
}

/** The sequence a device should submit next, as reported back to clients. */
export function nextExpectedOfflineSequence(lastFinalizedSequence: number | null): number {
  return lastFinalizedSequence === null ? OFFLINE_SEQUENCE_START : lastFinalizedSequence + 1;
}

// ---------------------------------------------------------------------------
// Canonical semantic request + fingerprint (C10-04)
// ---------------------------------------------------------------------------

/**
 * The AUTHENTICATED namespace a fingerprint binds to. These are server-trusted
 * values from the principal and device context (C10-02), never the envelope's
 * own claims.
 */
export interface OfflineReplayNamespace {
  organisation_id: string;
  site_id: string;
  user_id: string;
  device_id: string;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortKeysDeep(record[key])]),
    );
  }
  return value;
}

/**
 * Canonical JSON: object keys sort recursively; ARRAY ORDER IS PRESERVED.
 * Two requests that differ only in object key order are the same request; two
 * requests whose arrays differ in order are different requests — unless a
 * kind-specific rule below says the array is a set.
 */
export function canonicalOfflineJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value)) ?? 'null';
}

/**
 * C10-04: kind-specific normalisation, permitted only where semantics require
 * it. `recipient_user_ids` represents a SET (WP-18 validates uniqueness), so
 * it is deterministically sorted; every other array — and every future
 * ordered, patrol-checkpoint-style array — is left exactly as sent.
 */
export function normaliseOfflineOperation(operation: FieldOfflineOperationV2): FieldOfflineOperationV2 {
  if (operation.operation_kind === 'INCIDENT_FIELD_MESSAGE_SEND') {
    return {
      ...operation,
      payload: { ...operation.payload, recipient_user_ids: [...operation.payload.recipient_user_ids].sort() },
    };
  }
  return operation;
}

/**
 * The canonical semantic request (C10-04): authenticated namespace, operation
 * identity, sequence, client idempotency key, kind, normalised payload and
 * client created_at. `trace_id` is excluded by construction — a retry with a
 * fresh trace is the same request.
 */
export function canonicaliseOfflineSemanticRequest(namespace: OfflineReplayNamespace, operation: FieldOfflineOperationV2): string {
  const normalised = normaliseOfflineOperation(operation);
  return canonicalOfflineJson({
    namespace: {
      organisation_id: namespace.organisation_id,
      site_id: namespace.site_id,
      user_id: namespace.user_id,
      device_id: namespace.device_id,
    },
    offline_operation_id: normalised.offline_operation_id,
    device_sequence: normalised.device_sequence,
    idempotency_key: normalised.idempotency_key,
    operation_kind: normalised.operation_kind,
    payload: normalised.payload,
    created_at: normalised.created_at,
  });
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * The stored request fingerprint. Same sequence + different fingerprint is a
 * conflict even when a downstream domain service would consider the client's
 * idempotency key a duplicate.
 */
export function fingerprintOfflineSemanticRequest(namespace: OfflineReplayNamespace, operation: FieldOfflineOperationV2): string {
  return sha256Hex(canonicaliseOfflineSemanticRequest(namespace, operation));
}

/**
 * C10-09: the executor derives the downstream idempotency key server-side; a
 * client-controlled key is never forwarded as the domain key, so two queue
 * entries cannot steer unrelated domain calls into one idempotency namespace.
 *
 * EXACT ENCODING (part of this contract's tests):
 *   "offline:" + hex(SHA-256(
 *     organisation_id + "\n" + site_id + "\n" + user_id + "\n" + device_id
 *     + "\n" + offline_operation_id + "\n" + operation_kind))
 *
 * The "\n" separator prevents two different field splits from concatenating
 * to the same preimage.
 */
export function deriveOfflineDownstreamIdempotencyKey(
  namespace: OfflineReplayNamespace,
  offlineOperationId: string,
  operationKind: FieldOfflineOperationKind,
): string {
  const preimage = [namespace.organisation_id, namespace.site_id, namespace.user_id, namespace.device_id, offlineOperationId, operationKind].join('\n');
  return `offline:${sha256Hex(preimage)}`;
}

// ---------------------------------------------------------------------------
// Machine-readable safe outcomes (C10-11)
// ---------------------------------------------------------------------------

export const OfflineOperationOutcomeSchema = z.enum(['APPLIED', 'REJECTED']);
export type OfflineOperationOutcome = z.infer<typeof OfflineOperationOutcomeSchema>;

/**
 * Receipt lifecycle (C10-08). APPLIED and deterministic REJECTED advance the
 * cursor; UNKNOWN never does — an operation that died mid-flight is retried
 * into convergence, not skipped past.
 */
export const OfflineReceiptStatusSchema = z.enum(['RECEIVED', 'APPLYING', 'APPLIED', 'REJECTED', 'UNKNOWN']);
export type OfflineReceiptStatus = z.infer<typeof OfflineReceiptStatusSchema>;

export const OFFLINE_CURSOR_ADVANCING_STATUSES: readonly OfflineReceiptStatus[] = ['APPLIED', 'REJECTED'];

/** True when a finalized receipt status consumes its queue position. */
export function offlineReceiptAdvancesCursor(status: OfflineReceiptStatus): boolean {
  return OFFLINE_CURSOR_ADVANCING_STATUSES.includes(status);
}

export const OfflineReplayConflictCodeSchema = z.enum([
  'DEVICE_CONTEXT_MISMATCH',
  'SITE_SCOPE_MISMATCH',
  'SEQUENCE_GAP',
  'SEQUENCE_REUSED',
  'SEQUENCE_STALE',
  'OPERATION_ID_REUSED',
  'OPERATION_NOT_ALLOWED',
  'OPERATION_IN_PROGRESS',
  'DOMAIN_REJECTED',
  'UNKNOWN_OUTCOME',
]);
export type OfflineReplayConflictCode = z.infer<typeof OfflineReplayConflictCodeSchema>;

/**
 * A finalized synchronization result. `finalized_at` is SERVER time; the
 * request's `created_at` deliberately has no field here — client time is
 * telemetry and never becomes authority (C10-06). A replay of a previously
 * rejected operation returns the SAME stored rejection with `replayed: true`.
 *
 * The bounded snapshot is safe metadata only. Foreign-tenant or non-entitled
 * detail never rides a result or a conflict: a domain 404/403 must not become
 * "exists but belongs to someone else".
 */
export const OfflineOperationResultSchema = z
  .object({
    schema_version: z.literal(2),
    offline_operation_id: z.string().uuid(),
    device_sequence: deviceSequence,
    operation_kind: FieldOfflineOperationKindSchema,
    outcome: OfflineOperationOutcomeSchema,
    replayed: z.boolean(),
    finalized_at: timestamp,
    next_expected_sequence: deviceSequence,
    result_ref: scopedId.nullable(),
    result_snapshot: z
      .record(z.unknown())
      .refine((value) => isWithinJsonByteBudget(value, MAX_BOUNDED_JSON_BYTES), {
        message: `result_snapshot must serialize to at most ${MAX_BOUNDED_JSON_BYTES} bytes`,
      })
      .nullable(),
    trace_id: traceId,
  })
  .strict();
export type OfflineOperationResult = z.infer<typeof OfflineOperationResultSchema>;

/** An unfinalized or refused submission, described without domain disclosure. */
export const OfflineReplayConflictSchema = z
  .object({
    schema_version: z.literal(2),
    conflict_code: OfflineReplayConflictCodeSchema,
    offline_operation_id: z.string().uuid().nullable(),
    device_sequence: deviceSequence.nullable(),
    expected_sequence: deviceSequence.nullable(),
    received_sequence: deviceSequence.nullable(),
    trace_id: traceId,
  })
  .strict();
export type OfflineReplayConflict = z.infer<typeof OfflineReplayConflictSchema>;

// ---------------------------------------------------------------------------
// Authenticated device context seam (C10-02)
// ---------------------------------------------------------------------------

/**
 * The internal, non-wire seam a future genuine device-authentication facility
 * will populate. WP-20 does not invent a trust engine; it defines where the
 * trusted identity plugs in. Every replay decision binds the operation's
 * claimed namespace against THIS context and the live principal, fail-closed.
 */
export interface AuthenticatedFieldDeviceContext {
  organisationId: string;
  userId: string;
  deviceId: string;
  authorisedSiteIds: readonly string[];
}
