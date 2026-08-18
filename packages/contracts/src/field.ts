import { z } from 'zod';
import { DeliveryStateSchema, type DeliveryState } from './delivery.js';
import { OperationalSeveritySchema } from './threat.js';

const MAX_SUMMARY_BYTES = 8 * 1024;
export const MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES = 16 * 1024;
export const MAX_INCIDENT_FIELD_MESSAGE_BYTES = 64 * 1024;
export const MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS = 64;
export const MAX_OFFLINE_OPERATION_PAYLOAD_BYTES = 64 * 1024;

const scopedId = z.string().min(1).max(256);
const traceId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

function serializedByteLength(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  } catch {
    // A non-serialisable payload is not valid for an externally carried
    // contract and must fail the same bounded-payload validation.
    return Number.POSITIVE_INFINITY;
  }
}

const boundedObject = (maxBytes: number, name: string) => z.record(z.unknown()).refine(
  (value) => serializedByteLength(value) <= maxBytes,
  { message: `${name} must serialize to at most ${maxBytes} bytes` },
);

/** Audited operational state; this is deliberately distinct from realtime presence. */
export const FieldStateSchema = z.enum([
  'AVAILABLE',
  'PATROL',
  'OBSERVING',
  'RESPONDING',
  'ON_SCENE',
  'NEED_SUPPORT',
  'COMPROMISED',
  'OFF_DUTY',
]);
export type FieldState = z.infer<typeof FieldStateSchema>;

export const FieldAssignmentStatusSchema = z.enum([
  'REQUESTED',
  'ACCEPTED',
  'DECLINED',
  'IN_PROGRESS',
  'COMPLETED',
  'CANCELLED',
  'EXPIRED',
]);
export type FieldAssignmentStatus = z.infer<typeof FieldAssignmentStatusSchema>;

/** Assignment lifecycle, separate from the shared delivery/transport lifecycle. */
export const ALLOWED_FIELD_ASSIGNMENT_STATUS_TRANSITIONS: Readonly<Record<FieldAssignmentStatus, readonly FieldAssignmentStatus[]>> = {
  REQUESTED: ['ACCEPTED', 'DECLINED', 'CANCELLED', 'EXPIRED'],
  ACCEPTED: ['IN_PROGRESS', 'CANCELLED', 'EXPIRED'],
  DECLINED: [],
  IN_PROGRESS: ['COMPLETED', 'CANCELLED'],
  COMPLETED: [],
  CANCELLED: [],
  EXPIRED: [],
};

export function canTransitionFieldAssignmentStatus(from: FieldAssignmentStatus, to: FieldAssignmentStatus): boolean {
  return ALLOWED_FIELD_ASSIGNMENT_STATUS_TRANSITIONS[from].includes(to);
}

/** Need-to-know dispatch record. Delivery state always uses §76's shared enum. */
export const FieldAssignmentSchema = z.object({
  schema_version: z.literal(1),
  assignment_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  incident_id: scopedId.nullable(),
  assignee_user_id: scopedId,
  assignment_type: z.string().min(1).max(128),
  priority: OperationalSeveritySchema,
  status: FieldAssignmentStatusSchema,
  delivery_state: DeliveryStateSchema,
  need_to_know_summary: z.string().min(1).refine(
    (value) => Buffer.byteLength(value, 'utf8') <= MAX_SUMMARY_BYTES,
    { message: `need_to_know_summary must be at most ${MAX_SUMMARY_BYTES} bytes` },
  ),
  created_at: timestamp,
  updated_at: timestamp,
  expires_at: timestamp.nullable(),
  accepted_at: timestamp.nullable(),
  completed_at: timestamp.nullable(),
  created_by_user_id: scopedId,
  updated_by_user_id: scopedId,
  accepted_by_user_id: scopedId.nullable(),
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  if (new Date(value.updated_at) < new Date(value.created_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['updated_at'], message: 'updated_at must be >= created_at' });
  }
  if (value.expires_at !== null && new Date(value.expires_at) < new Date(value.created_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be >= created_at' });
  }
  if (['ACCEPTED', 'IN_PROGRESS', 'COMPLETED'].includes(value.status) && (value.accepted_at === null || value.accepted_by_user_id === null)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['accepted_at'], message: 'accepted states require accepted_at and accepted_by_user_id' });
  }
  if (value.accepted_at !== null && new Date(value.accepted_at) < new Date(value.created_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['accepted_at'], message: 'accepted_at must be >= created_at' });
  }
  if (value.accepted_by_user_id !== null && value.accepted_by_user_id !== value.assignee_user_id) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['accepted_by_user_id'], message: 'accepted_by_user_id must match assignee_user_id' });
  }
  if (value.status === 'COMPLETED' && value.completed_at === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['completed_at'], message: 'COMPLETED requires completed_at' });
  }
  if (value.completed_at !== null && new Date(value.completed_at) < new Date(value.created_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['completed_at'], message: 'completed_at must be >= created_at' });
  }
  if (value.completed_at !== null && value.accepted_at !== null && new Date(value.completed_at) < new Date(value.accepted_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['completed_at'], message: 'completed_at must be >= accepted_at' });
  }
});
export type FieldAssignment = z.infer<typeof FieldAssignmentSchema>;

export const FieldOperativeStateUpdateSchema = z.object({
  schema_version: z.literal(1),
  organisation_id: scopedId,
  site_id: scopedId,
  actor_user_id: scopedId,
  device_id: scopedId,
  state: FieldStateSchema,
  location: boundedObject(16 * 1024, 'location').nullable(),
  source_at: timestamp,
  /**
   * Client-observed telemetry only. Server modules must calculate
   * authoritative freshness from source_at and receipt time.
   */
  freshness_ms: z.number().int().nonnegative(),
  trace_id: traceId,
}).strict();
export type FieldOperativeStateUpdate = z.infer<typeof FieldOperativeStateUpdateSchema>;

export const PatrolRouteSchema = z.object({
  schema_version: z.literal(1),
  patrol_route_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  name: z.string().min(1).max(256),
  route_version: z.number().int().positive(),
  checkpoint_ids: z.array(scopedId).min(1).max(512).superRefine((ids, context) => {
    if (new Set(ids).size !== ids.length) context.addIssue({ code: z.ZodIssueCode.custom, message: 'checkpoint_ids must be unique' });
  }),
  created_at: timestamp,
  updated_at: timestamp,
  created_by_user_id: scopedId,
  trace_id: traceId,
}).strict().refine((value) => new Date(value.updated_at) >= new Date(value.created_at), {
  message: 'updated_at must be >= created_at', path: ['updated_at'],
});
export type PatrolRoute = z.infer<typeof PatrolRouteSchema>;

export const PatrolCheckpointSchema = z.object({
  schema_version: z.literal(1),
  patrol_checkpoint_id: scopedId,
  patrol_route_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  sequence_number: z.number().int().positive(),
  name: z.string().min(1).max(256),
  zone_id: scopedId.nullable(),
  location: boundedObject(16 * 1024, 'location').nullable(),
  trace_id: traceId,
}).strict();
export type PatrolCheckpoint = z.infer<typeof PatrolCheckpointSchema>;

export const CheckpointVerificationSchema = z.object({
  schema_version: z.literal(1),
  checkpoint_verification_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  patrol_route_id: scopedId,
  patrol_checkpoint_id: scopedId,
  operative_user_id: scopedId,
  device_id: scopedId,
  verification_method: z.string().min(1).max(128),
  verification_context: boundedObject(16 * 1024, 'verification_context'),
  source_at: timestamp,
  recorded_at: timestamp,
  idempotency_key: scopedId,
  trace_id: traceId,
}).strict().refine((value) => new Date(value.recorded_at) >= new Date(value.source_at), {
  message: 'recorded_at must be >= source_at', path: ['recorded_at'],
});
export type CheckpointVerification = z.infer<typeof CheckpointVerificationSchema>;

/**
 * WP-19 patrol execution.
 *
 * THE GAP THIS CLOSES
 * -------------------
 * WP-15 defined a patrol ROUTE (a versioned definition), its ordered
 * CHECKPOINTS, and a CHECKPOINT VERIFICATION (evidence that someone reached
 * one). Nothing tied those together into a single execution, so there was no
 * object that could answer "which operative is walking which version of which
 * route right now, and by when was each checkpoint due?" — and therefore no
 * server-owned basis for deciding LATE or MISSED. WP-19's roadmap entry
 * requires missed-checkpoint state, so that anchor has to exist first.
 *
 * ROUTE VERSUS EXECUTION
 * ----------------------
 * A run SNAPSHOTS the exact `route_version` it began under and materialises its
 * own checkpoint expectations at start time. Editing a route afterwards
 * therefore cannot rewrite what a completed patrol was required to do — the
 * historical truth of a patrol lives on the run, never on the definition.
 */
export const PatrolRunStatusSchema = z.enum([
  'SCHEDULED',
  'IN_PROGRESS',
  'COMPLETED',
  'ABANDONED',
  'EXPIRED',
]);
export type PatrolRunStatus = z.infer<typeof PatrolRunStatusSchema>;

export const ALLOWED_PATROL_RUN_TRANSITIONS: Readonly<Record<PatrolRunStatus, readonly PatrolRunStatus[]>> = {
  SCHEDULED: ['IN_PROGRESS', 'ABANDONED', 'EXPIRED'],
  IN_PROGRESS: ['COMPLETED', 'ABANDONED', 'EXPIRED'],
  COMPLETED: [],
  ABANDONED: [],
  EXPIRED: [],
};

export function canTransitionPatrolRunStatus(from: PatrolRunStatus, to: PatrolRunStatus): boolean {
  return ALLOWED_PATROL_RUN_TRANSITIONS[from].includes(to);
}

/**
 * Per-checkpoint state within one run.
 *
 * VERIFIED and LATE both mean the operative reached the checkpoint; they differ
 * only in whether they did so inside the expected window. MISSED means the
 * deadline passed with no verification, and is terminal.
 */
export const PatrolRunCheckpointStateSchema = z.enum(['PENDING', 'VERIFIED', 'LATE', 'MISSED']);
export type PatrolRunCheckpointState = z.infer<typeof PatrolRunCheckpointStateSchema>;

/**
 * One checkpoint expectation, materialised when the run starts.
 *
 * The three absolute timestamps are the entire timing model, and they are
 * server-computed once. A client never supplies them, and they are never
 * recomputed from a live route afterwards:
 *
 *   received_at <= late_after                  -> VERIFIED
 *   late_after  <  received_at <= missed_after -> LATE
 *   now         >  missed_after, still PENDING -> MISSED
 *
 * Absolute instants rather than offsets, deliberately: an offset must be
 * re-evaluated against a start time every time it is read, so drift or clock
 * disagreement would silently change historical judgements.
 */
export const PatrolRunCheckpointSchema = z.object({
  schema_version: z.literal(1),
  patrol_run_checkpoint_id: scopedId,
  patrol_run_id: scopedId,
  patrol_checkpoint_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  /** Authoritative ordering, snapshotted from the route version this run began under. */
  sequence_number: z.number().int().positive(),
  expected_at: timestamp,
  late_after: timestamp,
  missed_after: timestamp,
  state: PatrolRunCheckpointStateSchema,
  /** Server receipt time of the verification that resolved this checkpoint. */
  resolved_at: timestamp.nullable(),
  /** The verification record that resolved it, if any. */
  checkpoint_verification_id: scopedId.nullable(),
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  if (new Date(value.late_after) < new Date(value.expected_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['late_after'], message: 'late_after must be >= expected_at' });
  }
  if (new Date(value.missed_after) < new Date(value.late_after)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['missed_after'], message: 'missed_after must be >= late_after' });
  }
  const resolvedStates: readonly PatrolRunCheckpointState[] = ['VERIFIED', 'LATE'];
  if (resolvedStates.includes(value.state) && (value.resolved_at === null || value.checkpoint_verification_id === null)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['resolved_at'], message: 'VERIFIED and LATE require resolved_at and checkpoint_verification_id' });
  }
  if (value.state === 'PENDING' && value.resolved_at !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['resolved_at'], message: 'PENDING cannot carry resolved_at' });
  }
  if (value.state === 'MISSED' && value.checkpoint_verification_id !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['checkpoint_verification_id'], message: 'MISSED cannot reference a verification' });
  }
});
export type PatrolRunCheckpoint = z.infer<typeof PatrolRunCheckpointSchema>;

/** One operative walking one exact route version, with its own immutable schedule. */
export const PatrolRunSchema = z.object({
  schema_version: z.literal(1),
  patrol_run_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  patrol_route_id: scopedId,
  /** Snapshot of the route version this run began under. Later route edits never apply. */
  route_version: z.number().int().positive(),
  assigned_operative_user_id: scopedId,
  /** Set only when the patrol is executed as part of an incident response. */
  incident_id: scopedId.nullable(),
  status: PatrolRunStatusSchema,
  scheduled_start_at: timestamp,
  /** Server-owned. Null until the run actually starts. */
  started_at: timestamp.nullable(),
  completed_at: timestamp.nullable(),
  created_by_user_id: scopedId,
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  const startedStates: readonly PatrolRunStatus[] = ['IN_PROGRESS', 'COMPLETED'];
  if (startedStates.includes(value.status) && value.started_at === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['started_at'], message: 'IN_PROGRESS and COMPLETED require started_at' });
  }
  if (value.status === 'COMPLETED' && value.completed_at === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['completed_at'], message: 'COMPLETED requires completed_at' });
  }
  if (value.completed_at !== null && value.started_at !== null && new Date(value.completed_at) < new Date(value.started_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['completed_at'], message: 'completed_at must be >= started_at' });
  }
  if (value.status === 'SCHEDULED' && value.started_at !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['started_at'], message: 'SCHEDULED cannot carry started_at' });
  }
});
export type PatrolRun = z.infer<typeof PatrolRunSchema>;

/**
 * The authoritative on-time/late decision, expressed once so no call site can
 * reinvent it.
 *
 * `receivedAt` is the SERVER receipt time. A client-supplied source time is
 * telemetry and must never be passed here — which is the point of keeping this
 * a pure function over the run's own materialised expectation.
 *
 * Returns null when the deadline has already passed: the checkpoint is no
 * longer resolvable by verification and belongs to the missed sweep instead.
 */
export function resolveCheckpointState(
  receivedAt: Date,
  expectation: Pick<PatrolRunCheckpoint, 'late_after' | 'missed_after'>,
): Extract<PatrolRunCheckpointState, 'VERIFIED' | 'LATE'> | null {
  if (receivedAt.getTime() <= new Date(expectation.late_after).getTime()) return 'VERIFIED';
  if (receivedAt.getTime() <= new Date(expectation.missed_after).getTime()) return 'LATE';
  return null;
}

/**
 * True when a still-PENDING checkpoint has passed its deadline.
 *
 * Deliberately independent of any other checkpoint's progress: a checkpoint is
 * never missed merely because a later one was verified, and never because a
 * client said so. Only the run's own schedule and the server clock decide.
 */
export function isCheckpointMissed(
  now: Date,
  expectation: Pick<PatrolRunCheckpoint, 'state' | 'missed_after'>,
): boolean {
  return expectation.state === 'PENDING' && now.getTime() > new Date(expectation.missed_after).getTime();
}

export const IncidentFieldMessageSchema = z.object({
  schema_version: z.literal(1),
  incident_field_message_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  incident_id: scopedId,
  sender_user_id: scopedId,
  recipient_user_ids: z.array(scopedId).min(1).max(128).superRefine((ids, context) => {
    if (new Set(ids).size !== ids.length) context.addIssue({ code: z.ZodIssueCode.custom, message: 'recipient_user_ids must be unique' });
  }),
  body: z.string().min(1).refine(
    (value) => Buffer.byteLength(value, 'utf8') <= MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES,
    { message: `body must be at most ${MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES} bytes` },
  ).nullable(),
  media_refs: z.array(z.string().min(1).max(512)).max(MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS).default([]),
  delivery_state: DeliveryStateSchema,
  retention_class: z.string().min(1).max(128),
  sent_at: timestamp,
  expires_at: timestamp.nullable(),
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  if (value.body === null && value.media_refs.length === 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['body'], message: 'a message requires body or media_refs' });
  }
  if (value.expires_at !== null && new Date(value.expires_at) < new Date(value.sent_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be >= sent_at' });
  }
  if (serializedByteLength(value) > MAX_INCIDENT_FIELD_MESSAGE_BYTES) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: `message must serialize to at most ${MAX_INCIDENT_FIELD_MESSAGE_BYTES} bytes` });
  }
});
export type IncidentFieldMessage = z.infer<typeof IncidentFieldMessageSchema>;

export const FieldOfflineOperationSchema = z.object({
  schema_version: z.literal(1),
  offline_operation_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  device_id: scopedId,
  device_sequence: z.number().int().nonnegative(),
  idempotency_key: scopedId,
  operation_kind: z.string().min(1).max(128),
  payload: boundedObject(MAX_OFFLINE_OPERATION_PAYLOAD_BYTES, 'payload'),
  created_at: timestamp,
  trace_id: traceId,
}).strict();
export type FieldOfflineOperation = z.infer<typeof FieldOfflineOperationSchema>;

/** Stable key for durable duplicate-replay detection. */
export function offlineOperationReplayKey(operation: Pick<FieldOfflineOperation, 'organisation_id' | 'site_id' | 'device_id' | 'device_sequence'>): string {
  return `${operation.organisation_id}:${operation.site_id}:${operation.device_id}:${operation.device_sequence}`;
}

/** True only when candidate advances the same device's monotonic queue. */
export function isNewerOfflineOperation(
  previous: Pick<FieldOfflineOperation, 'device_id' | 'device_sequence'>,
  candidate: Pick<FieldOfflineOperation, 'device_id' | 'device_sequence'>,
): boolean {
  return previous.device_id === candidate.device_id && candidate.device_sequence > previous.device_sequence;
}

/** Convenience alias to make shared §76 semantics explicit at use sites. */
export type FieldDeliveryState = DeliveryState;
