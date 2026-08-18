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

/**
 * A checkpoint belongs to one exact ROUTE VERSION and carries the patrol
 * standard for that checkpoint (C9-04).
 *
 * Timing policy lives here, on the versioned definition, not on a mutable route
 * header and not on the run. Changing a patrol standard therefore means
 * publishing a NEW route version; version N is immutable once used. That is
 * what makes "later route edits cannot rewrite historical patrol truth"
 * enforceable rather than conventional — a run pins one version, and every one
 * of its checkpoints must originate from that same version.
 *
 * Offsets are relative to the run's server-owned `started_at`, so the same
 * standard produces correct absolute deadlines whenever the patrol actually
 * begins.
 */
export const PatrolCheckpointSchema = z.object({
  schema_version: z.literal(1),
  patrol_checkpoint_id: scopedId,
  patrol_route_id: scopedId,
  /** Part of the version identity: (patrol_route_id, route_version) is the real key. */
  route_version: z.number().int().positive(),
  organisation_id: scopedId,
  site_id: scopedId,
  sequence_number: z.number().int().positive(),
  name: z.string().min(1).max(256),
  zone_id: scopedId.nullable(),
  location: boundedObject(16 * 1024, 'location').nullable(),
  /** Earliest a verification counts. Arriving before this is TOO_EARLY, not credit. */
  window_open_offset_ms: z.number().int().nonnegative(),
  /** End of the on-time window. */
  late_after_offset_ms: z.number().int().nonnegative(),
  /** Deadline. Past this a verification cannot resolve the checkpoint at all. */
  missed_after_offset_ms: z.number().int().nonnegative(),
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  if (value.late_after_offset_ms < value.window_open_offset_ms) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['late_after_offset_ms'], message: 'late_after_offset_ms must be >= window_open_offset_ms' });
  }
  if (value.missed_after_offset_ms < value.late_after_offset_ms) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['missed_after_offset_ms'], message: 'missed_after_offset_ms must be >= late_after_offset_ms' });
  }
});
export type PatrolCheckpoint = z.infer<typeof PatrolCheckpointSchema>;

/**
 * Evidence that a named operative reached a checkpoint during a specific run
 * (C9-01).
 *
 * The run and run-checkpoint identities are part of the authoritative record.
 * Without them the same route and checkpoint executed twice — or twice
 * concurrently — produce indistinguishable evidence, and no audit could say
 * which patrol a verification belonged to.
 *
 * `source_at` is client telemetry; `recorded_at` is the server's authority.
 * There is deliberately NO constraint that recorded_at >= source_at: a device
 * clock five minutes fast must not be able to veto a perfectly valid server
 * receipt. The two are different kinds of claim and are stored side by side so
 * a skewed device is visible rather than authoritative.
 */
export const CheckpointVerificationSchema = z.object({
  schema_version: z.literal(1),
  checkpoint_verification_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  patrol_run_id: scopedId,
  patrol_run_checkpoint_id: scopedId,
  patrol_route_id: scopedId,
  patrol_checkpoint_id: scopedId,
  operative_user_id: scopedId,
  device_id: scopedId,
  verification_method: z.string().min(1).max(128),
  verification_context: boundedObject(16 * 1024, 'verification_context'),
  /** Client-reported observation time. Telemetry only. */
  source_at: timestamp,
  /** Server receipt time. The only value any timing decision may use. */
  recorded_at: timestamp,
  idempotency_key: scopedId,
  trace_id: traceId,
}).strict();
export type CheckpointVerification = z.infer<typeof CheckpointVerificationSchema>;

/**
 * WP-19 patrol execution.
 *
 * THE GAP THIS CLOSES
 * -------------------
 * WP-15 defined a patrol ROUTE, its ordered CHECKPOINTS, and a CHECKPOINT
 * VERIFICATION. Nothing tied those into a single execution, so nothing could
 * answer "which operative is walking which version of which route right now,
 * and by when was each checkpoint due?" — and therefore there was no
 * server-owned basis for LATE or MISSED, only a client assertion.
 *
 * ROUTE VERSUS EXECUTION
 * ----------------------
 * The route VERSION owns the relative standard; the RUN owns the materialised
 * absolute truth. At run start the server converts each versioned checkpoint's
 * offsets into fixed instants using the run's own `started_at`. Editing a route
 * afterwards cannot rewrite a finished patrol, and two concurrent runs of one
 * route never contend over shared rows.
 */
export const PatrolRunStatusSchema = z.enum([
  'SCHEDULED',
  'IN_PROGRESS',
  'COMPLETED',
  'ABANDONED',
  'CANCELLED',
]);
export type PatrolRunStatus = z.infer<typeof PatrolRunStatusSchema>;

/**
 * C9-03: EXPIRED is deliberately absent. It existed with no rule defining what
 * expiry meant, and an unspecified terminal state is a place for ambiguity to
 * hide. A run that is called off before starting is CANCELLED; one abandoned
 * after starting is ABANDONED.
 */
export const ALLOWED_PATROL_RUN_TRANSITIONS: Readonly<Record<PatrolRunStatus, readonly PatrolRunStatus[]>> = {
  SCHEDULED: ['IN_PROGRESS', 'CANCELLED'],
  IN_PROGRESS: ['COMPLETED', 'ABANDONED'],
  COMPLETED: [],
  ABANDONED: [],
  CANCELLED: [],
};

export function canTransitionPatrolRunStatus(from: PatrolRunStatus, to: PatrolRunStatus): boolean {
  return ALLOWED_PATROL_RUN_TRANSITIONS[from].includes(to);
}

/**
 * Per-checkpoint state within one run.
 *
 * VERIFIED and LATE both mean the operative reached it, differing only in
 * whether they did so inside the on-time window. MISSED means the deadline
 * passed unverified. CANCELLED means the expectation was withdrawn because the
 * run was abandoned before the checkpoint came due — it is NOT a way to erase
 * an already-overdue obligation.
 */
export const PatrolRunCheckpointStateSchema = z.enum(['PENDING', 'VERIFIED', 'LATE', 'MISSED', 'CANCELLED']);
export type PatrolRunCheckpointState = z.infer<typeof PatrolRunCheckpointStateSchema>;

/** Outcome of evaluating a verification receipt against a materialised window. */
export const CheckpointTimingOutcomeSchema = z.enum(['TOO_EARLY', 'VERIFIED', 'LATE', 'EXPIRED']);
export type CheckpointTimingOutcome = z.infer<typeof CheckpointTimingOutcomeSchema>;

/** States that record a completed verification, and so require its evidence. */
const RESOLVED_CHECKPOINT_STATES: readonly PatrolRunCheckpointState[] = ['VERIFIED', 'LATE'];

/**
 * One checkpoint expectation, materialised when the run starts.
 *
 * The three absolute instants are the whole timing model, server-computed once
 * from the route version's offsets and the run's `started_at`:
 *
 *   received  <  window_opens_at                 -> TOO_EARLY (no mutation)
 *   window_opens_at <= received <= late_after    -> VERIFIED
 *   late_after   <  received <= missed_after     -> LATE
 *   received  >  missed_after                    -> EXPIRED (no verification transition)
 *   now       >  missed_after, still PENDING     -> MISSED (server sweep only)
 *
 * Absolute instants rather than offsets on the run, deliberately: an offset must
 * be re-evaluated against a start time every time it is read, so drift, clock
 * disagreement, or an edit to the start would silently change historical
 * judgements. A materialised instant is a fact.
 */
export const PatrolRunCheckpointSchema = z.object({
  schema_version: z.literal(1),
  patrol_run_checkpoint_id: scopedId,
  patrol_run_id: scopedId,
  patrol_checkpoint_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  /** Authoritative ordering, snapshotted from the route version this run pinned. */
  sequence_number: z.number().int().positive(),
  /** C9-02: earliest a verification counts. Named for what it means, not for an expectation. */
  window_opens_at: timestamp,
  late_after: timestamp,
  missed_after: timestamp,
  state: PatrolRunCheckpointStateSchema,
  /** Server receipt time of the verification that resolved this checkpoint. */
  resolved_at: timestamp.nullable(),
  checkpoint_verification_id: scopedId.nullable(),
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  if (new Date(value.late_after) < new Date(value.window_opens_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['late_after'], message: 'late_after must be >= window_opens_at' });
  }
  if (new Date(value.missed_after) < new Date(value.late_after)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['missed_after'], message: 'missed_after must be >= late_after' });
  }

  const isResolved = RESOLVED_CHECKPOINT_STATES.includes(value.state);

  // C9-02: resolution evidence and state must agree in BOTH directions. An
  // unresolved state carrying a verification id, or a resolved state missing
  // one, is a row that asserts two different histories at once.
  if (isResolved && (value.resolved_at === null || value.checkpoint_verification_id === null)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['resolved_at'], message: 'VERIFIED and LATE require resolved_at and checkpoint_verification_id' });
  }
  if (!isResolved && (value.resolved_at !== null || value.checkpoint_verification_id !== null)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['resolved_at'],
      message: 'PENDING, MISSED and CANCELLED must carry no resolved_at or checkpoint_verification_id',
    });
  }

  // C9-02: the recorded state must equal what the authoritative timing rule
  // says about its own resolution time. Without this a row could claim
  // VERIFIED while its resolved_at sits inside the LATE window.
  if (isResolved && value.resolved_at !== null) {
    const outcome = resolveCheckpointTiming(new Date(value.resolved_at), value);
    if (outcome !== value.state) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['state'],
        message: `state ${value.state} contradicts resolved_at, which the timing rule classifies as ${outcome}`,
      });
    }
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
  /** Pinned version. Every run checkpoint must originate from this exact version. */
  route_version: z.number().int().positive(),
  assigned_operative_user_id: scopedId,
  /** Set only when the patrol is executed as part of an incident response. */
  incident_id: scopedId.nullable(),
  status: PatrolRunStatusSchema,
  /** Planned start. Kept distinct from started_at so a late start stays visible. */
  scheduled_start_at: timestamp,
  /** Server-owned actual start; the basis for all materialisation. Null until started. */
  started_at: timestamp.nullable(),
  ended_at: timestamp.nullable(),
  created_by_user_id: scopedId,
  trace_id: traceId,
}).strict().superRefine((value, context) => {
  const started: readonly PatrolRunStatus[] = ['IN_PROGRESS', 'COMPLETED', 'ABANDONED'];
  if (started.includes(value.status) && value.started_at === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['started_at'], message: `${value.status} requires started_at` });
  }
  if (!started.includes(value.status) && value.started_at !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['started_at'], message: `${value.status} cannot carry started_at` });
  }

  // C9-03: an end time exists only for runs that actually ended.
  const ended: readonly PatrolRunStatus[] = ['COMPLETED', 'ABANDONED', 'CANCELLED'];
  if (ended.includes(value.status) && value.ended_at === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['ended_at'], message: `${value.status} requires ended_at` });
  }
  if (!ended.includes(value.status) && value.ended_at !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['ended_at'], message: `${value.status} cannot carry ended_at` });
  }
  if (value.ended_at !== null && value.started_at !== null && new Date(value.ended_at) < new Date(value.started_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['ended_at'], message: 'ended_at must be >= started_at' });
  }
});
export type PatrolRun = z.infer<typeof PatrolRunSchema>;

/**
 * Materialises one checkpoint's absolute window from the route version's
 * relative standard and the run's server-owned actual start.
 *
 * Deliberately takes `startedAt` rather than `scheduled_start_at`: a patrol that
 * begins late gets a correspondingly shifted window, and the lateness of the
 * start is evidenced separately by the two fields differing.
 */
export function materialiseCheckpointWindow(
  startedAt: Date,
  policy: Pick<PatrolCheckpoint, 'window_open_offset_ms' | 'late_after_offset_ms' | 'missed_after_offset_ms'>,
): { window_opens_at: string; late_after: string; missed_after: string } {
  const at = (offsetMs: number): string => new Date(startedAt.getTime() + offsetMs).toISOString();
  return {
    window_opens_at: at(policy.window_open_offset_ms),
    late_after: at(policy.late_after_offset_ms),
    missed_after: at(policy.missed_after_offset_ms),
  };
}

/**
 * The authoritative timing decision, expressed once so no call site reinvents it.
 *
 * `receivedAt` is the SERVER receipt time, taken inside the transaction that
 * holds the run-checkpoint row. A client-supplied source time is telemetry and
 * must never be passed here.
 *
 * TOO_EARLY exists because arriving hours before a checkpoint is due is not
 * compliance — without it, a patrol could be "completed" the moment it started.
 */
export function resolveCheckpointTiming(
  receivedAt: Date,
  window: Pick<PatrolRunCheckpoint, 'window_opens_at' | 'late_after' | 'missed_after'>,
): CheckpointTimingOutcome {
  const received = receivedAt.getTime();
  if (received < new Date(window.window_opens_at).getTime()) return 'TOO_EARLY';
  if (received <= new Date(window.late_after).getTime()) return 'VERIFIED';
  if (received <= new Date(window.missed_after).getTime()) return 'LATE';
  return 'EXPIRED';
}

/**
 * True when a still-PENDING checkpoint has passed its deadline.
 *
 * Reads only this checkpoint's own state and deadline, so it is structurally
 * incapable of consulting a sibling: a checkpoint is never missed because a
 * later one was verified, and never because a client said so.
 */
export function isCheckpointMissed(
  now: Date,
  expectation: Pick<PatrolRunCheckpoint, 'state' | 'missed_after'>,
): boolean {
  return expectation.state === 'PENDING' && now.getTime() > new Date(expectation.missed_after).getTime();
}

/**
 * C9-02/C9-05: server-authoritative ordering.
 *
 * A checkpoint may be verified only once every LOWER sequence number has left
 * PENDING. An earlier checkpoint that is VERIFIED, LATE, MISSED or CANCELLED
 * permits progression; one still PENDING blocks it. A later verification never
 * auto-resolves an earlier checkpoint — that resolution belongs to the missed
 * sweep alone.
 */
export function canVerifySequence(
  sequenceNumber: number,
  siblings: readonly Pick<PatrolRunCheckpoint, 'sequence_number' | 'state'>[],
): boolean {
  return siblings.every((sibling) => sibling.sequence_number >= sequenceNumber || sibling.state !== 'PENDING');
}

/**
 * C9-03: what happens to a pending checkpoint when a run is abandoned.
 *
 * Abandonment must not launder an obligation that was already overdue, so a
 * pending checkpoint past its deadline becomes MISSED. Only a still-future
 * expectation is withdrawn as CANCELLED.
 */
export function resolveAbandonedCheckpointState(
  now: Date,
  expectation: Pick<PatrolRunCheckpoint, 'state' | 'missed_after'>,
): Extract<PatrolRunCheckpointState, 'MISSED' | 'CANCELLED'> | null {
  if (expectation.state !== 'PENDING') return null;
  return now.getTime() > new Date(expectation.missed_after).getTime() ? 'MISSED' : 'CANCELLED';
}

/** C9-03: a run may complete only when nothing is still outstanding. */
export function canCompletePatrolRun(checkpointStates: readonly PatrolRunCheckpointState[]): boolean {
  // C9-08 fail closed: a run with no checkpoints proves nothing, a PENDING
  // checkpoint is unfinished business, and a CANCELLED checkpoint only exists
  // on runs that were themselves cancelled or abandoned — none may COMPLETE.
  if (checkpointStates.length === 0) return false;
  return checkpointStates.every((state) => state === 'VERIFIED' || state === 'LATE' || state === 'MISSED');
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
