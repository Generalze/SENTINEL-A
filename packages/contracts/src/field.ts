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
export function offlineOperationReplayKey(operation: Pick<FieldOfflineOperation, 'device_id' | 'device_sequence'>): string {
  return `${operation.device_id}:${operation.device_sequence}`;
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
