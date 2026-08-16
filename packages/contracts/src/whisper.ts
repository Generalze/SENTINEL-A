import { z } from 'zod';

const MAX_CONTEXT_BYTES = 16 * 1024;
const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

function contextByteLength(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

const contextSchema = z.record(z.unknown()).refine(
  (value) => contextByteLength(value) <= MAX_CONTEXT_BYTES,
  { message: `context must serialize to at most ${MAX_CONTEXT_BYTES} bytes` },
);

export const WhisperSignalStatusSchema = z.enum([
  'DRAFT',
  'SIMULATION',
  'FALSE_POSITIVE_TEST',
  'ANTI_SPOOF_TEST',
  'FIELD_DRILL',
  'APPROVAL',
  'ACTIVE',
  'ROTATED',
  'RETIRED',
]);
export type WhisperSignalStatus = z.infer<typeof WhisperSignalStatusSchema>;

/** Exact §14.5 lifecycle; active configurations are never silently redefined. */
export const ALLOWED_WHISPER_SIGNAL_STATUS_TRANSITIONS: Readonly<Record<WhisperSignalStatus, readonly WhisperSignalStatus[]>> = {
  DRAFT: ['SIMULATION'],
  SIMULATION: ['FALSE_POSITIVE_TEST'],
  FALSE_POSITIVE_TEST: ['ANTI_SPOOF_TEST'],
  ANTI_SPOOF_TEST: ['FIELD_DRILL'],
  FIELD_DRILL: ['APPROVAL'],
  APPROVAL: ['ACTIVE'],
  ACTIVE: ['ROTATED', 'RETIRED'],
  ROTATED: [],
  RETIRED: [],
};

export function canTransitionWhisperSignalStatus(from: WhisperSignalStatus, to: WhisperSignalStatus): boolean {
  return ALLOWED_WHISPER_SIGNAL_STATUS_TRANSITIONS[from].includes(to);
}

/**
 * A versioned device-action signal. It only references a response protocol;
 * neither protocol steps nor universal secret phrases live in this contract.
 */
export const WhisperSignalSchema = z.object({
  schema_version: z.literal(1),
  whisper_signal_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId.nullable(),
  name: z.string().min(1).max(256),
  signal_version: z.number().int().positive(),
  status: WhisperSignalStatusSchema,
  modality: z.literal('DEVICE_ACTION'),
  device_action_id: z.string().min(1).max(256),
  authorised_user_ids: z.array(scopedId).min(1).max(1024).superRefine((ids, context) => {
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'authorised_user_ids must be unique' });
    }
  }),
  context_requirements: contextSchema,
  minimum_confidence: z.number().min(0).max(1),
  response_protocol_id: scopedId.nullable(),
  created_at: timestamp,
  updated_at: timestamp,
  created_by_user_id: scopedId,
  trace_id: scopedId,
}).strict().superRefine((value, context) => {
  if (new Date(value.updated_at) < new Date(value.created_at)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['updated_at'], message: 'updated_at must be >= created_at' });
  }
  if (value.status === 'ACTIVE' && value.response_protocol_id === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['response_protocol_id'], message: 'ACTIVE requires a response_protocol_id reference' });
  }
});
export type WhisperSignal = z.infer<typeof WhisperSignalSchema>;

export const DeviceTrustSchema = z.enum(['TRUSTED', 'DEGRADED', 'UNTRUSTED', 'COMPROMISED']);
export type DeviceTrust = z.infer<typeof DeviceTrustSchema>;

/** Signed device-action recognition outcome, intentionally not a response protocol. */
export const DeviceActionWhisperResultSchema = z.object({
  schema_version: z.literal(1),
  whisper_result_id: scopedId,
  whisper_signal_id: scopedId,
  whisper_signal_version: z.number().int().positive(),
  organisation_id: scopedId,
  site_id: scopedId,
  actor_user_id: scopedId,
  device_id: scopedId,
  recognised_at: timestamp,
  confidence: z.number().min(0).max(1),
  device_trust: DeviceTrustSchema,
  context: contextSchema,
  freshness_ms: z.number().int().nonnegative(),
  anti_replay_nonce: z.string().min(16).max(512),
  signature_algorithm: z.string().min(1).max(128),
  signature: z.string().min(16).max(16 * 1024),
  trace_id: scopedId,
}).strict();
export type DeviceActionWhisperResult = z.infer<typeof DeviceActionWhisperResultSchema>;

/** Key a verifier can retain to reject a replay from a device/signal version. */
export function deviceActionWhisperReplayKey(
  result: Pick<DeviceActionWhisperResult, 'device_id' | 'whisper_signal_id' | 'whisper_signal_version' | 'anti_replay_nonce'>,
): string {
  return `${result.device_id}:${result.whisper_signal_id}:${result.whisper_signal_version}:${result.anti_replay_nonce}`;
}
