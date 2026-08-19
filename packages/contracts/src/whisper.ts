import { createHash } from 'node:crypto';
import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';

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
 * W21-10/W21-11: the SERVER-OWNED response-protocol registry.
 *
 * A Whisper signal never carries executable content — no Constitution action
 * name, no controller route, no severity override, no protocol steps. It
 * carries a REFERENCE, and that reference must resolve inside this allowlist.
 * Making it an enum rather than a free identifier is the point: a signal
 * author cannot invent a protocol, and an approved signal cannot later be
 * pointed at something the platform never reviewed.
 *
 * Milestone 2 needs exactly one executable protocol — entry into the ALREADY
 * PROVEN silent incident-response path. Recognition INITIATES that protocol;
 * it never replaces Constitution evaluation, never substitutes for either
 * distinct site-commander approval, and never dispatches anything itself.
 */
export const WHISPER_RESPONSE_PROTOCOLS = ['SILENT_INCIDENT_RESPONSE'] as const;
export const WhisperResponseProtocolSchema = z.enum(WHISPER_RESPONSE_PROTOCOLS);
export type WhisperResponseProtocol = z.infer<typeof WhisperResponseProtocolSchema>;

export function isAllowlistedWhisperResponseProtocol(value: unknown): value is WhisperResponseProtocol {
  return WhisperResponseProtocolSchema.safeParse(value).success;
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
  /** W21-10: a registry reference, never a command. */
  response_protocol_id: WhisperResponseProtocolSchema.nullable(),
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
  /**
   * W21-06: the OBSERVED device action, bound into the signed statement.
   * Without it a signature proves only that some action occurred on a trusted
   * device for some signal version — not WHICH action the device witnessed,
   * so a captured signature could be re-presented for a different configured
   * action of the same version family.
   */
  device_action_id: z.string().min(1).max(256),
  recognised_at: timestamp,
  confidence: z.number().min(0).max(1),
  device_trust: DeviceTrustSchema,
  context: contextSchema,
  /**
   * Client-observed telemetry only. Server modules must calculate
   * authoritative freshness from recognised_at and receipt time, then verify
   * the signed nonce/device context.
   */
  freshness_ms: z.number().int().nonnegative(),
  anti_replay_nonce: z.string().min(16).max(512),
  signature_algorithm: z.string().min(1).max(128),
  signature: z.string().min(16).max(16 * 1024),
  trace_id: scopedId,
}).strict();
export type DeviceActionWhisperResult = z.infer<typeof DeviceActionWhisperResultSchema>;

/**
 * W21-09: the persistence-backed anti-replay identity.
 *
 * Tenant, site, ACTOR, device, signal and version bound. The actor belongs in
 * the key because two people may legitimately be authorised on one signal
 * version and may share a device between shifts; a nonce consumed by one must
 * not silently consume the other's queue of one-shot identities, and a nonce
 * replayed across actors must not look like the same request.
 *
 * This is an IDENTITY, not a duplicate-detector on its own: the runtime must
 * store it, and a reuse whose canonical signed statement differs is a generic
 * conflict that invokes no protocol (see `whisperRecognitionFingerprint`).
 */
export function deviceActionWhisperReplayKey(
  result: Pick<
    DeviceActionWhisperResult,
    'organisation_id' | 'site_id' | 'actor_user_id' | 'device_id' | 'whisper_signal_id' | 'whisper_signal_version' | 'anti_replay_nonce'
  >,
): string {
  return [
    result.organisation_id,
    result.site_id,
    result.actor_user_id,
    result.device_id,
    result.whisper_signal_id,
    result.whisper_signal_version,
    result.anti_replay_nonce,
  ].join(':');
}

// ---------------------------------------------------------------------------
// W21-02 configuration freeze and version identity
// ---------------------------------------------------------------------------

/**
 * The fields whose meaning IS the signal's security configuration.
 *
 * `name` and `trace_id` are deliberately absent: renaming a signal in Studio
 * changes no authority and must not force a version bump, whereas every field
 * below decides who may fire what, under which conditions, into which
 * protocol. `status` is absent because advancing the lifecycle is the audited
 * transition itself, not a configuration edit.
 */
export const WHISPER_SEMANTIC_CONFIGURATION_FIELDS = [
  'modality',
  'device_action_id',
  'authorised_user_ids',
  'context_requirements',
  'minimum_confidence',
  'response_protocol_id',
] as const;
export type WhisperSemanticConfigurationField = (typeof WHISPER_SEMANTIC_CONFIGURATION_FIELDS)[number];

/**
 * W21-02: configuration is editable only while DRAFT.
 *
 * The moment a version enters SIMULATION it starts ACCUMULATING EVIDENCE —
 * false-positive results, anti-spoof results, a field drill, an approval.
 * Editing the configuration underneath that evidence would leave the approval
 * attesting to a signal that no longer exists, which is how a tested-and-safe
 * label ends up on something nobody tested. A semantic change therefore means
 * a NEW version; the former active version is rotated or retired.
 */
export function isWhisperConfigurationEditable(status: WhisperSignalStatus): boolean {
  return status === 'DRAFT';
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

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value)) ?? 'null';
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export type WhisperSemanticConfiguration = Pick<WhisperSignal, WhisperSemanticConfigurationField>;

/**
 * A stable digest of the six semantic fields. `authorised_user_ids` is an
 * allowlist SET, so it is order-normalised — reordering the roster is not a
 * configuration change — while object keys canonicalise recursively so a
 * re-serialised context requirement does not read as an edit.
 */
export function whisperConfigurationFingerprint(configuration: WhisperSemanticConfiguration): string {
  return sha256Hex(
    canonicalJson({
      modality: configuration.modality,
      device_action_id: configuration.device_action_id,
      authorised_user_ids: [...configuration.authorised_user_ids].sort(),
      context_requirements: configuration.context_requirements,
      minimum_confidence: configuration.minimum_confidence,
      response_protocol_id: configuration.response_protocol_id,
    }),
  );
}

/**
 * W21-02: may this edit land on this version, in this status?
 *
 * A DRAFT accepts anything. Past DRAFT, only a no-op is admissible — and the
 * caller is told which of the two facts refused it, because "you must publish
 * a new version" and "nothing changed" are very different answers for Studio
 * to render.
 */
export function classifyWhisperConfigurationEdit(
  status: WhisperSignalStatus,
  current: WhisperSemanticConfiguration,
  proposed: WhisperSemanticConfiguration,
): 'EDITABLE' | 'UNCHANGED' | 'REQUIRES_NEW_VERSION' {
  if (isWhisperConfigurationEditable(status)) return 'EDITABLE';
  return whisperConfigurationFingerprint(current) === whisperConfigurationFingerprint(proposed) ? 'UNCHANGED' : 'REQUIRES_NEW_VERSION';
}

/** W21-03: the two states from which no lifecycle transition exists. */
export function isTerminalWhisperSignalStatus(status: WhisperSignalStatus): boolean {
  return ALLOWED_WHISPER_SIGNAL_STATUS_TRANSITIONS[status].length === 0;
}

// ---------------------------------------------------------------------------
// W21-05 trusted device-identity seam
// ---------------------------------------------------------------------------

/**
 * W21-05: the seam a genuine authenticated-device facility will populate.
 *
 * Every field here is SERVER-ESTABLISHED. Nothing in a submitted result may
 * become one of these values, and no HTTP surface may accept `device_id`,
 * actor, organisation, site, trust or verification key from JSON and call it
 * authority — exactly the WP-20/C10-02 boundary, applied to a channel whose
 * whole purpose is silent duress signalling.
 *
 * `device_trust` lives HERE rather than being read from the submitted result:
 * a compromised device would otherwise assert its own trustworthiness.
 * `verification_key_id` names the key the platform believes belongs to this
 * device, so signature verification is performed against a registry entry
 * rather than against a key travelling with the claim it authenticates.
 */
export interface AuthenticatedWhisperDeviceContext {
  organisationId: string;
  actorUserId: string;
  deviceId: string;
  authorisedSiteIds: readonly string[];
  /** The platform's CURRENT trust judgement, not the device's self-report. */
  deviceTrust: DeviceTrust;
  /** Registry identity of the key the verifier must check the signature against. */
  verificationKeyId: string;
}

/**
 * W21-05: which live trust states may fire a silent protocol.
 *
 * TRUSTED only. A silent duress dispatch raised from a device the platform has
 * already flagged as SUSPICIOUS, QUARANTINED or COMPROMISED is precisely the
 * attack this modality invites, and DEGRADED/OFFLINE cannot support the
 * signature and freshness guarantees the protocol depends on. A blocked
 * invocation still leaves every ordinary alarm path available to the operative.
 */
export const WHISPER_INVOCATION_TRUST_STATES: readonly DeviceTrust[] = ['TRUSTED'];

export function deviceTrustPermitsWhisperInvocation(trust: DeviceTrust): boolean {
  return WHISPER_INVOCATION_TRUST_STATES.includes(trust);
}

// ---------------------------------------------------------------------------
// W21-06 the canonical signed statement
// ---------------------------------------------------------------------------

/** Domain separator: a signature for this purpose can serve no other. */
export const WHISPER_SIGNED_STATEMENT_DOMAIN = 'sentinel.whisper.device-action.v1';

export type WhisperSignedStatementInput = Pick<
  DeviceActionWhisperResult,
  | 'schema_version'
  | 'organisation_id'
  | 'site_id'
  | 'actor_user_id'
  | 'device_id'
  | 'whisper_signal_id'
  | 'whisper_signal_version'
  | 'device_action_id'
  | 'recognised_at'
  | 'anti_replay_nonce'
>;

/**
 * W21-06: EXACTLY what the device signs.
 *
 * Newline-separated with a leading domain tag, so no two different field
 * splits can concatenate to the same preimage and no signature minted for
 * another Sentinel purpose can be replayed here.
 *
 * What is deliberately ABSENT is as load-bearing as what is present:
 *
 *  - `response_protocol_id` — the server resolves the protocol from the exact
 *    active signal version (W21-10). A device that could sign the protocol
 *    could choose its own consequence.
 *  - `confidence`, `freshness_ms`, `context` — telemetry (W21-07). Signing
 *    them would dress client claims as authority.
 *  - `device_trust` — the platform's judgement, never the device's (W21-05).
 */
export function canonicalWhisperSignedStatement(input: WhisperSignedStatementInput): string {
  return [
    WHISPER_SIGNED_STATEMENT_DOMAIN,
    String(input.schema_version),
    input.organisation_id,
    input.site_id,
    input.actor_user_id,
    input.device_id,
    input.whisper_signal_id,
    String(input.whisper_signal_version),
    input.device_action_id,
    input.recognised_at,
    input.anti_replay_nonce,
  ].join('\n');
}

/**
 * W21-09: the digest a receipt stores. The same canonical statement converges
 * to the same stored outcome; a reused replay identity whose statement differs
 * is a conflict that invokes nothing.
 */
export function whisperRecognitionFingerprint(input: WhisperSignedStatementInput): string {
  return sha256Hex(canonicalWhisperSignedStatement(input));
}

// ---------------------------------------------------------------------------
// W21-08 authoritative freshness
// ---------------------------------------------------------------------------

/**
 * W21-08: named, reviewable bounds — not magic constants buried in a service.
 *
 * A device-action duress signal is meaningful for as long as the situation it
 * reports plausibly persists. Two minutes is deliberately short: a silent
 * dispatch raised from a recognition captured long ago is more likely a
 * replayed or delayed artefact than a live emergency, and the operative can
 * always signal again. Five seconds of future skew tolerates ordinary clock
 * drift while refusing a device that claims to be signalling from the future
 * to extend its own acceptance window.
 */
export const MAX_WHISPER_RECOGNITION_AGE_MS = 120_000;
export const MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS = 5_000;

export const WhisperFreshnessOutcomeSchema = z.enum(['FRESH', 'STALE', 'FUTURE_SKEW']);
export type WhisperFreshnessOutcome = z.infer<typeof WhisperFreshnessOutcomeSchema>;

/**
 * Judged against the AUTHORITATIVE receipt time — the server clock read when
 * the result arrives. The submitted `freshness_ms` is the device's own opinion
 * and plays no part: a device that under-reports its age must not thereby
 * extend the window (W21-07/W21-08).
 */
export function classifyWhisperRecognitionFreshness(recognisedAt: Date, receivedAt: Date): WhisperFreshnessOutcome {
  const ageMs = receivedAt.getTime() - recognisedAt.getTime();
  if (ageMs < -MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS) return 'FUTURE_SKEW';
  if (ageMs > MAX_WHISPER_RECOGNITION_AGE_MS) return 'STALE';
  return 'FRESH';
}

// ---------------------------------------------------------------------------
// W21-04 / W21-07 runtime eligibility
// ---------------------------------------------------------------------------

export const WhisperRecognitionConflictCodeSchema = z.enum([
  'DEVICE_CONTEXT_MISMATCH',
  'SITE_SCOPE_MISMATCH',
  'SIGNAL_NOT_ACTIVE',
  'SIGNAL_VERSION_MISMATCH',
  'ACTOR_NOT_ELIGIBLE',
  'DEVICE_TRUST_INSUFFICIENT',
  'DEVICE_ACTION_MISMATCH',
  'CONTEXT_NOT_SATISFIED',
  'CONFIDENCE_BELOW_THRESHOLD',
  'RECOGNITION_STALE',
  'RECOGNITION_FUTURE_SKEW',
  'SIGNATURE_INVALID',
  'REPLAY_IDENTITY_REUSED',
  'PROTOCOL_NOT_ALLOWLISTED',
]);
export type WhisperRecognitionConflictCode = z.infer<typeof WhisperRecognitionConflictCodeSchema>;

/**
 * W21-07: SERVER-owned facts about the world at recognition time.
 *
 * `on_duty` is the worked example the ruling names: it must come from
 * authoritative Field state, never from a device asserting `{on_duty: true}`.
 * A value of `null` means the server could not establish the fact, which is
 * NOT the same as false and must fail closed — an unknown duty state is a gap
 * in evidence, and a silent dispatch is not something to grant on a guess.
 */
export type ServerWhisperContextFacts = Readonly<Record<string, unknown>>;

/**
 * Every declared requirement must be matched by a SERVER-established fact of
 * equal value. A requirement the server cannot answer (absent or null) fails
 * closed and is named in the result so the runtime can audit WHY without
 * disclosing the requirement set to the caller.
 */
export function evaluateWhisperContextRequirements(
  requirements: Readonly<Record<string, unknown>>,
  serverFacts: ServerWhisperContextFacts,
): { satisfied: true } | { satisfied: false; unsatisfiedKeys: string[] } {
  const unsatisfiedKeys = Object.keys(requirements).filter((key) => {
    const fact = serverFacts[key];
    if (fact === undefined || fact === null) return true;
    return canonicalJson(fact) !== canonicalJson(requirements[key]);
  });
  return unsatisfiedKeys.length === 0 ? { satisfied: true } : { satisfied: false, unsatisfiedKeys };
}

/**
 * Everything the runtime decision needs, with each value's PROVENANCE fixed by
 * its type. The signal is the exact stored version; trust and site scope come
 * from the authenticated device context; `actorHoldsCurrentAuthority` is the
 * live capability/scope answer the caller computed a moment ago; the freshness
 * outcome was judged against the server clock. The only values taken from the
 * submitted result are the ones a signature covers plus the confidence figure,
 * and confidence can only ever REDUCE what is permitted.
 */
export interface WhisperRuntimeEligibilityInput {
  signal: Pick<
    WhisperSignal,
    'status' | 'signal_version' | 'device_action_id' | 'authorised_user_ids' | 'context_requirements' | 'minimum_confidence' | 'response_protocol_id'
  >;
  context: AuthenticatedWhisperDeviceContext;
  claimedSignalVersion: number;
  claimedSiteId: string;
  claimedDeviceActionId: string;
  reportedConfidence: number;
  /**
   * W21-04: the allowlist is NOT a grant. This is the CURRENT answer to "may
   * this authenticated person do this here, now" — recomputed per invocation,
   * so revoking someone's authority stops them even while an older active
   * version still lists their id.
   */
  actorHoldsCurrentAuthority: boolean;
  serverFacts: ServerWhisperContextFacts;
  freshness: WhisperFreshnessOutcome;
}

export type WhisperRuntimeEligibility =
  | { eligible: true; responseProtocolId: WhisperResponseProtocol }
  | { eligible: false; conflictCode: WhisperRecognitionConflictCode };

/**
 * W21-04/W21-07: the ordered runtime gate, expressed once so no service
 * reinvents it — and deliberately ordered so that identity and scope failures
 * are decided before anything reveals that a signal exists at all.
 *
 * Signature verification and replay-identity consumption are NOT here: they
 * are I/O the runtime performs around this decision (against the registry key
 * and the durable receipt), and folding them into a pure function would invite
 * a caller to believe a `true` here meant a verified signature.
 */
export function evaluateWhisperRuntimeEligibility(input: WhisperRuntimeEligibilityInput): WhisperRuntimeEligibility {
  if (!input.context.authorisedSiteIds.includes(input.claimedSiteId)) return { eligible: false, conflictCode: 'SITE_SCOPE_MISMATCH' };
  if (!deviceTrustPermitsWhisperInvocation(input.context.deviceTrust)) return { eligible: false, conflictCode: 'DEVICE_TRUST_INSUFFICIENT' };
  if (input.signal.status !== 'ACTIVE') return { eligible: false, conflictCode: 'SIGNAL_NOT_ACTIVE' };
  if (input.signal.signal_version !== input.claimedSignalVersion) return { eligible: false, conflictCode: 'SIGNAL_VERSION_MISMATCH' };
  if (input.signal.device_action_id !== input.claimedDeviceActionId) return { eligible: false, conflictCode: 'DEVICE_ACTION_MISMATCH' };
  // Both halves of W21-04, in order: named on this version AND currently authorised.
  if (!input.signal.authorised_user_ids.includes(input.context.actorUserId)) return { eligible: false, conflictCode: 'ACTOR_NOT_ELIGIBLE' };
  if (!input.actorHoldsCurrentAuthority) return { eligible: false, conflictCode: 'ACTOR_NOT_ELIGIBLE' };
  if (input.freshness === 'FUTURE_SKEW') return { eligible: false, conflictCode: 'RECOGNITION_FUTURE_SKEW' };
  if (input.freshness === 'STALE') return { eligible: false, conflictCode: 'RECOGNITION_STALE' };
  if (input.reportedConfidence < input.signal.minimum_confidence) return { eligible: false, conflictCode: 'CONFIDENCE_BELOW_THRESHOLD' };
  if (!evaluateWhisperContextRequirements(input.signal.context_requirements, input.serverFacts).satisfied) {
    return { eligible: false, conflictCode: 'CONTEXT_NOT_SATISFIED' };
  }
  // W21-10: the protocol is resolved from the stored version, never supplied.
  if (!isAllowlistedWhisperResponseProtocol(input.signal.response_protocol_id)) return { eligible: false, conflictCode: 'PROTOCOL_NOT_ALLOWLISTED' };
  return { eligible: true, responseProtocolId: input.signal.response_protocol_id };
}

// ---------------------------------------------------------------------------
// W21-12 authority vocabulary and W21-13 activation approval
// ---------------------------------------------------------------------------

/**
 * W21-12: four SEPARATE capabilities, proposed here for the lead's ruling and
 * deliberately NOT yet wired into `roles.ts`.
 *
 * Reading a signal roster, editing a configuration, approving an activation
 * and firing the thing are four different powers, and the existing §62 model
 * already treats patrol, messaging and SILENT approval as explicit
 * capabilities rather than consequences of `incident.view` or admin status.
 */
export const WHISPER_ACTIONS = ['whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve', 'whisper.device-action.invoke'] as const;
export const WhisperActionSchema = z.enum(WHISPER_ACTIONS);
export type WhisperAction = z.infer<typeof WhisperActionSchema>;

/**
 * The PROPOSED §62 matrix (W21-12), stated as data so the eventual `roles.ts`
 * change is a mechanical, reviewable transcription rather than a fresh
 * judgement call. `admin` holds nothing operational: platform administration
 * is not authority over a silent duress channel. `field.operative` holds only
 * `whisper.device-action.invoke`, and that is OWN-ONLY — every runtime
 * entitlement check in `evaluateWhisperRuntimeEligibility` still applies on
 * top of it (W21-04).
 */
export const PROPOSED_WHISPER_ROLE_ACTIONS: Readonly<Record<string, readonly WhisperAction[]>> = {
  'site.commander': ['whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve'],
  dispatcher: [],
  operator: [],
  'field.operative': ['whisper.device-action.invoke'],
  investigator: [],
  'evidence.custodian': [],
  admin: [],
};

/**
 * W21-12: activation requires a SECOND authenticated person.
 *
 * A creator approving their own signal would make the entire test-and-approve
 * lifecycle self-attesting — one compromised or mistaken account could mint an
 * active silent-dispatch trigger end to end.
 */
export function whisperActivationApproverIsDistinct(createdByUserId: string, approvedByUserId: string): boolean {
  return createdByUserId !== approvedByUserId && approvedByUserId.length > 0;
}

/**
 * W21-13: the activation approval record.
 *
 * This attests that a TESTED CONFIGURATION IS SAFE TO RECOGNISE. It is not,
 * and can never be replayed as, an approval of any operational response — the
 * shape carries no incident, no task, no dispatch reference precisely so that
 * no code path can mistake one for the other. When an active signal later
 * fires, the existing SILENT response still requires its own
 * Constitution-governed approvals from distinct commanders.
 *
 * `configuration_fingerprint` binds the approval to the exact configuration
 * that was tested, so an approval cannot survive a configuration it never saw.
 */
export const WhisperActivationApprovalSchema = z
  .object({
    schema_version: z.literal(1),
    whisper_signal_id: scopedId,
    signal_version: z.number().int().positive(),
    configuration_fingerprint: z.string().length(64),
    approved_by_user_id: scopedId,
    created_by_user_id: scopedId,
    approved_at: timestamp,
    trace_id: scopedId,
  })
  .strict()
  .superRefine((value, context) => {
    if (!whisperActivationApproverIsDistinct(value.created_by_user_id, value.approved_by_user_id)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['approved_by_user_id'],
        message: 'activation approval requires a person distinct from the version creator',
      });
    }
  });
export type WhisperActivationApproval = z.infer<typeof WhisperActivationApprovalSchema>;

// ---------------------------------------------------------------------------
// W21-14 audit without secret leakage
// ---------------------------------------------------------------------------

/**
 * W21-14: the ONLY fields a Whisper audit payload may carry.
 *
 * `.strict()` is the enforcement: the discreet action definition, signature
 * material, public keys, the authorised-user roster and the context values
 * themselves have no field here, so a well-meaning future edit cannot quietly
 * widen an audit row into a disclosure of the very secret the modality
 * depends on. What remains is enough to reconstruct WHO did WHAT, WHEN, under
 * WHICH version, with WHICH outcome, and where it went in the response chain.
 */
export const WhisperAuditPayloadSchema = z
  .object({
    whisper_signal_id: scopedId,
    signal_version: z.number().int().positive(),
    /** Digest, never the configuration itself. */
    configuration_fingerprint: z.string().length(64).nullable(),
    actor_user_id: scopedId.nullable(),
    device_id: scopedId.nullable(),
    from_status: WhisperSignalStatusSchema.nullable(),
    to_status: WhisperSignalStatusSchema.nullable(),
    outcome: z.enum(['ACCEPTED', 'REFUSED']).nullable(),
    conflict_code: WhisperRecognitionConflictCodeSchema.nullable(),
    /** Digest of the signed statement — never the signature or the key. */
    recognition_fingerprint: z.string().length(64).nullable(),
    response_protocol_id: WhisperResponseProtocolSchema.nullable(),
    /** Link into the existing SILENT path, so the chain stays reconstructable. */
    incident_id: scopedId.nullable(),
    trace_id: scopedId,
  })
  .strict();
export type WhisperAuditPayload = z.infer<typeof WhisperAuditPayloadSchema>;
