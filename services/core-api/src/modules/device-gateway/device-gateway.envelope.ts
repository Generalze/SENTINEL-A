import { canonicalDeviceJson, deviceCanonicalDigest } from '@sentinel/contracts';
import { z } from 'zod';
import { DEVICE_GATEWAY_OPERATION_ENVELOPE_DOMAIN } from './device-gateway.constants';

/**
 * WP-25/D25-11 — THE CANONICAL TYPED OPERATION ENVELOPE.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE
 * ------------------------------------
 *     A DEVICE MUST NOT SIGN `SHA256(whatever JSON arrived)`.
 *
 * If the signed digest were taken over raw request bytes, then two operations
 * whose bodies happened to serialise identically would share a signature, and
 * a valid proof minted for an assignment accept could be carried to a
 * field-state update. So the gateway owns the envelope, builds it from a
 * PARSED semantic object, and hashes THAT.
 *
 * THE ROUTE CHOOSES `operation_kind` AND `purpose`. NEITHER IS
 * CALLER-CONTROLLED SECURITY INPUT.
 *
 * `parseOperationEnvelope` takes the kind as an argument from the controller,
 * never from the body. A body that carries `operation_kind` or `target_type`
 * at all is accepted ONLY when it agrees with the route, and is REFUSED on
 * disagreement rather than silently overridden — because "silently overridden"
 * is indistinguishable, in a log, from "the caller chose it".
 *
 * WHY THE IDENTITY FIELDS ARE SERVER-RESOLVED
 * -------------------------------------------
 * `organisation_id`, `site_id`, `actor_user_id` and `device_id` are handed in
 * by the pipeline from the PERSISTED CONTEXT and the verified proof, never
 * read from the body. They are inside the digest so that a proof is bound to
 * the tenant, site, operative and hardware it was minted for; they are not
 * inside the body so that there is no parameter through which a caller could
 * propose one. The device can reproduce every one of them, which is what makes
 * the digest computable on both sides.
 *
 * CANONICALISATION IS THE CONTRACT'S, NOT THIS MODULE'S. `canonicalDeviceJson`
 * sorts keys recursively and REFUSES anything not losslessly representable —
 * `undefined`, a function, a `Date`, a sparse array, a getter, a prototype
 * that is not `Object.prototype`. A second canonicaliser here would be a
 * second opinion about what the signed bytes are, which is the one thing a
 * signature scheme cannot survive.
 */

export const DEVICE_GATEWAY_OPERATION_KINDS = [
  'FIELD_STATE_UPDATE',
  'ASSIGNMENT_ACCEPT',
  'ASSIGNMENT_DECLINE',
  'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
] as const;
export const DeviceGatewayOperationKindSchema = z.enum(DEVICE_GATEWAY_OPERATION_KINDS);
export type DeviceGatewayOperationKind = z.infer<typeof DeviceGatewayOperationKindSchema>;

/**
 * What the operation acts ON. Fixed per kind by the table below and never
 * taken from the request: a caller able to name the target TYPE could sign one
 * statement and have it resolved against a different domain's row.
 */
export const DEVICE_GATEWAY_TARGET_TYPES = ['FIELD_OPERATIVE_STATE', 'FIELD_ASSIGNMENT', 'INCIDENT_FIELD_MESSAGE'] as const;
export type DeviceGatewayTargetType = (typeof DEVICE_GATEWAY_TARGET_TYPES)[number];

export const DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND: Readonly<Record<DeviceGatewayOperationKind, DeviceGatewayTargetType>> = {
  FIELD_STATE_UPDATE: 'FIELD_OPERATIVE_STATE',
  ASSIGNMENT_ACCEPT: 'FIELD_ASSIGNMENT',
  ASSIGNMENT_DECLINE: 'FIELD_ASSIGNMENT',
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: 'INCIDENT_FIELD_MESSAGE',
};

/**
 * The §62 action each operation requires of the CURRENT human actor.
 *
 * These are the actions the existing HUMAN routes are gated on, quoted rather
 * than re-decided: the device gateway is a second ingress to the same
 * operations, not a second authorisation model for them. Widening any entry
 * would let a device-authenticated path do something the same person cannot do
 * over HTTP, which is precisely the fusion §62.1 forbids.
 */
export const DEVICE_GATEWAY_REQUIRED_ACTION: Readonly<Record<DeviceGatewayOperationKind, string>> = {
  FIELD_STATE_UPDATE: 'field.state.write',
  ASSIGNMENT_ACCEPT: 'field.assignment.act',
  ASSIGNMENT_DECLINE: 'field.assignment.act',
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: 'field.message.acknowledge',
};

/** Every action any gateway operation can require. Used by the establishment gate. */
export const DEVICE_GATEWAY_CAPABILITY_ACTIONS: readonly string[] = [
  ...new Set(Object.values(DEVICE_GATEWAY_REQUIRED_ACTION)),
];

/**
 * ASSIGNMENT ACTIONS REACHABLE THROUGH THE GATEWAY, EXHAUSTIVELY.
 *
 * D25-10: "Assignment acknowledgement — ACCEPT and DECLINE ONLY. NOT start,
 * complete, cancel or reassign." The gateway therefore has no parameter that
 * could carry an action name at all: the map below is keyed on the two
 * operation kinds that exist, so `start`, `complete` and `cancel` are not
 * "refused" by a check somebody could delete — they are unreachable because
 * nothing constructs them.
 */
export const DEVICE_GATEWAY_ASSIGNMENT_ACTION: Readonly<Record<'ASSIGNMENT_ACCEPT' | 'ASSIGNMENT_DECLINE', 'accept' | 'decline'>> = {
  ASSIGNMENT_ACCEPT: 'accept',
  ASSIGNMENT_DECLINE: 'decline',
};

// ---------------------------------------------------------------------------
// The semantic payloads, one strict schema per kind
// ---------------------------------------------------------------------------

/**
 * `.strict()` everywhere, deliberately. An unknown key in a semantic payload
 * is not a harmless extra: it is a value the device signed and the server did
 * not understand, and admitting it means the two sides disagree about what the
 * signature covers.
 *
 * Every field here is SEMANTIC. Identity, tenant, site, actor and device are
 * envelope fields, resolved by the server; none of them may appear in a
 * payload, and `.strict()` is what makes that structural rather than polite.
 */
const FieldStateSemanticPayloadSchema = z
  .object({
    state: z.enum(['AVAILABLE', 'PATROL', 'OBSERVING', 'RESPONDING', 'ON_SCENE', 'NEED_SUPPORT', 'COMPROMISED', 'OFF_DUTY']),
    location: z.record(z.unknown()).nullable(),
    source_at: z.string().datetime(),
    freshness_ms: z.number().int().nonnegative(),
  })
  .strict();

const AssignmentSemanticPayloadSchema = z
  .object({
    /**
     * The compare-and-set the Field domain already requires. It is SEMANTIC —
     * it changes what the operative is asserting — so it is signed, and a
     * device cannot retarget a signed accept at an assignment in a different
     * status by editing the body.
     */
    expected_status: z.enum(['REQUESTED', 'ACCEPTED', 'DECLINED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'EXPIRED']),
  })
  .strict();

/**
 * Acknowledgement carries no semantics of its own beyond WHICH delivery row is
 * being acknowledged, and that is the envelope's `target_id`. The empty object
 * is the honest shape: §76 keeps the device's claim about when it saw
 * something as telemetry, never authority, so there is no `seen_at` here to be
 * mistaken for delivery evidence.
 */
const AcknowledgeSemanticPayloadSchema = z.object({}).strict();

const SEMANTIC_PAYLOAD_SCHEMA: Readonly<Record<DeviceGatewayOperationKind, z.ZodTypeAny>> = {
  FIELD_STATE_UPDATE: FieldStateSemanticPayloadSchema,
  ASSIGNMENT_ACCEPT: AssignmentSemanticPayloadSchema,
  ASSIGNMENT_DECLINE: AssignmentSemanticPayloadSchema,
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: AcknowledgeSemanticPayloadSchema,
};

export type FieldStateSemanticPayload = z.infer<typeof FieldStateSemanticPayloadSchema>;
export type AssignmentSemanticPayload = z.infer<typeof AssignmentSemanticPayloadSchema>;

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

export interface DeviceGatewayOperationEnvelope {
  readonly schema_version: 1;
  readonly operation_kind: DeviceGatewayOperationKind;
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly target_type: DeviceGatewayTargetType;
  readonly target_id: string;
  readonly semantic_payload: Record<string, unknown>;
}

/** The server-resolved identity the envelope is built around. Never from the body. */
export interface DeviceGatewayEnvelopeIdentity {
  readonly organisationId: string;
  readonly siteId: string;
  readonly actorUserId: string;
  readonly deviceId: string;
  readonly targetId: string;
}

export type DeviceGatewayEnvelopeParse =
  | { readonly ok: true; readonly envelope: DeviceGatewayOperationEnvelope; readonly digest: string }
  | { readonly ok: false; readonly refusal: 'ENVELOPE_MALFORMED' | 'OPERATION_KIND_CONFLICT' };

/**
 * The shape a device-authenticated operation request body may take.
 *
 * `proof` is validated by the frozen `DeviceRequestProofSchema` elsewhere; here
 * it is only carved off so it cannot leak into the semantic payload. The
 * echoed `operation_kind` and `target_type` are OPTIONAL and are equality-bound
 * to the route's choice — a device that wants to state what it thinks it is
 * doing may, and a device that states something else is refused.
 */
const RequestBodySchema = z
  .object({
    proof: z.unknown(),
    payload: z.record(z.unknown()).optional(),
    operation_kind: z.string().optional(),
    target_type: z.string().optional(),
    target_id: z.string().optional(),
  })
  .passthrough();

/**
 * Builds the canonical envelope for `kind`, or refuses.
 *
 * `kind` comes from the ROUTE. `identity` comes from the persisted context and
 * the proof. Only `payload` comes from the caller, and only after a strict
 * per-kind parse.
 */
export function parseOperationEnvelope(
  kind: DeviceGatewayOperationKind,
  identity: DeviceGatewayEnvelopeIdentity,
  rawBody: unknown,
): DeviceGatewayEnvelopeParse {
  const body = RequestBodySchema.safeParse(rawBody ?? {});
  if (!body.success) return { ok: false, refusal: 'ENVELOPE_MALFORMED' };

  const targetType = DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND[kind];

  // D25-11. A conflicting echo is a REFUSAL, not an override. The three checks
  // are separate so the audit records which one disagreed.
  if (body.data.operation_kind !== undefined && body.data.operation_kind !== kind) {
    return { ok: false, refusal: 'OPERATION_KIND_CONFLICT' };
  }
  if (body.data.target_type !== undefined && body.data.target_type !== targetType) {
    return { ok: false, refusal: 'OPERATION_KIND_CONFLICT' };
  }
  if (body.data.target_id !== undefined && body.data.target_id !== identity.targetId) {
    return { ok: false, refusal: 'OPERATION_KIND_CONFLICT' };
  }

  const payload = SEMANTIC_PAYLOAD_SCHEMA[kind].safeParse(body.data.payload ?? {});
  if (!payload.success) return { ok: false, refusal: 'ENVELOPE_MALFORMED' };

  const envelope: DeviceGatewayOperationEnvelope = {
    schema_version: 1,
    operation_kind: kind,
    organisation_id: identity.organisationId,
    site_id: identity.siteId,
    actor_user_id: identity.actorUserId,
    device_id: identity.deviceId,
    target_type: targetType,
    target_id: identity.targetId,
    semantic_payload: payload.data as Record<string, unknown>,
  };

  // The digest may itself be unrepresentable if a payload smuggled something
  // canonical JSON refuses. That is a malformed envelope, not a crash.
  try {
    return { ok: true, envelope, digest: deviceGatewayEnvelopeDigest(envelope) };
  } catch {
    return { ok: false, refusal: 'ENVELOPE_MALFORMED' };
  }
}

/**
 * EXACTLY the bytes a device hashes into `DeviceRequestProof.payload_digest`.
 *
 * Both the canonical form and the digest read from ONE object literal, for the
 * reason `device-context.ts` gives for its statement builder and fingerprint:
 * two literals drift, and a drift here would let a signature cover something
 * the server verified a different digest of.
 */
function deviceGatewayEnvelopeStatementObject(envelope: DeviceGatewayOperationEnvelope): Record<string, unknown> {
  return {
    domain: DEVICE_GATEWAY_OPERATION_ENVELOPE_DOMAIN,
    schema_version: envelope.schema_version,
    operation_kind: envelope.operation_kind,
    organisation_id: envelope.organisation_id,
    site_id: envelope.site_id,
    actor_user_id: envelope.actor_user_id,
    device_id: envelope.device_id,
    target_type: envelope.target_type,
    target_id: envelope.target_id,
    semantic_payload: envelope.semantic_payload,
  };
}

export function canonicalDeviceGatewayEnvelope(envelope: DeviceGatewayOperationEnvelope): string {
  return canonicalDeviceJson(deviceGatewayEnvelopeStatementObject(envelope));
}

export function deviceGatewayEnvelopeDigest(envelope: DeviceGatewayOperationEnvelope): string {
  return deviceCanonicalDigest(deviceGatewayEnvelopeStatementObject(envelope));
}
