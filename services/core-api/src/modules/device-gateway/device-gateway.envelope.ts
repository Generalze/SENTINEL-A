import {
  DEVICE_PURPOSE_PERMITTED_TRUST,
  DEVICE_QUEUE_ADMISSION_PURPOSE,
  DeviceOfflineOperationEnvelopeSchema,
  OfflineIncidentMessageAcknowledgePayloadSchema,
  WhisperDeviceActionV2ClaimsSchema,
  canonicalDeviceJson,
  deviceCanonicalDigest,
  type DeviceRequestPurpose,
  type DeviceTrust,
} from '@sentinel/contracts';
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
  /**
   * WP-27: the M3 device-action statement.
   *
   * It is an operation KIND rather than a new subsystem for the same reason
   * D25-11 made the other four kinds: the ROUTE chooses it, the body cannot,
   * and choosing it selects the target type, the required 62 action, the
   * device-request PURPOSE and the semantic payload schema together, from
   * server-owned tables, in one place.
   */
  'DEVICE_ACTION',
  /**
   * WP-29A: submission of ONE operation a device produced while disconnected.
   *
   * It is a gateway kind, and not a separate ingress, because D29A-26 §13
   * forbids a second device-authentication mechanism. Everything the other
   * kinds get, this gets: the human session, the fresh possession proof over a
   * canonical payload digest, the live authority re-read, the purpose table,
   * the D25-13 refusal boundary.
   *
   * WHAT IS DIFFERENT IS WHAT THE PAYLOAD CONTAINS. The other kinds carry an
   * instruction the device is issuing NOW. This one carries a statement the
   * device signed EARLIER, under a policy lease, and the fresh proof attests
   * only that the queued statement reached us intact from the device that still
   * holds the key. The queued statement's own authority is judged separately,
   * by the frozen WP-23 evaluator, against the SERVER's copy of the lease it
   * names.
   */
  'OFFLINE_QUEUE_SUBMIT',
] as const;
export const DeviceGatewayOperationKindSchema = z.enum(DEVICE_GATEWAY_OPERATION_KINDS);
export type DeviceGatewayOperationKind = z.infer<typeof DeviceGatewayOperationKindSchema>;

/**
 * What the operation acts ON. Fixed per kind by the table below and never
 * taken from the request: a caller able to name the target TYPE could sign one
 * statement and have it resolved against a different domain's row.
 */
export const DEVICE_GATEWAY_TARGET_TYPES = [
  'FIELD_OPERATIVE_STATE',
  'FIELD_ASSIGNMENT',
  'INCIDENT_FIELD_MESSAGE',
  'DEVICE_ACTION_STATEMENT',
  /** WP-29A: a queued operation, identified by its own `offline_operation_id`. */
  'FIELD_OFFLINE_OPERATION',
] as const;
export type DeviceGatewayTargetType = (typeof DEVICE_GATEWAY_TARGET_TYPES)[number];

export const DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND: Readonly<Record<DeviceGatewayOperationKind, DeviceGatewayTargetType>> = {
  FIELD_STATE_UPDATE: 'FIELD_OPERATIVE_STATE',
  ASSIGNMENT_ACCEPT: 'FIELD_ASSIGNMENT',
  ASSIGNMENT_DECLINE: 'FIELD_ASSIGNMENT',
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: 'INCIDENT_FIELD_MESSAGE',
  /**
   * WP-27: the target is the OPERATIVE THEMSELVES, exactly as it is for a field
   * state update, and the target id is resolved from the persisted context.
   *
   * The Whisper signal the statement names is deliberately NOT the envelope's
   * target. It is a SIGNED CLAIM inside the semantic payload, covered by the
   * payload digest, so it binds cryptographically without ever appearing in a
   * route, a path parameter or an audit identifier. W21-14's rule about audit
   * disclosure applies with full force to a covert channel: a route that named
   * a signal id would publish, in every access log, which discreet
   * configuration a device was firing.
   */
  DEVICE_ACTION: 'DEVICE_ACTION_STATEMENT',
  /**
   * WP-29A: the target is the QUEUED OPERATION itself, and its id is resolved
   * from the signed offline envelope rather than from a path parameter. A route
   * that took one would be a route through which a device could name a queue
   * position other than the one it signed.
   */
  OFFLINE_QUEUE_SUBMIT: 'FIELD_OFFLINE_OPERATION',
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
  /**
   * W21-12: firing a device action is its OWN capability, and no other action
   * implies it. `field.operative` holds it; `admin` deliberately holds nothing
   * operational on this channel.
   */
  DEVICE_ACTION: 'whisper.device-action.invoke',
  /**
   * WP-29A ADMITS EXACTLY ONE QUEUED KIND, AND THIS ENTRY IS THAT FACT.
   *
   * `INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE` is the only kind WP-23 lists as
   * stale-tolerant, and therefore the only one that can be judged without an
   * Edge time witness. So the action the CURRENT human must hold to submit a
   * queued operation is the acknowledgement action, and the envelope's own kind
   * is refused if it is anything else.
   *
   * THIS ENTRY MUST CHANGE WHEN THE SCOPE DOES. Widening the admitted kinds
   * without revisiting it would let one capability submit queued work that
   * requires another — which is why `FieldOfflineReplayService` independently
   * re-checks `REQUIRED_ACTION_FOR_KIND` for the kind actually inside the
   * envelope, and refuses on its own if they disagree.
   */
  OFFLINE_QUEUE_SUBMIT: 'field.message.acknowledge',
};

/**
 * WP-27/D25-11 — THE ROUTE CHOOSES THE PURPOSE, AND THE PURPOSE IS A TABLE.
 *
 * WP-25 hard-coded `expectedPurpose: 'FIELD_OPERATION'` at the one call site
 * that needed it, with the note that all three operations mapped to the frozen
 * FIELD_OPERATION and no new `DeviceRequestPurpose` value was added merely
 * because there were three route types. That reasoning still holds for those
 * kinds and is unchanged below.
 *
 * WP-27 is different, and the difference is the whole point.
 * `DEVICE_PURPOSE_PERMITTED_TRUST` admits `TRUSTED` and `DEGRADED` for
 * FIELD_OPERATION but `TRUSTED` ALONE for WHISPER_DEVICE_ACTION — that is
 * W21-05, and it is the reason a covert-channel operation must not travel under
 * a Field purpose. Running a device action as FIELD_OPERATION would let a
 * DEGRADED device fire the silent channel, which is exactly what the frozen
 * table forbids.
 *
 * So the purpose becomes a SERVER-OWNED TABLE KEYED ON THE ROUTE'S KIND. It is
 * still not caller-controlled security input: there is no parameter anywhere in
 * this module through which a caller could propose a purpose, and a proof minted
 * for one purpose is refused for another by the frozen evaluator's
 * `PURPOSE_NOT_ALLOWED`. Adding a row here is a visible change to a frozen route
 * table, which is the property D25-11 asked for.
 */
export const DEVICE_GATEWAY_PURPOSE_FOR_KIND: Readonly<Record<DeviceGatewayOperationKind, DeviceRequestPurpose>> = {
  FIELD_STATE_UPDATE: 'FIELD_OPERATION',
  ASSIGNMENT_ACCEPT: 'FIELD_OPERATION',
  ASSIGNMENT_DECLINE: 'FIELD_OPERATION',
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: 'FIELD_OPERATION',
  DEVICE_ACTION: 'WHISPER_DEVICE_ACTION',
  /**
   * WP-29A: `OFFLINE_SYNC` — the frozen purpose for queued work, and NOT
   * `FIELD_OPERATION`.
   *
   * The two currently admit the same trust states, so this selection changes
   * no behaviour today. It is still the correct one, and choosing the
   * convenient one because it happens to match would be storing up the exact
   * defect C15-R2-final removed: `DEVICE_QUEUE_ADMISSION_PURPOSE` exists so
   * that the question "may this device's QUEUED work take effect?" is asked
   * under its own name, and can be tightened later without also tightening
   * live field operations.
   */
  OFFLINE_QUEUE_SUBMIT: DEVICE_QUEUE_ADMISSION_PURPOSE,
};

/** The trust states each kind's purpose admits, read from the FROZEN table, never restated. */
export function deviceGatewayPermittedTrustFor(kind: DeviceGatewayOperationKind): readonly DeviceTrust[] {
  return DEVICE_PURPOSE_PERMITTED_TRUST[DEVICE_GATEWAY_PURPOSE_FOR_KIND[kind]];
}

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

/**
 * WP-29A — ONE QUEUED OPERATION, AS IT ARRIVES.
 *
 * Two members, and the split between them is the whole design. The envelope is
 * what the device SIGNED while disconnected; the payload is what that signature
 * COMMITS TO without carrying. Keeping them apart is what lets an envelope be
 * retained, logged and audited while the operational content it refers to is
 * not (D23-14) — and it is why the server re-computes `payload_digest` from the
 * payload it actually received rather than trusting the digest inside the
 * envelope.
 */
const OfflineQueueSubmissionSchema = z
  .object({
    envelope: DeviceOfflineOperationEnvelopeSchema,
    /**
     * WP-29A admits one operation kind, so this is that kind's payload,
     * referenced from the WP-20 contract rather than redeclared. When the
     * admitted scope widens this becomes a discriminated union keyed on the
     * envelope's `operation_kind` — never a loosened object.
     */
    payload: OfflineIncidentMessageAcknowledgePayloadSchema,
  })
  .strict();

const SEMANTIC_PAYLOAD_SCHEMA: Readonly<Record<DeviceGatewayOperationKind, z.ZodTypeAny>> = {
  FIELD_STATE_UPDATE: FieldStateSemanticPayloadSchema,
  ASSIGNMENT_ACCEPT: AssignmentSemanticPayloadSchema,
  ASSIGNMENT_DECLINE: AssignmentSemanticPayloadSchema,
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: AcknowledgeSemanticPayloadSchema,
  /**
   * WP-27: the CONTRACT's own claims schema, used directly rather than restated.
   *
   * A second definition of what a device action carries would be a second
   * opinion about what the device signed, and a signature scheme cannot survive
   * two opinions about its own preimage. It is `.strict()` in the contract, so
   * `signature_algorithm`, `signature_profile`, `curve` and `hash_algorithm` are
   * parse failures HERE too — the client never names the algorithm, at any
   * layer.
   *
   * Note what it does NOT contain: `organisation_id`, `site_id`,
   * `actor_user_id`, `device_id` and `context_id`. Those are ENVELOPE fields,
   * resolved by the server from the persisted context, and the v2 service
   * assembles the full submission from them. There is no parameter through which
   * a caller could propose one.
   */
  DEVICE_ACTION: WhisperDeviceActionV2ClaimsSchema,
  /**
   * WP-29A: the CONTRACTS' own schemas, composed — not restated.
   *
   * `envelope` is the frozen WP-23 `DeviceOfflineOperationEnvelopeSchema`,
   * which runs the full canonical signature decode at parse time, so a
   * malformed or high-S signature cannot reach a parsed submission. `payload`
   * is the WP-20 payload the envelope's `payload_digest` commits to; it travels
   * BESIDE the envelope rather than inside it (D23-14) so that an envelope
   * retained in an audit trail discloses nothing, and the server re-digests it
   * on arrival rather than believing the digest it was handed.
   *
   * `.strict()` on both, so an extra member is a parse failure rather than an
   * unsigned field riding along beside a signed statement.
   */
  OFFLINE_QUEUE_SUBMIT: OfflineQueueSubmissionSchema,
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
 * echoed `operation_kind`, `target_type` and `target_id` are OPTIONAL and are
 * equality-bound to what the ROUTE and the SERVER resolved — a device that
 * wants to state what it thinks it is doing may, and a device that states
 * something else is refused.
 *
 * C17-06 — `.strict()`, BECAUSE THIS IS A SIGNED BOUNDARY.
 *
 * The semantic payloads have always been strict. This outer envelope was
 * `.passthrough()`, which meant a top-level key that is NO PART of the signed
 * object was accepted and silently dropped: `organisation_id`, `device_id`,
 * `actor_user_id`, `context_id`, `purpose`, `idempotency_key`. None of them was
 * read, so it was not a bypass — it was the debt that BECOMES one the day a
 * refactor adds `body.organisation_id` to a handler whose parse already
 * succeeded. Accepting fields the signature does not cover is how the two sides
 * of a signature scheme start disagreeing about what was signed, so an unknown
 * top-level value is REFUSED rather than discarded.
 *
 * The three echoes stay because they are the opposite of unsigned input: each
 * is equality-bound below to a value the SERVER already decided, and a
 * disagreement is a refusal.
 */
const RequestBodySchema = z
  .object({
    proof: z.unknown(),
    payload: z.record(z.unknown()).optional(),
    operation_kind: z.string().optional(),
    target_type: z.string().optional(),
    target_id: z.string().optional(),
  })
  .strict();

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
