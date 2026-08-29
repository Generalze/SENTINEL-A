import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import { DeviceSignatureProfileSchema, DeviceSignatureSchema } from './device-signature.js';
import { FieldOfflineOperationKindSchema, MAX_OFFLINE_DEVICE_SEQUENCE, type FieldOfflineOperationKind } from './field-offline.js';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceAttestationOutcomeSchema,
  DeviceAttestationStandingSchema,
  DeviceDigestSchema,
  DeviceEnrollmentStateSchema,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DeviceTraceIdSchema,
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
} from './device-identity.js';

/**
 * WP-23 offline envelope, Edge provenance, revocation/recovery and audit
 * (D23-08, D23-10, D23-11, D23-12, D23-14 with corrections C14-04 and C14-06).
 *
 * THE HOLE THIS MODULE CLOSES
 * ---------------------------
 * D23-11 expires cached authority. D23-12 refuses to trust the client clock.
 * Both are individually right, and together they left a question nobody could
 * answer: after six hours offline, how does central prove an operation happened
 * BEFORE its lease expired, when the only timestamp is one a compromised client
 * could backdate?
 *
 * Two things close it. The canonical device-signed envelope binds the LEASE
 * IDENTITY into the signature, so the operation names the authority it acted
 * under. And the Edge receipt supplies an independent time witness. Where no
 * trustworthy witness exists, time-bounded authority cannot be established and
 * the operation is REFUSED — a device's own timestamp never closes that gap.
 *
 * CONTRACTS ONLY (D23-16)
 * -----------------------
 * No Edge runtime, no reconciliation service, no queue, no persistence. Every
 * decision below is a pure function over explicitly server-owned inputs.
 */

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();
const deviceSequence = z.number().int().nonnegative().max(MAX_OFFLINE_DEVICE_SEQUENCE);

function epochMs(value: string): number {
  return Date.parse(value);
}

// ---------------------------------------------------------------------------
// The policy / authority lease (D23-11)
// ---------------------------------------------------------------------------

/**
 * A disconnected client may act only within a cached policy, and that cache has
 * an explicit expiry after which the client REFUSES rather than assumes.
 *
 * `scope` is an allowlist of operation kinds drawn from WP-20's existing set —
 * single-sourced from `field-offline.ts` deliberately, so an offline lease can
 * never authorise something the online replay contract does not admit. A lease
 * that could name its own operation kinds would be a second, weaker allowlist.
 */
export const DevicePolicyLeaseSchema = z
  .object({
    schema_version: z.literal(1),
    lease_id: scopedId,
    organisation_id: scopedId,
    site_id: scopedId,
    /** The lease is issued TO one device identity; it is not a site-wide permit. */
    device_id: scopedId,
    scope: z.array(FieldOfflineOperationKindSchema).min(1).max(64),
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    const issued = epochMs(value.issued_at);
    const expires = epochMs(value.expires_at);
    if (!(expires > issued)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be after issued_at' });
    } else if (expires - issued > DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: `policy lease lifetime must not exceed ${DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS} ms`,
      });
    }
    if (new Set(value.scope).size !== value.scope.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['scope'], message: 'scope must be unique' });
    }
  });
export type DevicePolicyLease = z.infer<typeof DevicePolicyLeaseSchema>;

export const DevicePolicyLeaseStandingSchema = z.enum(['VALID', 'NOT_YET_VALID', 'EXPIRED']);
export type DevicePolicyLeaseStanding = z.infer<typeof DevicePolicyLeaseStandingSchema>;

/**
 * Judged at an explicit instant. The caller must pass a TRUSTWORTHY instant —
 * the server receipt clock, or an Edge-witnessed time — never `created_at` from
 * an envelope. That is not a convention: `evaluateOfflineOperationAdmissibility`
 * below is the only place this is called from in the contract, and it never
 * passes a device-supplied value.
 */
export function classifyDevicePolicyLease(lease: DevicePolicyLease, at: string): DevicePolicyLeaseStanding {
  const atMs = epochMs(at);
  if (atMs < epochMs(lease.issued_at)) return 'NOT_YET_VALID';
  if (atMs > epochMs(lease.expires_at)) return 'EXPIRED';
  return 'VALID';
}

// ---------------------------------------------------------------------------
// The canonical device-signed offline operation envelope (C14-04)
// ---------------------------------------------------------------------------

/** Domain separator, distinct from the request-proof and Whisper domains. */
export const DEVICE_OFFLINE_OPERATION_DOMAIN = 'sentinel.device.offline-operation.v1';

/** Domain separator for the Edge provenance receipt. */
export const DEVICE_EDGE_RECEIPT_DOMAIN = 'sentinel.device.edge-receipt.v1';

/**
 * The envelope D23-10 assumed and C14-04 required to be defined.
 *
 * WHY `policy_lease_id` IS INSIDE THE SIGNATURE
 * --------------------------------------------
 * This is the load-bearing field of the whole module. Binding the lease
 * identity into the signed bytes means the operation NAMES THE AUTHORITY IT
 * ACTED UNDER. A lease that has since expired or been revoked can then be
 * judged on its own terms — its own issue and expiry times, which the server
 * issued — rather than on the device's word about when it acted. Without it,
 * the only evidence about the authority in force would be a timestamp the
 * device controls, and a compromised client would simply backdate.
 *
 * `created_at` is CLIENT TELEMETRY and nothing else (C10-06/D23-12). It is
 * signed, so it cannot be altered in transit, and it is never authority: it
 * cannot revive an expired lease, backdate a transition, or extend a window.
 *
 * `payload_digest` rather than the payload: the envelope binds the body without
 * carrying it, so an envelope in an audit trail discloses nothing (D23-14). The
 * payload itself travels beside the envelope and is re-digested on arrival.
 */
export const DeviceOfflineOperationEnvelopeSchema = z
  .object({
    schema_version: z.literal(1),
    offline_operation_id: z.string().uuid(),
    organisation_id: scopedId,
    site_id: scopedId,
    /** The actor is part of the replay identity — one device, many shifts (C14-02). */
    actor_user_id: scopedId,
    device_id: scopedId,
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    operation_kind: FieldOfflineOperationKindSchema,
    /** WP-20 semantics unchanged: contiguous, per-device, never reset. */
    device_sequence: deviceSequence,
    idempotency_key: scopedId,
    payload_digest: DeviceDigestSchema,
    /** C14-04: the authority this operation claims to have acted under. */
    policy_lease_id: scopedId,
    nonce: DeviceNonceSchema,
    /** Client telemetry only. Never server authority. */
    created_at: timestamp,
    signature_profile: DeviceSignatureProfileSchema,
    signature: DeviceSignatureSchema,
  })
  .strict();
export type DeviceOfflineOperationEnvelope = z.infer<typeof DeviceOfflineOperationEnvelopeSchema>;

export type DeviceOfflineOperationStatementInput = Omit<DeviceOfflineOperationEnvelope, 'signature'>;

function deviceOfflineOperationStatementObject(input: DeviceOfflineOperationStatementInput): Record<string, unknown> {
  return {
    domain: DEVICE_OFFLINE_OPERATION_DOMAIN,
    schema_version: input.schema_version,
    offline_operation_id: input.offline_operation_id,
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    actor_user_id: input.actor_user_id,
    device_id: input.device_id,
    key_id: input.key_id,
    key_version: input.key_version,
    operation_kind: input.operation_kind,
    device_sequence: input.device_sequence,
    idempotency_key: input.idempotency_key,
    payload_digest: input.payload_digest,
    policy_lease_id: input.policy_lease_id,
    nonce: input.nonce,
    created_at: input.created_at,
    signature_profile: input.signature_profile,
  };
}

/**
 * EXACTLY what the device signs. Domain-tagged canonical JSON for the C11-01
 * reason: a delimiter-joined string lets a field containing the delimiter forge
 * a different identity tuple under one signature.
 */
export function canonicalDeviceOfflineOperationStatement(input: DeviceOfflineOperationStatementInput): string {
  return canonicalDeviceJson(deviceOfflineOperationStatementObject(input));
}

/**
 * The operation's identity as a digest. This is what an Edge receipt witnesses
 * and what an audit row records — never the envelope's contents.
 */
export function deviceOfflineOperationFingerprint(input: DeviceOfflineOperationStatementInput): string {
  return deviceCanonicalDigest(deviceOfflineOperationStatementObject(input));
}

// ---------------------------------------------------------------------------
// The Edge receipt (D23-10 / C14-04, first half)
// ---------------------------------------------------------------------------

/**
 * EDGE MAY WITNESS. EDGE MAY NOT AUTHORIZE.
 *
 * The only sentence this structure is allowed to express is:
 *
 *   "I, trusted Edge E17, received device-signed operation X at my trusted
 *    time / monotonic position Y."
 *
 * and explicitly NOT:
 *
 *   "I authorize operation X."
 *
 * Origin still comes from the device signature, which travels intact and is
 * verified centrally. Local admissibility still comes from the cached policy
 * lease. Edge contributes independent time and provenance evidence and nothing
 * else — because a compromised Edge must be able to delay, drop or corrupt
 * traffic without being able to FORGE a Field action. If an Edge receipt could
 * confer authority, the whole device-trust model would collapse into trusting
 * the box in the wiring closet.
 *
 * `.strict()` is the enforcement, not the comment. There is no approval field,
 * no authorisation field, no decision field, and no field in which Edge could
 * assert anything about the DEVICE's trust — and adding one is a parse failure
 * rather than a review comment. `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS` names the
 * shapes the Crucible proves cannot be attached.
 */
export const DeviceEdgeReceiptSchema = z
  .object({
    schema_version: z.literal(1),
    edge_id: scopedId,
    edge_key_id: scopedId,
    edge_key_version: DeviceKeyVersionSchema,
    /** The device-signed operation this receipt is ABOUT. A digest, not contents. */
    witnessed_operation_fingerprint: DeviceDigestSchema,
    /** Edge's trusted wall-clock reading, when it has one. */
    edge_trusted_time: timestamp.nullable(),
    /** Edge's monotonic counter position, which survives a clock that does not. */
    edge_monotonic_position: z.number().int().nonnegative().max(MAX_OFFLINE_DEVICE_SEQUENCE).nullable(),
    edge_signature_profile: DeviceSignatureProfileSchema,
    edge_signature: DeviceSignatureSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.edge_trusted_time === null && value.edge_monotonic_position === null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['edge_trusted_time'],
        message: 'a receipt must witness a trusted time or a monotonic position',
      });
    }
  });
export type DeviceEdgeReceipt = z.infer<typeof DeviceEdgeReceiptSchema>;

/**
 * The fields an Edge receipt must NEVER be able to carry, enumerated so the
 * Crucible can prove each one is refused rather than trusting a reviewer to
 * notice. Every entry is a way of saying "I authorize" or "I vouch for the
 * device", which is precisely what D23-10 removes from Edge.
 */
export const DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS = [
  'authorises_operation',
  'authorizes_operation',
  'authorisation',
  'approval',
  'approved_by',
  'decision',
  'device_trust',
  'trust_assertion',
  'vouches_for_device',
  'policy_override',
  'operation_permitted',
] as const;

export type DeviceEdgeReceiptStatementInput = Omit<DeviceEdgeReceipt, 'edge_signature'>;

/**
 * What Edge signs. Note what is absent: there is no operation payload, no
 * verdict, and nothing about the device beyond the fingerprint of what Edge
 * saw. The statement can only ever mean "this passed through me, then".
 */
export function canonicalDeviceEdgeReceiptStatement(input: DeviceEdgeReceiptStatementInput): string {
  return canonicalDeviceJson({
    domain: DEVICE_EDGE_RECEIPT_DOMAIN,
    schema_version: input.schema_version,
    edge_id: input.edge_id,
    edge_key_id: input.edge_key_id,
    edge_key_version: input.edge_key_version,
    witnessed_operation_fingerprint: input.witnessed_operation_fingerprint,
    edge_trusted_time: input.edge_trusted_time,
    edge_monotonic_position: input.edge_monotonic_position,
    edge_signature_profile: input.edge_signature_profile,
  });
}

export function deviceEdgeReceiptFingerprint(input: DeviceEdgeReceiptStatementInput): string {
  return deviceCanonicalDigest({
    domain: DEVICE_EDGE_RECEIPT_DOMAIN,
    schema_version: input.schema_version,
    edge_id: input.edge_id,
    edge_key_id: input.edge_key_id,
    edge_key_version: input.edge_key_version,
    witnessed_operation_fingerprint: input.witnessed_operation_fingerprint,
    edge_trusted_time: input.edge_trusted_time,
    edge_monotonic_position: input.edge_monotonic_position,
    edge_signature_profile: input.edge_signature_profile,
  });
}

/**
 * The witness available at reconciliation.
 *
 * `NONE` is a first-class case, not an omission: no Edge on the path is the
 * ordinary situation for a phone that was simply out of coverage, and it must
 * evaluate to a refusal for time-bounded work rather than to a shrug.
 */
export type DeviceOfflineWitness =
  | { readonly kind: 'NONE' }
  | {
      readonly kind: 'EDGE';
      readonly receipt: DeviceEdgeReceipt;
      /** Edge's OWN trust state. Edge is a principal in its own right (D23-10). */
      readonly edgeTrust: DeviceTrust;
      /** Server's verdict on the Edge signature. Never Edge's claim about itself. */
      readonly edgeSignatureVerified: boolean;
    };

// ---------------------------------------------------------------------------
// Admissibility (C14-04, second half)
// ---------------------------------------------------------------------------

/**
 * Which operation kinds may legitimately arrive stale (D23-12).
 *
 * The directive is explicit that one window must not cover both a queued
 * assignment acknowledgement and a duress signal. An acknowledgement records
 * that a human saw something; it is meaningful whenever it lands, and its
 * authority does not depend on the moment it was produced. Everything else in
 * WP-20's allowlist changes state under an authority that was in force at a
 * particular time, and therefore needs a trustworthy witness placing it inside
 * the lease.
 *
 * WIDENING THIS LIST IS A SECURITY-CONTRACT CHANGE, not a convenience. Each
 * addition is a kind that may commit on a clock nobody independently observed.
 */
export const DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS: readonly FieldOfflineOperationKind[] = ['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'];

/**
 * Time-bounded authority is the default, and the caller cannot override it.
 *
 * There is deliberately no `timeBounded` parameter on the admissibility
 * evaluator: a flag a caller could set would be a flag an attacker's request
 * path could set. The answer is derived from the operation kind alone.
 */
export function deviceOfflineOperationRequiresTimeWitness(kind: FieldOfflineOperationKind): boolean {
  return !DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS.includes(kind);
}

export const DeviceOfflineAdmissibilityRefusalSchema = z.enum([
  'SIGNATURE_NOT_VERIFIED',
  'CREDENTIAL_REVOKED',
  'PAYLOAD_DIGEST_MISMATCH',
  'LEASE_MISSING',
  'LEASE_IDENTITY_MISMATCH',
  'LEASE_SCOPE_MISMATCH',
  'LEASE_NOT_IN_FORCE',
  'NO_TRUSTWORTHY_TIME_WITNESS',
  'EDGE_NOT_TRUSTED',
  'EDGE_SIGNATURE_NOT_VERIFIED',
  'WITNESS_FINGERPRINT_MISMATCH',
]);
export type DeviceOfflineAdmissibilityRefusal = z.infer<typeof DeviceOfflineAdmissibilityRefusalSchema>;

export interface DeviceOfflineAdmissibilityInput {
  readonly envelope: DeviceOfflineOperationEnvelope;
  /** The SERVER's lease record, resolved by `envelope.policy_lease_id`. */
  readonly lease: DevicePolicyLease | null;
  readonly witness: DeviceOfflineWitness;
  /** The authoritative server receipt clock (D23-12). */
  readonly now: string;
  /** Digest the SERVER computed over the payload that arrived alongside. */
  readonly expectedPayloadDigest: string;
  /**
   * SERVER-KNOWN revocation time, or null. D23-08: revocation is evaluated
   * against this, never against timestamps the device supplies.
   */
  readonly deviceRevokedAt: string | null;
  /** The server's verdict on the device signature over the canonical statement. */
  readonly signatureVerified: boolean;
}

export type DeviceOfflineAdmissibility =
  | {
      readonly admitted: true;
      /** Which clock established the authority window. */
      readonly time_basis: 'EDGE_WITNESS' | 'SERVER_RECEIPT';
      readonly established_at: string;
      readonly operation_fingerprint: string;
    }
  | { readonly admitted: false; readonly refusal: DeviceOfflineAdmissibilityRefusal };

/**
 * C14-04: THE DEVICE'S OWN TIMESTAMP NEVER CLOSES THE GAP.
 *
 * Read the ordering as the argument it is:
 *
 *  1. the device signature must verify — origin before anything else;
 *  2. a server-known revocation refuses the operation WHOLESALE (D23-08),
 *     including one the device claims predates the revocation, because a
 *     thief's queue and an honest operative's queue are indistinguishable once
 *     the credential is in the wrong hands;
 *  3. the payload must be the payload the signature covers;
 *  4. the named lease must exist, belong to this device and site, and admit
 *     this operation kind — a missing `policy_lease_id` cannot even be
 *     expressed, because the field is required and signed;
 *  5. for a time-bounded kind, an INDEPENDENT witness must place the operation
 *     inside the lease window. No Edge, an untrusted Edge, an Edge whose
 *     signature does not verify, a receipt about a DIFFERENT operation, or an
 *     Edge with no trusted clock all fail closed;
 *  6. for a stale-tolerant kind, the lease is judged at the SERVER receipt
 *     clock — the only clock we own.
 *
 * `envelope.created_at` appears nowhere in this function. That absence is the
 * contract: a backdated client timestamp cannot revive an expired lease,
 * because nothing ever reads it.
 */
export function evaluateOfflineOperationAdmissibility(input: DeviceOfflineAdmissibilityInput): DeviceOfflineAdmissibility {
  const { envelope, lease, witness } = input;

  if (!input.signatureVerified) return { admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' };
  if (input.deviceRevokedAt !== null) return { admitted: false, refusal: 'CREDENTIAL_REVOKED' };
  if (envelope.payload_digest !== input.expectedPayloadDigest) return { admitted: false, refusal: 'PAYLOAD_DIGEST_MISMATCH' };

  if (lease === null) return { admitted: false, refusal: 'LEASE_MISSING' };
  if (lease.lease_id !== envelope.policy_lease_id) return { admitted: false, refusal: 'LEASE_IDENTITY_MISMATCH' };
  if (
    lease.organisation_id !== envelope.organisation_id ||
    lease.site_id !== envelope.site_id ||
    lease.device_id !== envelope.device_id
  ) {
    return { admitted: false, refusal: 'LEASE_IDENTITY_MISMATCH' };
  }
  if (!lease.scope.includes(envelope.operation_kind)) return { admitted: false, refusal: 'LEASE_SCOPE_MISMATCH' };

  const fingerprint = deviceOfflineOperationFingerprint(envelope);

  if (deviceOfflineOperationRequiresTimeWitness(envelope.operation_kind)) {
    if (witness.kind === 'NONE') return { admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' };
    if (witness.edgeTrust !== 'TRUSTED') return { admitted: false, refusal: 'EDGE_NOT_TRUSTED' };
    if (!witness.edgeSignatureVerified) return { admitted: false, refusal: 'EDGE_SIGNATURE_NOT_VERIFIED' };
    if (witness.receipt.witnessed_operation_fingerprint !== fingerprint) {
      return { admitted: false, refusal: 'WITNESS_FINGERPRINT_MISMATCH' };
    }
    // A monotonic position proves ordering, not wall-clock time. Placing an
    // operation inside a lease window needs a clock, so a receipt carrying only
    // a counter is not a time witness for this purpose.
    if (witness.receipt.edge_trusted_time === null) return { admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' };
    if (classifyDevicePolicyLease(lease, witness.receipt.edge_trusted_time) !== 'VALID') {
      return { admitted: false, refusal: 'LEASE_NOT_IN_FORCE' };
    }
    return {
      admitted: true,
      time_basis: 'EDGE_WITNESS',
      established_at: witness.receipt.edge_trusted_time,
      operation_fingerprint: fingerprint,
    };
  }

  if (classifyDevicePolicyLease(lease, input.now) !== 'VALID') return { admitted: false, refusal: 'LEASE_NOT_IN_FORCE' };
  return { admitted: true, time_basis: 'SERVER_RECEIPT', established_at: input.now, operation_fingerprint: fingerprint };
}

// ---------------------------------------------------------------------------
// Revocation and recovery (D23-15 / C14-06)
// ---------------------------------------------------------------------------

/**
 * D23-15: three threats, three responses, never one flag.
 *
 * LOST            the device may come back and may still be in honest hands.
 * STOLEN          assume adversarial possession.
 * COMPROMISED_KEY assume the credential itself has been copied.
 */
export const DeviceRevocationDispositionSchema = z.enum(['LOST', 'STOLEN', 'COMPROMISED_KEY']);
export type DeviceRevocationDisposition = z.infer<typeof DeviceRevocationDispositionSchema>;

export interface DeviceRevocationResponse {
  /** What the device's trust state becomes. */
  readonly trust: DeviceTrust;
  /** Whether any queued domain operation may execute. Always false. */
  readonly queued_domain_execution: false;
  /** Whether outstanding contexts are invalidated. Always true. */
  readonly invalidates_issued_contexts: true;
  /** Whether the Edge buffer for this device is discarded rather than replayed. */
  readonly discards_edge_buffer: boolean;
  /** Whether THIS identity can ever be restored, versus needing a new one (D23-09). */
  readonly identity_restorable: boolean;
}

/**
 * C14-06, first sharpening. Note the one column that does not vary:
 * `queued_domain_execution` is `false` for all three, typed as the literal
 * `false` so no future edit can flip it for one disposition. The entire point
 * of revocation is to stop trusting anything that credential says.
 *
 * LOST quarantines rather than compromises, because the device may return and
 * a controlled restoration is a legitimate outcome. STOLEN and COMPROMISED_KEY
 * both go to COMPROMISED, which is terminal for that identity — recovery is a
 * new enrollment with a new device_id and a fresh sequence namespace.
 */
export const DEVICE_REVOCATION_RESPONSES: Readonly<Record<DeviceRevocationDisposition, DeviceRevocationResponse>> = {
  LOST: {
    trust: 'QUARANTINED',
    queued_domain_execution: false,
    invalidates_issued_contexts: true,
    discards_edge_buffer: false,
    identity_restorable: true,
  },
  STOLEN: {
    trust: 'COMPROMISED',
    queued_domain_execution: false,
    invalidates_issued_contexts: true,
    discards_edge_buffer: true,
    identity_restorable: false,
  },
  COMPROMISED_KEY: {
    trust: 'COMPROMISED',
    queued_domain_execution: false,
    invalidates_issued_contexts: true,
    discards_edge_buffer: true,
    identity_restorable: false,
  },
};

/**
 * SENTINEL'S OWN AUTHORITATIVE EVIDENCE that an effect already committed.
 *
 * Every field here is server-owned, and the structure has NO field a device
 * could populate: no signature, no device timestamp, no client-claimed
 * commit time, no envelope. That is C14-06's boundary expressed as a type —
 * "trusting Sentinel's own prior evidence, not the device" is only a real
 * distinction if the evidence structurally cannot contain the device's word.
 *
 * `.strict()` is the enforcement; `DEVICE_COMMITTED_EVIDENCE_FORBIDDEN_FIELDS`
 * enumerates what the Crucible proves cannot be attached.
 */
export const DeviceCommittedEffectEvidenceSchema = z
  .object({
    /** A literal, so the only admissible provenance is Sentinel's own record. */
    source: z.literal('SENTINEL_DOMAIN_RECORD'),
    offline_operation_id: z.string().uuid(),
    /** SERVER time at which Sentinel's own record shows the effect committed. */
    committed_at: timestamp,
    /** Pointer into the authoritative domain record. */
    domain_record_ref: scopedId,
  })
  .strict();
export type DeviceCommittedEffectEvidence = z.infer<typeof DeviceCommittedEffectEvidenceSchema>;

export const DEVICE_COMMITTED_EVIDENCE_FORBIDDEN_FIELDS = [
  'signature',
  'device_signature',
  'device_id',
  'device_reported_at',
  'device_claimed_committed_at',
  'nonce',
  'envelope',
  'client_created_at',
] as const;

export const DeviceRevokedOperationResolutionSchema = z.enum(['RESOLVE_AS_COMMITTED', 'REFUSE_NEW_EFFECT', 'REQUIRES_HUMAN_REENTRY']);
export type DeviceRevokedOperationResolution = z.infer<typeof DeviceRevokedOperationResolutionSchema>;

export interface DeviceRevokedOperationInput {
  readonly disposition: DeviceRevocationDisposition;
  readonly offline_operation_id: string;
  /**
   * Sentinel's own record, or null. Deliberately a SEPARATE server-owned input
   * rather than a field on the envelope: an evidence field the device could
   * fill in would be the loophole C14-06 exists to close.
   */
  readonly priorCommittedEvidence: DeviceCommittedEffectEvidence | null;
}

export interface DeviceRevokedOperationDecision {
  readonly resolution: DeviceRevokedOperationResolution;
  readonly reason: string;
}

/**
 * C14-06, in full:
 *
 * > A revoked or compromised credential can never cause a NEW domain mutation.
 * > Server-owned evidence may resolve an already-committed effect; it may never
 * > be used as a loophole to admit a previously unapplied queued request.
 *
 * RESOLVE_AS_COMMITTED requires Sentinel's own authoritative record for THIS
 * operation id. It executes nothing — it records the historical fact that
 * already exists. It is available under every disposition, because it is not
 * trusting the credential at all.
 *
 * Otherwise the work is unapplied, and the disposition decides the route.
 * LOST may still be in honest hands, so the genuinely lost work is routed to
 * human-attested re-entry. STOLEN and COMPROMISED_KEY assume hostile
 * possession: this queue entry causes no effect and is not eligible for
 * automatic re-entry either, because re-entering an attacker's queued request
 * on the operative's behalf would be the same mutation by another name. Real
 * work lost that way is re-originated by a human who witnessed it, not
 * recovered from the queue.
 *
 * This deliberately discards work that may have been legitimate. That is the
 * correct trade, and the contract states the consequence honestly rather than
 * softening it into "accept it if the payload looks plausible".
 */
export function resolveRevokedDeviceOperation(input: DeviceRevokedOperationInput): DeviceRevokedOperationDecision {
  const evidence = input.priorCommittedEvidence;
  if (evidence !== null && evidence.source === 'SENTINEL_DOMAIN_RECORD' && evidence.offline_operation_id === input.offline_operation_id) {
    return {
      resolution: 'RESOLVE_AS_COMMITTED',
      reason: "Sentinel's own authoritative record shows this effect committed; it is recorded as historical fact and never re-executed",
    };
  }
  if (input.disposition === 'LOST') {
    return {
      resolution: 'REQUIRES_HUMAN_REENTRY',
      reason: 'the credential is suspended rather than assumed hostile; unapplied work goes through human-attested re-entry',
    };
  }
  return {
    resolution: 'REFUSE_NEW_EFFECT',
    reason: 'hostile possession is assumed, so this queued request causes no new domain mutation',
  };
}

// ---------------------------------------------------------------------------
// Audit without secret leakage (D23-14, the W21-14 pattern)
// ---------------------------------------------------------------------------

export const DeviceAuditEventTypeSchema = z.enum([
  'ENROLLMENT_REQUESTED',
  'ENROLLMENT_APPROVED',
  'ENROLLMENT_COMMITTED',
  'ENROLLMENT_REFUSED',
  'CONTEXT_ISSUED',
  'CONTEXT_REFUSED',
  'KEY_ROTATED',
  'DEVICE_REVOKED',
  'TRUST_TRANSITIONED',
  'RECONNECT_HANDSHAKE',
  'OFFLINE_OPERATION_ADMITTED',
  'OFFLINE_OPERATION_REFUSED',
]);
export type DeviceAuditEventType = z.infer<typeof DeviceAuditEventTypeSchema>;

/**
 * D23-14: the ONLY fields a device audit payload may carry.
 *
 * This is W21-14 applied to a domain with far more secrets in play. Enrollment,
 * issuance, rotation, revocation, quarantine, trust transitions, reconnect
 * handshakes and refusals must all be auditable to a device, a user, a time and
 * a reason — and none of that requires a private key, a bootstrap token, an
 * attestation blob, a nonce, a challenge, or the contents of a device context.
 *
 * `.strict()` is the enforcement. Every secret-bearing concept is represented
 * here by a DIGEST or a LABEL, so a well-meaning future edit cannot quietly
 * widen an audit row into a disclosure of the very material the model depends
 * on. `DEVICE_AUDIT_FORBIDDEN_FIELDS` enumerates the shapes the Crucible proves
 * are refused.
 */
export const DeviceAuditPayloadSchema = z
  .object({
    schema_version: z.literal(1),
    event_type: DeviceAuditEventTypeSchema,
    organisation_id: scopedId,
    site_id: scopedId.nullable(),
    device_id: scopedId.nullable(),
    actor_user_id: scopedId.nullable(),
    /** The key's registry IDENTITY. Never key material. */
    key_id: scopedId.nullable(),
    key_version: DeviceKeyVersionSchema.nullable(),
    from_trust: DeviceTrustSchema.nullable(),
    to_trust: DeviceTrustSchema.nullable(),
    from_enrollment_state: DeviceEnrollmentStateSchema.nullable(),
    to_enrollment_state: DeviceEnrollmentStateSchema.nullable(),
    /** Digest of the enrollment request — never the request or the public key. */
    enrollment_request_fingerprint: DeviceDigestSchema.nullable(),
    /** Digest of the signed operation — never the envelope or its signature. */
    operation_fingerprint: DeviceDigestSchema.nullable(),
    /** The attestation OUTCOME label. Never the attestation blob. */
    attestation_outcome: DeviceAttestationOutcomeSchema.nullable(),
    attestation_standing: DeviceAttestationStandingSchema.nullable(),
    outcome: z.enum(['ACCEPTED', 'REFUSED']).nullable(),
    /** A machine-readable refusal label from one of the WP-23 refusal enums. */
    refusal_code: scopedId.nullable(),
    /** The human behind a decision, where one made it. */
    decided_by_user_id: scopedId.nullable(),
    occurred_at: timestamp,
    trace_id: DeviceTraceIdSchema,
  })
  .strict();
export type DeviceAuditPayload = z.infer<typeof DeviceAuditPayloadSchema>;

/**
 * The material D23-14 forbids in any audit payload, log line, metric or
 * realtime signal — enumerated so the refusal is proven rather than asserted.
 */
export const DEVICE_AUDIT_FORBIDDEN_FIELDS = [
  'private_key',
  'public_key',
  'key_material',
  'bootstrap_token',
  'bootstrap_grant_token',
  'attestation_blob',
  'attestation_token',
  'nonce',
  'anti_replay_nonce',
  'challenge',
  'challenge_nonce',
  'context',
  'device_context',
  'context_token',
  'signature',
  'payload',
] as const;
