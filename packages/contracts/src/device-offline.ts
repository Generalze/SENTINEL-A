import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import {
  bindClaimedSignatureProfile,
  DeviceP256PublicKeySchema,
  DeviceSignatureProfileSchema,
  DeviceSignatureSchema,
  deviceKeyThumbprintMatches,
  type DeviceSignatureProfile,
} from './device-signature.js';
import { FieldOfflineOperationKindSchema, MAX_OFFLINE_DEVICE_SEQUENCE, type FieldOfflineOperationKind } from './field-offline.js';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceAttestationOutcomeSchema,
  DeviceAttestationStandingSchema,
  DeviceDigestSchema,
  DeviceEnrollmentStateSchema,
  DeviceKeyLifecycleStateSchema,
  deviceKeyStatePermitsHistoricalVerification,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DeviceTraceIdSchema,
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  isExpiredAt,
  parseAuthoritativeInstants,
  refineDeviceInstantWindow,
  type DeviceNonceConsumption,
  type DeviceRevocationDisposition,
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
    /**
     * C15-06: THE LEASE NAMES THE ACTOR WHOSE AUTHORITY JUSTIFIED IT.
     *
     * A lease bound only to a device is a device-wide permit, and on a
     * CONTROLLED_SHARED device that is a hole: operative A, who holds the
     * capability, causes a lease to be issued; the device passes to operative B
     * at shift change; B — who holds nothing — signs envelopes that ride A's
     * lease. Both envelopes name the same device and the same lease, and
     * nothing in WP-23 distinguished them. Binding the actor here, and refusing
     * a mismatch in `evaluateOfflineOperationAdmissibility`, closes it.
     *
     * This is CACHED authority, not live authority: central still revalidates
     * the actor's CURRENT entitlement at reconnect (C15-04). The lease answers
     * "whose authority was cached", never "who is allowed now".
     */
    actor_user_id: scopedId,
    /** The specific capability/authority grant the issuance rested on, for audit and revalidation. */
    authority_basis_id: scopedId,
    scope: z.array(FieldOfflineOperationKindSchema).min(1).max(64),
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    refineDeviceInstantWindow(value, context, DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS, 'policy lease');
    if (new Set(value.scope).size !== value.scope.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['scope'], message: 'scope must be unique' });
    }
  });
export type DevicePolicyLease = z.infer<typeof DevicePolicyLeaseSchema>;

export const DevicePolicyLeaseStandingSchema = z.enum(['VALID', 'NOT_YET_VALID', 'EXPIRED', DEVICE_TIME_NOT_AUTHORITATIVE]);
export type DevicePolicyLeaseStanding = z.infer<typeof DevicePolicyLeaseStandingSchema>;

/**
 * Judged at an explicit instant. The caller must pass a TRUSTWORTHY instant —
 * the server receipt clock, or an Edge-witnessed time — never `created_at` from
 * an envelope. That is not a convention: `evaluateOfflineOperationAdmissibility`
 * below is the only place this is called from in the contract, and it never
 * passes a device-supplied value.
 *
 * C15-07: expiry is EXCLUSIVE (`at >= expires_at` is expired), and an
 * unreadable instant answers `TIME_NOT_AUTHORITATIVE` — which is not `VALID`,
 * so every caller's `!== 'VALID'` test fails closed on it.
 */
export function classifyDevicePolicyLease(lease: DevicePolicyLease, at: string): DevicePolicyLeaseStanding {
  const instants = parseAuthoritativeInstants({ at, issued: lease.issued_at, expires: lease.expires_at });
  if (instants === null) return DEVICE_TIME_NOT_AUTHORITATIVE;
  if (instants.at < instants.issued) return 'NOT_YET_VALID';
  if (isExpiredAt(instants.at, instants.expires)) return 'EXPIRED';
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
    /** C15-01: a non-authoritative claim, equality-bound to the registry's profile. */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /** C15-01: branded; the schema runs the full canonical decode, so a malformed or high-S value cannot reach a parsed envelope. */
    signature: DeviceSignatureSchema,
  })
  .strict();
export type DeviceOfflineOperationEnvelope = z.infer<typeof DeviceOfflineOperationEnvelopeSchema>;

/**
 * C15-01: the signed bytes carry the SERVER-selected profile in place of the
 * device's claim, and the type forbids passing an envelope straight through.
 */
export type DeviceOfflineOperationStatementInput = Omit<DeviceOfflineOperationEnvelope, 'signature' | 'claimed_signature_profile'> & {
  /** SERVER-selected, from the registry key record. Never `claimed_signature_profile`. */
  readonly signature_profile: DeviceSignatureProfile;
};

/**
 * Build the statement input by REPLACING the client's claim with the server's
 * answer. Every field is listed rather than spread-minus-two, so what the
 * device signs is legible in one place.
 */
export function deviceOfflineOperationStatementInput(
  envelope: DeviceOfflineOperationEnvelope,
  serverResolvedProfile: DeviceSignatureProfile,
): DeviceOfflineOperationStatementInput {
  return {
    schema_version: envelope.schema_version,
    offline_operation_id: envelope.offline_operation_id,
    organisation_id: envelope.organisation_id,
    site_id: envelope.site_id,
    actor_user_id: envelope.actor_user_id,
    device_id: envelope.device_id,
    key_id: envelope.key_id,
    key_version: envelope.key_version,
    operation_kind: envelope.operation_kind,
    device_sequence: envelope.device_sequence,
    idempotency_key: envelope.idempotency_key,
    payload_digest: envelope.payload_digest,
    policy_lease_id: envelope.policy_lease_id,
    nonce: envelope.nonce,
    created_at: envelope.created_at,
    signature_profile: serverResolvedProfile,
  };
}

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
// Offline replay identity (C15-05)
// ---------------------------------------------------------------------------

/** Domain separator for the offline-envelope replay identity. */
export const DEVICE_OFFLINE_OPERATION_REPLAY_IDENTITY_DOMAIN = 'sentinel.device.offline-operation.replay-identity.v1';

export interface DeviceOfflineOperationReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly nonce: string;
}

/**
 * C15-05, the same six columns as the request-proof identity and WP-20's
 * Whisper identity before it, for the same reasons — and separate from
 * `deviceOfflineOperationFingerprint`, which answers "same bytes?" rather than
 * "same one-shot slot?".
 *
 * The distinction earns its keep on the offline path more than anywhere else: a
 * queue that reconnects and re-sends is the NORMAL case, so an exact retry must
 * converge on what already happened rather than committing a second effect,
 * while the same slot carrying different bytes is a device rewriting history
 * and must conflict.
 */
export function deviceOfflineOperationReplayIdentity(envelope: {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly nonce: string;
}): DeviceOfflineOperationReplayIdentity {
  return {
    organisation_id: envelope.organisation_id,
    site_id: envelope.site_id,
    actor_user_id: envelope.actor_user_id,
    device_id: envelope.device_id,
    key_version: envelope.key_version,
    nonce: envelope.nonce,
  };
}

/** C11-01: canonical JSON, never a delimiter join. */
export function deviceOfflineOperationReplayKey(envelope: Parameters<typeof deviceOfflineOperationReplayIdentity>[0]): string {
  return canonicalDeviceJson({
    domain: DEVICE_OFFLINE_OPERATION_REPLAY_IDENTITY_DOMAIN,
    ...deviceOfflineOperationReplayIdentity(envelope),
  });
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
    /**
     * C15-01: Edge does not choose its profile either. The claim is
     * equality-bound to the profile on the EDGE registry key record before the
     * receipt's signature is verified.
     */
    claimed_edge_signature_profile: DeviceSignatureProfileSchema,
    /** C15-01: branded; a malformed or high-S Edge signature cannot reach a parsed receipt. */
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

/** C15-01: the Edge statement binds the EDGE REGISTRY's profile, not the receipt's claim. */
export type DeviceEdgeReceiptStatementInput = Omit<DeviceEdgeReceipt, 'edge_signature' | 'claimed_edge_signature_profile'> & {
  readonly edge_signature_profile: DeviceSignatureProfile;
};

export function deviceEdgeReceiptStatementInput(
  receipt: DeviceEdgeReceipt,
  serverResolvedProfile: DeviceSignatureProfile,
): DeviceEdgeReceiptStatementInput {
  return {
    schema_version: receipt.schema_version,
    edge_id: receipt.edge_id,
    edge_key_id: receipt.edge_key_id,
    edge_key_version: receipt.edge_key_version,
    witnessed_operation_fingerprint: receipt.witnessed_operation_fingerprint,
    edge_trusted_time: receipt.edge_trusted_time,
    edge_monotonic_position: receipt.edge_monotonic_position,
    edge_signature_profile: serverResolvedProfile,
  };
}

/**
 * What Edge signs. Note what is absent: there is no operation payload, no
 * verdict, and nothing about the device beyond the fingerprint of what Edge
 * saw. The statement can only ever mean "this passed through me, then".
 *
 * Both this and the fingerprint below read from ONE object literal, so the
 * signed bytes and the fingerprinted bytes cannot drift apart in a future edit.
 */
function deviceEdgeReceiptStatementObject(input: DeviceEdgeReceiptStatementInput): Record<string, unknown> {
  return {
    domain: DEVICE_EDGE_RECEIPT_DOMAIN,
    schema_version: input.schema_version,
    edge_id: input.edge_id,
    edge_key_id: input.edge_key_id,
    edge_key_version: input.edge_key_version,
    witnessed_operation_fingerprint: input.witnessed_operation_fingerprint,
    edge_trusted_time: input.edge_trusted_time,
    edge_monotonic_position: input.edge_monotonic_position,
    edge_signature_profile: input.edge_signature_profile,
  };
}

export function canonicalDeviceEdgeReceiptStatement(input: DeviceEdgeReceiptStatementInput): string {
  return canonicalDeviceJson(deviceEdgeReceiptStatementObject(input));
}

export function deviceEdgeReceiptFingerprint(input: DeviceEdgeReceiptStatementInput): string {
  return deviceCanonicalDigest(deviceEdgeReceiptStatementObject(input));
}

// ---------------------------------------------------------------------------
// The Edge registry seam (C15-02)
// ---------------------------------------------------------------------------

/**
 * C15-02: AN EDGE RECEIPT NOBODY CAN VERIFY IS NOT EVIDENCE.
 *
 * `DeviceOfflineWitness` asks for `edgeSignatureVerified` — a boolean the server
 * is supposed to have computed. Against what? WP-23 named `edge_key_id` and
 * `edge_key_version` and stored no Edge key anywhere, so the verification the
 * whole time-witness argument rests on had nothing to run against. This is the
 * device registry key record's exact counterpart for Edge.
 *
 * `edge_trust` is Edge's OWN trust state — Edge is a principal in its own right
 * (D23-10) — and is deliberately separate from the key's lifecycle `status`: a
 * perfectly valid key belonging to an Edge we have suspended must not witness
 * anything, and a suspended Edge whose key was also rotated is two facts, not
 * one.
 */
export const DeviceEdgeTrustStatusSchema = z.enum(['TRUSTED', 'SUSPENDED', 'REVOKED']);
export type DeviceEdgeTrustStatus = z.infer<typeof DeviceEdgeTrustStatusSchema>;

export const EdgeRegistryKeyRecordSchema = z
  .object({
    schema_version: z.literal(1),
    organisation_id: scopedId,
    edge_id: scopedId,
    edge_key_id: scopedId,
    edge_key_version: DeviceKeyVersionSchema,
    /** The actual Edge public key, in the one canonical representation. */
    public_key: DeviceP256PublicKeySchema,
    /** Must EQUAL the digest derived from `public_key`. Never trusted alone. */
    public_key_thumbprint: DeviceDigestSchema,
    /** SERVER-selected. A receipt's claimed profile is bound to this. */
    signature_profile: DeviceSignatureProfileSchema,
    /** The key's own lifecycle, using the same four states as a device key. */
    status: DeviceKeyLifecycleStateSchema,
    /** The Edge principal's trust, which is a different question from the key's. */
    edge_trust: DeviceEdgeTrustStatusSchema,
    registered_at: timestamp,
    revoked_at: timestamp.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if (!deviceKeyThumbprintMatches(value.public_key, value.public_key_thumbprint)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['public_key_thumbprint'],
        message: 'public_key_thumbprint must equal the digest derived from public_key',
      });
    }
    if ((value.status === 'REVOKED' || value.status === 'COMPROMISED') && value.revoked_at === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['revoked_at'], message: 'a REVOKED or COMPROMISED Edge key must record when it was withdrawn' });
    }
  });
export type EdgeRegistryKeyRecord = z.infer<typeof EdgeRegistryKeyRecordSchema>;

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
      /**
       * C15-02: the SERVER's Edge registry record for this receipt's
       * `edge_key_id + edge_key_version`. It carries the key the signature was
       * checked against, the SERVER-selected Edge profile, the key's lifecycle
       * and Edge's own trust state (D23-10) — the facts that make
       * `edgeSignatureVerified` mean anything.
       */
      readonly registeredEdgeKey: EdgeRegistryKeyRecord;
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
  /** C15-06: the envelope's actor is not the actor whose authority the lease cached. */
  'LEASE_ACTOR_MISMATCH',
  /** C15-01: the envelope's claimed profile is not the server-resolved one. */
  'SIGNATURE_PROFILE_CLAIM_MISMATCH',
  /** C15-01: the receipt's claimed Edge profile is not the Edge registry's. */
  'EDGE_SIGNATURE_PROFILE_CLAIM_MISMATCH',
  /** C15-02: the Edge key record is about a different key, or is no longer usable. */
  'EDGE_KEY_NOT_USABLE',
  /** C15-05: this one-shot identity was already spent on different bytes. */
  'NONCE_REUSED_WITH_CHANGED_SEMANTICS',
  /** C15-05: the consumption fact handed in is about some other operation. */
  'NONCE_CONSUMPTION_MISBOUND',
  /** C15-07: an instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
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
  /**
   * C15-01: the profile the registry key record names for this device's
   * `key_id + key_version`. `envelope.claimed_signature_profile` is bound to it.
   */
  readonly registeredSignatureProfile: DeviceSignatureProfile;
  /**
   * C15-05: the store's report on this envelope's one-shot identity. REQUIRED,
   * with no default — a reconnecting queue re-sends by design, so an evaluator
   * that cannot tell a retry from a rewrite commits duplicate effects.
   */
  readonly consumption: DeviceNonceConsumption;
}

export type DeviceOfflineAdmissibility =
  | {
      readonly admitted: true;
      readonly effect: 'PROCEED';
      /** Which clock established the authority window. */
      readonly time_basis: 'EDGE_WITNESS' | 'SERVER_RECEIPT';
      readonly established_at: string;
      readonly operation_fingerprint: string;
    }
  /** C15-05: a byte-identical retry of one queued operation. No second effect. */
  | {
      readonly admitted: true;
      readonly effect: 'CONVERGE_ON_STORED_OUTCOME';
      readonly time_basis: 'EDGE_WITNESS' | 'SERVER_RECEIPT';
      readonly established_at: string;
      readonly operation_fingerprint: string;
      readonly stored_outcome_ref: string;
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

  // C15-01: bind the claimed profile to the registry's BEFORE anything else, so
  // the fingerprint below is computed over the server's profile.
  const profileBinding = bindClaimedSignatureProfile(envelope.claimed_signature_profile, input.registeredSignatureProfile);
  if (!profileBinding.bound) return { admitted: false, refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' };

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
  // C15-06: the lease belongs to the ACTOR whose authority justified it. On a
  // CONTROLLED_SHARED device this is the whole defence: operative B cannot ride
  // the lease operative A's capability produced.
  if (lease.actor_user_id !== envelope.actor_user_id) return { admitted: false, refusal: 'LEASE_ACTOR_MISMATCH' };
  if (!lease.scope.includes(envelope.operation_kind)) return { admitted: false, refusal: 'LEASE_SCOPE_MISMATCH' };

  const fingerprint = deviceOfflineOperationFingerprint(deviceOfflineOperationStatementInput(envelope, profileBinding.profile));

  // C15-05: the one-shot identity, and the fact must be about THIS operation.
  const replayKey = deviceOfflineOperationReplayKey(envelope);
  if (input.consumption.replay_key !== replayKey || input.consumption.statement_fingerprint !== fingerprint) {
    return { admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' };
  }
  if (input.consumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { admitted: false, refusal: 'NONCE_REUSED_WITH_CHANGED_SEMANTICS' };
  }
  const storedOutcomeRef = input.consumption.outcome === 'EXACT_DUPLICATE' ? input.consumption.stored_outcome_ref : null;

  if (deviceOfflineOperationRequiresTimeWitness(envelope.operation_kind)) {
    if (witness.kind === 'NONE') return { admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' };
    // C15-02: the Edge key record must be ABOUT this receipt's key and must
    // still be able to verify. A key we revoked cannot witness anything, and a
    // record for another key is not evidence about this signature.
    if (
      witness.registeredEdgeKey.edge_id !== witness.receipt.edge_id ||
      witness.registeredEdgeKey.edge_key_id !== witness.receipt.edge_key_id ||
      witness.registeredEdgeKey.edge_key_version !== witness.receipt.edge_key_version ||
      !deviceKeyStatePermitsHistoricalVerification(witness.registeredEdgeKey.status)
    ) {
      return { admitted: false, refusal: 'EDGE_KEY_NOT_USABLE' };
    }
    if (witness.registeredEdgeKey.edge_trust !== 'TRUSTED') return { admitted: false, refusal: 'EDGE_NOT_TRUSTED' };
    const edgeProfileBinding = bindClaimedSignatureProfile(
      witness.receipt.claimed_edge_signature_profile,
      witness.registeredEdgeKey.signature_profile,
    );
    if (!edgeProfileBinding.bound) return { admitted: false, refusal: 'EDGE_SIGNATURE_PROFILE_CLAIM_MISMATCH' };
    if (!witness.edgeSignatureVerified) return { admitted: false, refusal: 'EDGE_SIGNATURE_NOT_VERIFIED' };
    if (witness.receipt.witnessed_operation_fingerprint !== fingerprint) {
      return { admitted: false, refusal: 'WITNESS_FINGERPRINT_MISMATCH' };
    }
    // A monotonic position proves ordering, not wall-clock time. Placing an
    // operation inside a lease window needs a clock, so a receipt carrying only
    // a counter is not a time witness for this purpose.
    const edgeTime = witness.receipt.edge_trusted_time;
    if (edgeTime === null) return { admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' };
    const standing = classifyDevicePolicyLease(lease, edgeTime);
    // C15-07: an unreadable witnessed instant is not a witness at all.
    if (standing === DEVICE_TIME_NOT_AUTHORITATIVE) return { admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
    if (standing !== 'VALID') return { admitted: false, refusal: 'LEASE_NOT_IN_FORCE' };
    if (storedOutcomeRef !== null) {
      return {
        admitted: true,
        effect: 'CONVERGE_ON_STORED_OUTCOME',
        time_basis: 'EDGE_WITNESS',
        established_at: edgeTime,
        operation_fingerprint: fingerprint,
        stored_outcome_ref: storedOutcomeRef,
      };
    }
    return {
      admitted: true,
      effect: 'PROCEED',
      time_basis: 'EDGE_WITNESS',
      established_at: edgeTime,
      operation_fingerprint: fingerprint,
    };
  }

  const standing = classifyDevicePolicyLease(lease, input.now);
  if (standing === DEVICE_TIME_NOT_AUTHORITATIVE) return { admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  if (standing !== 'VALID') return { admitted: false, refusal: 'LEASE_NOT_IN_FORCE' };
  if (storedOutcomeRef !== null) {
    return {
      admitted: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      time_basis: 'SERVER_RECEIPT',
      established_at: input.now,
      operation_fingerprint: fingerprint,
      stored_outcome_ref: storedOutcomeRef,
    };
  }
  return { admitted: true, effect: 'PROCEED', time_basis: 'SERVER_RECEIPT', established_at: input.now, operation_fingerprint: fingerprint };
}

// ---------------------------------------------------------------------------
// Revocation and recovery (D23-15 / C14-06)
// ---------------------------------------------------------------------------

/**
 * D23-15's three dispositions are defined in `device-identity.ts` (C15-04 needs
 * them on `DeviceRegistryFacts` too) and re-stated here only in the response
 * table below. `DeviceRevocationDispositionSchema` is imported, not redeclared:
 * two enums with one name is how they drift apart.
 */
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
    /**
     * C15-06: THE EXACT OPERATION, NOT MERELY ITS ID.
     *
     * Evidence keyed on `offline_operation_id` alone says "something with this
     * id committed". An id is a value a device chooses, so a revoked device
     * could re-present a DIFFERENT operation under an id Sentinel had already
     * recorded as committed and have it resolved as historical fact — turning
     * C14-06's narrow "recognise what already happened" into a general
     * write path for a credential we no longer trust. Binding the operation
     * FINGERPRINT means the evidence is about specific bytes, which is WP-20's
     * request-bound idempotency rule, unchanged.
     */
    operation_fingerprint: DeviceDigestSchema,
    /** C15-06: and the tenant scope, so evidence cannot cross an organisation or site. */
    organisation_id: scopedId,
    site_id: scopedId,
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

export const DeviceRevokedOperationResolutionSchema = z.enum([
  'RESOLVE_AS_COMMITTED',
  'REFUSE_NEW_EFFECT',
  'REQUIRES_HUMAN_REENTRY',
  /**
   * C15-06: an operation id Sentinel has committed evidence for, presented with
   * DIFFERENT bytes or in a different tenant scope. It is neither the thing
   * that committed nor a fresh piece of work — it is a collision, and the only
   * safe answer is to resolve nothing and cause nothing.
   */
  'CONFLICT',
]);
export type DeviceRevokedOperationResolution = z.infer<typeof DeviceRevokedOperationResolutionSchema>;

export interface DeviceRevokedOperationInput {
  readonly disposition: DeviceRevocationDisposition;
  readonly offline_operation_id: string;
  /** C15-06: the fingerprint of the operation actually being resolved. */
  readonly operation_fingerprint: string;
  /** C15-06: the tenant scope it is being resolved in. */
  readonly organisation_id: string;
  readonly site_id: string;
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
    // C15-06: the id matching is NOT enough. The evidence must be about these
    // exact bytes in this exact tenant scope, or the "already committed" answer
    // is being given about a different operation.
    const sameOperation =
      evidence.operation_fingerprint === input.operation_fingerprint &&
      evidence.organisation_id === input.organisation_id &&
      evidence.site_id === input.site_id;
    if (!sameOperation) {
      return {
        resolution: 'CONFLICT',
        reason:
          "Sentinel's record for this operation id is about different bytes or a different tenant scope; a reused id is a collision, never a resolution",
      };
    }
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
