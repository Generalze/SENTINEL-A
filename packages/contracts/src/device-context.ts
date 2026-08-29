import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import { bindClaimedSignatureProfile, DeviceSignatureProfileSchema, DeviceSignatureSchema, type DeviceSignatureProfile } from './device-signature.js';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceDigestSchema,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_REQUEST_PROOF_MAX_AGE_MS,
  DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  isExpiredAt,
  parseAuthoritativeInstants,
  refineDeviceInstantWindow,
  type DeviceNonceConsumption,
  type DeviceRevocationDisposition,
} from './device-identity.js';

/**
 * WP-23 sender-constrained device context and per-request possession proof
 * (D23-07 with the C14-03 correction).
 *
 * THE LOCKED INVARIANT
 * --------------------
 * > POSSESSION OF A DEVICE-CONTEXT TOKEN WITHOUT POSSESSION OF THE REGISTERED
 * > HARDWARE PRIVATE KEY MUST BE USELESS.
 *
 * A short TTL plus a registry check does NOT deliver that. A context lifted
 * from memory or transport, replayed inside its lifetime against a registry
 * record that still says TRUSTED, passes every one of those checks — because
 * nothing in that path required the thief to hold the hardware key. So the
 * context is not a bearer credential at all: it is a scope statement, and every
 * security-relevant use is accompanied by a fresh proof of possession that
 * cryptographically binds the request to the device's current registered key.
 *
 * WHAT IS DELIBERATELY ABSENT
 * ---------------------------
 * There is no token field, no opaque `context_token`, no secret, and no
 * `authorization` string anywhere in this module. A context that carried its
 * own bearer secret would re-create the very defect C14-03 corrected, and
 * D23-14 forbids that material appearing in any audit payload regardless.
 */

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

// ---------------------------------------------------------------------------
// The authenticated device context (D23-07)
// ---------------------------------------------------------------------------

/**
 * SERVER-ISSUED, not server-constructed.
 *
 * Every field is established by the issuer from an authenticated user session
 * PLUS an authenticated device credential PLUS current registry state. Nothing
 * a device submits may become one of these values — that is the WP-20/C10-02
 * boundary and the W21-05 boundary, restated at registry scale.
 *
 * `device_trust` lives here rather than in any submitted payload, because a
 * compromised device would otherwise assert its own trustworthiness (D23-05).
 * `key_version` is carried so a rotation invalidates every outstanding context
 * bound to the old version (D23-09), without that invalidation being mistaken
 * for a change of device identity.
 *
 * The lifetime ceiling is the C14-03 arithmetic made explicit: the context's
 * lifetime IS the maximum window in which revocation can be outrun, so it is
 * bounded in the contract rather than configured in a service.
 */
export const AuthenticatedDeviceContextSchema = z
  .object({
    schema_version: z.literal(1),
    /** Identity of this context/session. Bound into every request proof. */
    context_id: scopedId,
    organisation_id: scopedId,
    /** The authenticated user. Custody provenance is NOT this field (C14-02). */
    actor_user_id: scopedId,
    device_id: scopedId,
    /** Site scope resolved at issuance from current entitlement, not claimed. */
    authorised_site_ids: z.array(scopedId).min(1).max(256),
    /** The platform's judgement about the device (D23-05). */
    device_trust: DeviceTrustSchema,
    /** Registry identity of the key every proof must be verified against. */
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    refineDeviceInstantWindow(value, context, DEVICE_CONTEXT_MAX_LIFETIME_MS, 'device context');
    if (new Set(value.authorised_site_ids).size !== value.authorised_site_ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['authorised_site_ids'], message: 'authorised_site_ids must be unique' });
    }
  });
export type AuthenticatedDeviceContext = z.infer<typeof AuthenticatedDeviceContextSchema>;

/**
 * Remaining lifetime in ms; negative once the context has expired. `null` when
 * either instant is unreadable — C15-07: an unanswerable question gets no
 * number, because a number would be compared and quietly admitted.
 */
export function deviceContextRemainingMs(context: AuthenticatedDeviceContext, now: string): number | null {
  const instants = parseAuthoritativeInstants({ expires: context.expires_at, now });
  if (instants === null) return null;
  return instants.expires - instants.now;
}

/** C15-07: expiry is exclusive (`now >= expires_at`), and an unreadable clock is expired. */
export function isDeviceContextExpired(context: AuthenticatedDeviceContext, now: string): boolean {
  const remaining = deviceContextRemainingMs(context, now);
  return remaining === null || remaining <= 0;
}

// ---------------------------------------------------------------------------
// The request proof (C14-03)
// ---------------------------------------------------------------------------

/**
 * Domain separator, DISTINCT from Whisper's.
 *
 * `sentinel.whisper.device-action.v1` signs a recognition; this signs a
 * request. A signature minted for one must never verify as the other, and a
 * shared domain tag would make that possible the moment the two statements
 * happened to share a shape.
 */
export const DEVICE_REQUEST_PROOF_DOMAIN = 'sentinel.device.request-proof.v1';

/**
 * The allowlisted purposes a proof may be minted for.
 *
 * An enum rather than a free string, for the W21-10 reason: a device that could
 * invent its own purpose could sign a statement whose meaning the platform
 * never reviewed, and a proof captured for one purpose could then be presented
 * for another. `RECONNECT_HANDSHAKE` is here because D23-13's handshake obeys
 * the same possession rule as everything else.
 */
export const DEVICE_REQUEST_PURPOSES = [
  'FIELD_OPERATION',
  'OFFLINE_SYNC',
  'RECONNECT_HANDSHAKE',
  'WHISPER_DEVICE_ACTION',
  'DEVICE_KEY_ROTATION',
] as const;
export const DeviceRequestPurposeSchema = z.enum(DEVICE_REQUEST_PURPOSES);
export type DeviceRequestPurpose = z.infer<typeof DeviceRequestPurposeSchema>;

/**
 * The proof that accompanies a request.
 *
 * `payload_digest` is a DIGEST, never the payload: the proof binds the body
 * without carrying it, so a proof travelling through a log or an audit row
 * discloses nothing about the request's contents (D23-14).
 */
export const DeviceRequestProofSchema = z
  .object({
    schema_version: z.literal(1),
    context_id: scopedId,
    organisation_id: scopedId,
    site_id: scopedId,
    actor_user_id: scopedId,
    device_id: scopedId,
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    purpose: DeviceRequestPurposeSchema,
    /** SHA-256 over the canonical request payload. */
    payload_digest: DeviceDigestSchema,
    /** One-shot, scoped to the identity that consumed it (D23-12). */
    nonce: DeviceNonceSchema,
    /** Client-claimed mint time. Judged against the SERVER clock, never trusted as authority. */
    issued_at: timestamp,
    /**
     * C15-01: A CLAIM, NOT AN AUTHORITY.
     *
     * Renamed so it cannot be mistaken for the thing that selects a verifier.
     * The authority is `DeviceRegistryFacts.signature_profile`, resolved from
     * the registry key record; this field is equality-bound to it before
     * verification and refused on disagreement.
     */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /**
     * C15-01: the branded canonical form. The schema itself runs the full
     * decode, so a high-S, zero-scalar, wrong-length or non-canonical value
     * cannot exist inside a parsed proof — the whole structure fails to parse.
     */
    signature: DeviceSignatureSchema,
  })
  .strict();
export type DeviceRequestProof = z.infer<typeof DeviceRequestProofSchema>;

/**
 * C15-01: what the device signs is built from the proof MINUS its claim, PLUS
 * the server's resolved profile. The type makes that substitution mandatory —
 * a `DeviceRequestProof` is not assignable here, so no caller can accidentally
 * sign or fingerprint the client's claimed profile.
 */
export type DeviceRequestProofStatementInput = Omit<DeviceRequestProof, 'signature' | 'claimed_signature_profile'> & {
  /** SERVER-selected, from the registry key record. Never `claimed_signature_profile`. */
  readonly signature_profile: DeviceSignatureProfile;
};

/**
 * Build the statement input by REPLACING the client's claim with the server's
 * answer.
 *
 * Every field is listed rather than spread-minus-two, so what the device signs
 * is legible in one place and a field added to the proof cannot slip into the
 * signed bytes without someone deciding it should be there.
 */
export function deviceRequestProofStatementInput(
  proof: DeviceRequestProof,
  serverResolvedProfile: DeviceSignatureProfile,
): DeviceRequestProofStatementInput {
  return {
    schema_version: proof.schema_version,
    context_id: proof.context_id,
    organisation_id: proof.organisation_id,
    site_id: proof.site_id,
    actor_user_id: proof.actor_user_id,
    device_id: proof.device_id,
    key_id: proof.key_id,
    key_version: proof.key_version,
    purpose: proof.purpose,
    payload_digest: proof.payload_digest,
    nonce: proof.nonce,
    issued_at: proof.issued_at,
    signature_profile: serverResolvedProfile,
  };
}

/**
 * C14-03/C11-01: EXACTLY what the device signs, canonically.
 *
 * Domain-tagged canonical JSON, not a delimiter-joined string — every field is
 * a caller-supplied value that may itself contain the delimiter, so organisation
 * `"a\nb"` with site `"c"` and organisation `"a"` with site `"b\nc"` would
 * otherwise produce identical bytes and one signature would verify for two
 * different identities.
 *
 * The bound set is the C14-03 minimum plus the full identity tuple:
 *
 *   context/session identity   nonce
 *   request purpose            freshness (issued_at)
 *   payload digest             device_id + key_id + key_version
 *   organisation + site + actor
 *
 * Organisation, site and actor are bound even though the context also names
 * them, because a proof that bound only `context_id` would be replayable
 * against any context whose id an attacker learned. Binding the tuple means a
 * mismatch between the proof and the context is a cryptographic contradiction,
 * not a lookup that could be skipped.
 *
 * `signature` is excluded for the obvious reason: it is the output.
 * `device_trust` is excluded because it is the platform's judgement, never the
 * device's (D23-05).
 */
function deviceRequestProofStatementObject(input: DeviceRequestProofStatementInput): Record<string, unknown> {
  return {
    domain: DEVICE_REQUEST_PROOF_DOMAIN,
    schema_version: input.schema_version,
    context_id: input.context_id,
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    actor_user_id: input.actor_user_id,
    device_id: input.device_id,
    key_id: input.key_id,
    key_version: input.key_version,
    purpose: input.purpose,
    payload_digest: input.payload_digest,
    nonce: input.nonce,
    issued_at: input.issued_at,
    signature_profile: input.signature_profile,
  };
}

export function canonicalDeviceRequestProofStatement(input: DeviceRequestProofStatementInput): string {
  return canonicalDeviceJson(deviceRequestProofStatementObject(input));
}

/**
 * SHA-256 over the canonical statement. The digest an audit row may carry.
 *
 * Both this and the statement builder read from ONE object literal, so the
 * signed bytes and the fingerprinted bytes cannot drift apart in a future edit
 * — a drift that would let a signature cover something the fingerprint does not.
 */
export function deviceRequestProofFingerprint(input: DeviceRequestProofStatementInput): string {
  return deviceCanonicalDigest(deviceRequestProofStatementObject(input));
}

// ---------------------------------------------------------------------------
// Replay identity (C15-05)
// ---------------------------------------------------------------------------

/** Domain separator for the request-proof replay identity, distinct from the statement domain. */
export const DEVICE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN = 'sentinel.device.request-proof.replay-identity.v1';

export interface DeviceRequestProofReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly nonce: string;
}

/**
 * C15-05, mirroring `deviceActionWhisperReplayIdentity` exactly.
 *
 * SCOPED, and deliberately NOT the statement fingerprint. The two answer
 * different questions: the fingerprint asks "are these the same bytes?", the
 * replay identity asks "is this the same one-shot slot?". Collapsing them would
 * make every distinct request its own slot, which is no replay protection at
 * all; keeping them separate is what lets the store distinguish an exact retry
 * (same slot, same bytes — converge) from a reuse (same slot, different bytes —
 * conflict).
 *
 * The ACTOR is in the identity for WP-20's reason, restated: one device is
 * legitimately used by several people across shifts, so a nonce consumed by one
 * operative must not consume another's slot, and the same nonce presented under
 * two actors must not look like one request. `key_version` is in it because a
 * rotation is a new credential, and a slot consumed under the old key says
 * nothing about the new one.
 *
 * WP-24 persistence MUST enforce uniqueness with a real composite key over
 * these six columns — a hash is not an identity.
 */
export function deviceRequestProofReplayIdentity(proof: {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly nonce: string;
}): DeviceRequestProofReplayIdentity {
  return {
    organisation_id: proof.organisation_id,
    site_id: proof.site_id,
    actor_user_id: proof.actor_user_id,
    device_id: proof.device_id,
    key_version: proof.key_version,
    nonce: proof.nonce,
  };
}

/** C11-01: canonical JSON, never a delimiter join. */
export function deviceRequestProofReplayKey(proof: Parameters<typeof deviceRequestProofReplayIdentity>[0]): string {
  return canonicalDeviceJson({
    domain: DEVICE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN,
    ...deviceRequestProofReplayIdentity(proof),
  });
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export const DeviceRequestProofRefusalSchema = z.enum([
  'CONTEXT_EXPIRED',
  'CONTEXT_NOT_YET_VALID',
  'CONTEXT_IDENTITY_MISMATCH',
  'CONTEXT_ORGANISATION_MISMATCH',
  'CONTEXT_ACTOR_MISMATCH',
  'CONTEXT_DEVICE_MISMATCH',
  'CONTEXT_SITE_NOT_AUTHORISED',
  'CONTEXT_KEY_MISMATCH',
  'CREDENTIAL_REVOKED',
  'KEY_VERSION_ROTATED',
  'PURPOSE_NOT_ALLOWED',
  'PROOF_STALE',
  'PROOF_FUTURE_SKEW',
  'PAYLOAD_DIGEST_MISMATCH',
  'POSSESSION_NOT_PROVEN',
  /** C15-01: the proof's claimed profile is not the server-resolved one. */
  'SIGNATURE_PROFILE_CLAIM_MISMATCH',
  /** C15-04: the registry's current trust does not admit this purpose (W21-05 shape). */
  'DEVICE_TRUST_NOT_PERMITTED',
  /** C15-04: the registry's trust has FALLEN since the context was issued. */
  'DEVICE_TRUST_DOWNGRADED',
  /** C15-04: the context's actor is no longer the authenticated user, or has lost the capability. */
  'ACTOR_AUTHORITY_REMOVED',
  /** C15-04: the actor's CURRENT entitlement no longer covers the site. */
  'SITE_ENTITLEMENT_LOST',
  /** C15-04: the registry record is about a different organisation or device. */
  'REGISTRY_IDENTITY_MISMATCH',
  /** C15-05: this one-shot identity was already spent on different bytes. */
  'NONCE_REUSED_WITH_CHANGED_SEMANTICS',
  /** C15-05: the consumption fact handed in is about some other request. */
  'NONCE_CONSUMPTION_MISBOUND',
  /** C15-07: an instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
]);
export type DeviceRequestProofRefusal = z.infer<typeof DeviceRequestProofRefusalSchema>;

/**
 * C15-04: WHICH TRUST STATES ADMIT WHICH PURPOSE.
 *
 * `DeviceRegistryFacts` used to carry no trust at all, so a device the registry
 * had already downgraded to SUSPICIOUS kept operating on a context issued while
 * it was TRUSTED, for the whole life of that context. Trust is now a registry
 * fact read at use, and this table is what it is read against.
 *
 * WHISPER_DEVICE_ACTION admits TRUSTED ONLY — that is W21-05, mirrored here so
 * the covert channel cannot be fired from a device we have stopped vouching
 * for. RECONNECT_HANDSHAKE is deliberately the widest: a device coming back
 * from the dark is OFFLINE by definition, and refusing it the handshake would
 * make re-establishing trust impossible for exactly the devices that need to.
 * Even so it does not admit QUARANTINED or COMPROMISED — those are decisions,
 * not uncertainty.
 *
 * WIDENING ANY ROW IS A SECURITY-CONTRACT CHANGE.
 */
export const DEVICE_PURPOSE_PERMITTED_TRUST: Readonly<Record<DeviceRequestPurpose, readonly DeviceTrust[]>> = {
  FIELD_OPERATION: ['TRUSTED', 'DEGRADED'],
  OFFLINE_SYNC: ['TRUSTED', 'DEGRADED'],
  RECONNECT_HANDSHAKE: ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'OFFLINE'],
  WHISPER_DEVICE_ACTION: ['TRUSTED'],
  DEVICE_KEY_ROTATION: ['TRUSTED', 'DEGRADED'],
};

export function deviceTrustPermitsPurpose(trust: DeviceTrust, purpose: DeviceRequestPurpose): boolean {
  return DEVICE_PURPOSE_PERMITTED_TRUST[purpose].includes(trust);
}

/**
 * Operational capability, ordered, so "downgrade" is a fact rather than a
 * feeling (C15-04).
 *
 * COMPROMISED is the floor — a terminal decision. QUARANTINED and SUSPICIOUS
 * are suspicion, in that order. OFFLINE sits ABOVE them: it means "we have not
 * heard from this device", which is ignorance, not suspicion, and a device that
 * was TRUSTED before it went dark has not been accused of anything. DEGRADED is
 * known-good-but-limited, and TRUSTED is the ceiling.
 */
export const DEVICE_TRUST_OPERATIONAL_RANK: Readonly<Record<DeviceTrust, number>> = {
  COMPROMISED: 0,
  QUARANTINED: 1,
  SUSPICIOUS: 2,
  OFFLINE: 3,
  DEGRADED: 4,
  TRUSTED: 5,
};

/** True when `to` sits strictly lower in operational capability than `from`. */
export function isDeviceTrustDowngrade(from: DeviceTrust, to: DeviceTrust): boolean {
  return DEVICE_TRUST_OPERATIONAL_RANK[to] < DEVICE_TRUST_OPERATIONAL_RANK[from];
}

/**
 * C15-04: THE CURRENT AUTHORITY OF THE CURRENT USER.
 *
 * A device context names an actor and a site list resolved AT ISSUANCE. Between
 * issuance and use, that person can be suspended, moved off the site, or have
 * the capability withdrawn — and nothing in WP-23 looked. These are the CURRENT
 * facts, recomputed per request from live roles and entitlement (C12-01), and
 * they are what the evaluator judges against, never the context's snapshot.
 */
export interface DeviceActorAuthorityFacts {
  /** The user authenticated RIGHT NOW. Must still be the context's actor. */
  readonly user_id: string;
  /** The sites this user is CURRENTLY entitled to. Not the context's list. */
  readonly authorised_site_ids: readonly string[];
  /** Whether the user CURRENTLY holds the capability this purpose requires. */
  readonly holds_required_capability: boolean;
}

/**
 * The CURRENT registry record for the device, read at use.
 *
 * D23-07 offered a choice — keep the TTL short enough that the exposure is
 * acceptable, or require a registry check at use. WP-23 does both: the TTL is
 * bounded by `DEVICE_CONTEXT_MAX_LIFETIME_MS`, AND this record is consulted on
 * every evaluation, so a rotation or a revocation lands immediately rather than
 * at the end of the context's life.
 *
 * C15-04 expands it from three fields to the full set of SERVER-OWNED CURRENT
 * facts the decision actually needs. Every one of them was previously either
 * absent or taken from the context's stale snapshot.
 */
export interface DeviceRegistryFacts {
  readonly organisation_id: string;
  readonly device_id: string;
  readonly key_id: string;
  readonly key_version: number;
  /** C15-01: the SERVER-selected profile. The proof's claim is bound to this. */
  readonly signature_profile: DeviceSignatureProfile;
  /** The platform's CURRENT judgement (D23-05). Never the context's snapshot. */
  readonly trust: DeviceTrust;
  /** Server-known revocation. Never a device's word about its own standing. */
  readonly revoked: boolean;
  /** Which of D23-15's three cases, when revoked. `null` otherwise. */
  readonly revocation_disposition: DeviceRevocationDisposition | null;
  /** The authenticated user's CURRENT authority (C15-04). */
  readonly actor: DeviceActorAuthorityFacts;
}

export interface DeviceRequestProofEvaluationInput {
  readonly context: AuthenticatedDeviceContext;
  readonly proof: DeviceRequestProof;
  /** The authoritative server clock at receipt. */
  readonly now: string;
  /** Digest the SERVER computed over the received payload. */
  readonly expectedPayloadDigest: string;
  /** The registry record for this device, read now. */
  readonly registered: DeviceRegistryFacts;
  /**
   * The caller's cryptographic possession check: did this signature verify
   * against the registered public key over `canonicalDeviceRequestProofStatement`?
   *
   * It is a separate, explicit input precisely so the Crucible can hold every
   * other fact valid and set this to `false` — which is the stolen-context
   * scenario, and which must refuse.
   */
  readonly verified: boolean;
  /**
   * C15-04: THE PURPOSE IS EXPECTED, NOT ALLOWED.
   *
   * This replaces an optional `allowedPurposes` that DEFAULTED TO EVERY
   * PURPOSE — so a caller that forgot it accepted a proof minted for any other
   * purpose, and cross-purpose reuse was the default behaviour rather than a
   * refusal. A caller knows what it is doing; it must say so, and exactly one
   * purpose is admissible per evaluation.
   */
  readonly expectedPurpose: DeviceRequestPurpose;
  /**
   * C15-05: the store's report on this proof's one-shot identity. REQUIRED,
   * with no default — an evaluator that can decide without knowing whether the
   * nonce was already spent is an evaluator that admits replays.
   */
  readonly consumption: DeviceNonceConsumption;
}

export type DeviceRequestProofDecision =
  | { readonly admitted: true; readonly effect: 'PROCEED'; readonly fingerprint: string }
  /** C15-05: a byte-identical retry. Converge on the stored outcome; cause no second effect. */
  | { readonly admitted: true; readonly effect: 'CONVERGE_ON_STORED_OUTCOME'; readonly fingerprint: string; readonly stored_outcome_ref: string }
  | { readonly admitted: false; readonly refusal: DeviceRequestProofRefusal };

/**
 * C14-03: the evaluation that makes a lifted context worthless.
 *
 * Ordering is deliberate. The cheap, non-cryptographic checks run first —
 * context lifetime, identity binding, purpose, freshness, payload digest — and
 * POSSESSION IS CHECKED LAST. That way the Crucible's central case (a stolen,
 * still-unexpired context, replayed with every other field perfect, by someone
 * who does not hold the hardware key) reaches the end and refuses with
 * `POSSESSION_NOT_PROVEN` rather than being deflected by an unrelated check.
 * The refusal names the actual reason, which is the point of the ruling.
 *
 * `proof.issued_at` is the device's claim about when it signed. It is judged
 * against the server clock in both directions and is never authority: a device
 * under-reporting its age cannot extend the window, and one claiming to sign
 * from the future cannot either (W21-08 / D23-12).
 */
export function evaluateDeviceRequestProof(input: DeviceRequestProofEvaluationInput): DeviceRequestProofDecision {
  const { context, proof, registered } = input;

  // 0. C15-07: every instant, parsed once, fail-closed. An unreadable clock
  //    used to make every comparison below silently answer "fine".
  const instants = parseAuthoritativeInstants({
    now: input.now,
    contextIssued: context.issued_at,
    contextExpires: context.expires_at,
    proofIssued: proof.issued_at,
  });
  if (instants === null) return { admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  const nowMs = instants.now;

  // 1. The context must be live. C15-07: expiry is exclusive.
  if (nowMs < instants.contextIssued) return { admitted: false, refusal: 'CONTEXT_NOT_YET_VALID' };
  if (isExpiredAt(nowMs, instants.contextExpires)) return { admitted: false, refusal: 'CONTEXT_EXPIRED' };

  // 2. The proof's identity must BE the context's identity. A proof that
  //    disagrees is not a proof about this context (cross-org, cross-user,
  //    cross-device and cross-site replay all die here).
  if (proof.organisation_id !== context.organisation_id) return { admitted: false, refusal: 'CONTEXT_ORGANISATION_MISMATCH' };
  if (proof.actor_user_id !== context.actor_user_id) return { admitted: false, refusal: 'CONTEXT_ACTOR_MISMATCH' };
  if (proof.device_id !== context.device_id) return { admitted: false, refusal: 'CONTEXT_DEVICE_MISMATCH' };
  if (proof.context_id !== context.context_id) return { admitted: false, refusal: 'CONTEXT_IDENTITY_MISMATCH' };
  if (!context.authorised_site_ids.includes(proof.site_id)) return { admitted: false, refusal: 'CONTEXT_SITE_NOT_AUTHORISED' };
  if (proof.key_id !== context.key_id || proof.key_version !== context.key_version) {
    return { admitted: false, refusal: 'CONTEXT_KEY_MISMATCH' };
  }

  // 3. The registry, read at use. The record must be ABOUT this device, or it
  //    is not evidence concerning this request at all.
  if (registered.organisation_id !== context.organisation_id || registered.device_id !== context.device_id) {
    return { admitted: false, refusal: 'REGISTRY_IDENTITY_MISMATCH' };
  }
  if (registered.revoked) return { admitted: false, refusal: 'CREDENTIAL_REVOKED' };
  if (registered.key_id !== context.key_id) return { admitted: false, refusal: 'CONTEXT_KEY_MISMATCH' };
  // D23-09: a rotation invalidates every context bound to the old version.
  if (registered.key_version !== context.key_version) return { admitted: false, refusal: 'KEY_VERSION_ROTATED' };

  // 4. C15-04: purpose is EXPECTED — exactly one — and the registry's current
  //    trust must admit it. A proof minted for another purpose refuses here,
  //    so cross-purpose reuse is a refusal rather than a default.
  if (proof.purpose !== input.expectedPurpose) return { admitted: false, refusal: 'PURPOSE_NOT_ALLOWED' };
  if (!deviceTrustPermitsPurpose(registered.trust, proof.purpose)) {
    return { admitted: false, refusal: 'DEVICE_TRUST_NOT_PERMITTED' };
  }

  // 5. C15-04: CURRENT user authority, not the context's snapshot of it. The
  //    context said who was entitled when it was issued; between then and now
  //    that person can have been suspended or moved off the site.
  if (registered.actor.user_id !== context.actor_user_id) return { admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED' };
  if (!registered.actor.holds_required_capability) return { admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED' };
  if (!registered.actor.authorised_site_ids.includes(proof.site_id)) return { admitted: false, refusal: 'SITE_ENTITLEMENT_LOST' };

  // 6. C15-01: the server resolved the profile; the proof merely claimed one.
  //    Bound before any verification, so the client cannot steer the verifier.
  const profileBinding = bindClaimedSignatureProfile(proof.claimed_signature_profile, registered.signature_profile);
  if (!profileBinding.bound) return { admitted: false, refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' };

  // 7. Freshness, judged against the server clock in both directions.
  const proofAgeMs = nowMs - instants.proofIssued;
  if (proofAgeMs < -DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS) return { admitted: false, refusal: 'PROOF_FUTURE_SKEW' };
  if (proofAgeMs > DEVICE_REQUEST_PROOF_MAX_AGE_MS) return { admitted: false, refusal: 'PROOF_STALE' };

  // 8. The proof must be about THIS body.
  if (proof.payload_digest !== input.expectedPayloadDigest) return { admitted: false, refusal: 'PAYLOAD_DIGEST_MISMATCH' };

  // The canonical statement binds the SERVER's profile, never the claim.
  const fingerprint = deviceRequestProofFingerprint(deviceRequestProofStatementInput(proof, profileBinding.profile));

  // 9. C15-05: the one-shot identity. The fact must be about THIS request —
  //    a consumption record for another proof is not evidence about this one.
  const replayKey = deviceRequestProofReplayKey(proof);
  if (input.consumption.replay_key !== replayKey || input.consumption.statement_fingerprint !== fingerprint) {
    return { admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' };
  }
  if (input.consumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { admitted: false, refusal: 'NONCE_REUSED_WITH_CHANGED_SEMANTICS' };
  }

  // 10. And finally: possession. Without this, everything above is a bearer
  //     credential — which is exactly what C14-03 refuses to ship.
  if (!input.verified) return { admitted: false, refusal: 'POSSESSION_NOT_PROVEN' };

  if (input.consumption.outcome === 'EXACT_DUPLICATE' && input.consumption.stored_outcome_ref !== null) {
    return {
      admitted: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      fingerprint,
      stored_outcome_ref: input.consumption.stored_outcome_ref,
    };
  }

  return { admitted: true, effect: 'PROCEED', fingerprint };
}

// ---------------------------------------------------------------------------
// The reconnect handshake (D23-13 / C14-03)
// ---------------------------------------------------------------------------

/**
 * D23-13's handshake obeys the same rule as every other use: IT AUTHENTICATES
 * BY POSSESSION, NEVER BY PRESENTING A TOKEN.
 *
 * This is a thin wrapper rather than a second proof type on purpose. A separate
 * handshake credential would be a second thing to get wrong, and history says
 * the second thing is where the bearer-token exemption creeps back in. So the
 * handshake reuses `DeviceRequestProofSchema` with `purpose:
 * 'RECONNECT_HANDSHAKE'` and inherits the whole evaluation, including the
 * possession check.
 *
 * A device that reconnects by presenting a context and nothing else is refused
 * with `POSSESSION_NOT_PROVEN`; a proof minted for some other purpose is
 * refused with `PURPOSE_NOT_ALLOWED`. The handshake completes BEFORE any queued
 * operation is examined, and it fails closed as a whole rather than partially
 * admitting a queue.
 *
 * C15-04: THREE THINGS CHANGE WHILE A DEVICE IS DARK, AND ALL THREE ARE NAMED.
 *
 * The reconnect is the one moment where a long gap between issuance and use is
 * GUARANTEED — that is what being offline means. So the three facts most likely
 * to have moved are checked explicitly, each with its own refusal:
 *
 *   1. DEVICE_TRUST_DOWNGRADED   the platform lowered its judgement while the
 *                                device was away. The context still says what
 *                                it said on the day it was issued.
 *   2. ACTOR_AUTHORITY_REMOVED   the operative was suspended, replaced, or had
 *                                the capability withdrawn.
 *   3. SITE_ENTITLEMENT_LOST     the operative no longer works that site.
 *
 * `queue_examination_permitted` makes D23-13's ordering a CONTRACT rather than
 * a comment: identity, trust and entitlement are established first, and the
 * caller is handed a `false` it cannot ignore on any refusal. There is no
 * partial admission — a queue is examined in full or not at all.
 */
export type DeviceReconnectHandshakeDecision =
  | { readonly admitted: true; readonly effect: 'PROCEED'; readonly fingerprint: string; readonly queue_examination_permitted: true }
  | {
      readonly admitted: true;
      readonly effect: 'CONVERGE_ON_STORED_OUTCOME';
      readonly fingerprint: string;
      readonly stored_outcome_ref: string;
      readonly queue_examination_permitted: true;
    }
  | { readonly admitted: false; readonly refusal: DeviceRequestProofRefusal; readonly queue_examination_permitted: false };

export function evaluateDeviceReconnectHandshake(
  input: Omit<DeviceRequestProofEvaluationInput, 'expectedPurpose'>,
): DeviceReconnectHandshakeDecision {
  const { context, registered, proof } = input;

  // D23-13: identity, trust and entitlement BEFORE any queue is examined —
  // which is why these three run ahead of the shared evaluation rather than
  // being folded into it.
  if (isDeviceTrustDowngrade(context.device_trust, registered.trust)) {
    return { admitted: false, refusal: 'DEVICE_TRUST_DOWNGRADED', queue_examination_permitted: false };
  }
  if (registered.actor.user_id !== context.actor_user_id || !registered.actor.holds_required_capability) {
    return { admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED', queue_examination_permitted: false };
  }
  if (!registered.actor.authorised_site_ids.includes(proof.site_id)) {
    return { admitted: false, refusal: 'SITE_ENTITLEMENT_LOST', queue_examination_permitted: false };
  }

  const decision = evaluateDeviceRequestProof({ ...input, expectedPurpose: 'RECONNECT_HANDSHAKE' });
  if (!decision.admitted) return { admitted: false, refusal: decision.refusal, queue_examination_permitted: false };
  if (decision.effect === 'CONVERGE_ON_STORED_OUTCOME') {
    return {
      admitted: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      fingerprint: decision.fingerprint,
      stored_outcome_ref: decision.stored_outcome_ref,
      queue_examination_permitted: true,
    };
  }
  return { admitted: true, effect: 'PROCEED', fingerprint: decision.fingerprint, queue_examination_permitted: true };
}

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

/**
 * Site entitlement and trust sufficiency in one place, for the callers that
 * need to ask before building a request. This answers what the CONTEXT permits;
 * it is never a substitute for `evaluateDeviceRequestProof`, because a context
 * on its own proves nothing about who is holding the hardware.
 */
export function deviceContextPermits(
  context: AuthenticatedDeviceContext,
  requirement: { readonly site_id: string; readonly requiredTrust: readonly DeviceTrust[] },
): boolean {
  return context.authorised_site_ids.includes(requirement.site_id) && requirement.requiredTrust.includes(context.device_trust);
}
