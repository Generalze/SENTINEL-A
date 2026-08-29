import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import { DeviceSignatureProfileSchema, DeviceSignatureSchema } from './device-signature.js';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceDigestSchema,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_REQUEST_PROOF_MAX_AGE_MS,
  DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS,
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

function epochMs(value: string): number {
  return Date.parse(value);
}

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
    const issued = epochMs(value.issued_at);
    const expires = epochMs(value.expires_at);
    if (!(expires > issued)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be after issued_at' });
    } else if (expires - issued > DEVICE_CONTEXT_MAX_LIFETIME_MS) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: `device context lifetime must not exceed ${DEVICE_CONTEXT_MAX_LIFETIME_MS} ms`,
      });
    }
    if (new Set(value.authorised_site_ids).size !== value.authorised_site_ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['authorised_site_ids'], message: 'authorised_site_ids must be unique' });
    }
  });
export type AuthenticatedDeviceContext = z.infer<typeof AuthenticatedDeviceContextSchema>;

/** Remaining lifetime in ms; negative once the context has expired. */
export function deviceContextRemainingMs(context: AuthenticatedDeviceContext, now: string): number {
  return epochMs(context.expires_at) - epochMs(now);
}

export function isDeviceContextExpired(context: AuthenticatedDeviceContext, now: string): boolean {
  return deviceContextRemainingMs(context, now) <= 0;
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
    signature_profile: DeviceSignatureProfileSchema,
    /** Canonical P-256 form; structurally refused before any verifier (C14-01). */
    signature: DeviceSignatureSchema,
  })
  .strict();
export type DeviceRequestProof = z.infer<typeof DeviceRequestProofSchema>;

export type DeviceRequestProofStatementInput = Omit<DeviceRequestProof, 'signature'>;

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
]);
export type DeviceRequestProofRefusal = z.infer<typeof DeviceRequestProofRefusalSchema>;

/**
 * The CURRENT registry record for the device, read at use.
 *
 * D23-07 offered a choice — keep the TTL short enough that the exposure is
 * acceptable, or require a registry check at use. WP-23 does both: the TTL is
 * bounded by `DEVICE_CONTEXT_MAX_LIFETIME_MS`, AND this record is consulted on
 * every evaluation, so a rotation or a revocation lands immediately rather than
 * at the end of the context's life.
 */
export interface DeviceRegistryFacts {
  readonly key_id: string;
  readonly key_version: number;
  /** Server-known revocation. Never a device's word about its own standing. */
  readonly revoked: boolean;
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
  /** Optional narrowing; defaults to every allowlisted purpose. */
  readonly allowedPurposes?: readonly DeviceRequestPurpose[];
}

export type DeviceRequestProofDecision =
  | { readonly admitted: true; readonly fingerprint: string }
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
  const nowMs = epochMs(input.now);

  // 1. The context must be live.
  if (nowMs < epochMs(context.issued_at)) return { admitted: false, refusal: 'CONTEXT_NOT_YET_VALID' };
  if (nowMs >= epochMs(context.expires_at)) return { admitted: false, refusal: 'CONTEXT_EXPIRED' };

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

  // 3. The registry, read at use.
  if (registered.revoked) return { admitted: false, refusal: 'CREDENTIAL_REVOKED' };
  if (registered.key_id !== context.key_id) return { admitted: false, refusal: 'CONTEXT_KEY_MISMATCH' };
  // D23-09: a rotation invalidates every context bound to the old version.
  if (registered.key_version !== context.key_version) return { admitted: false, refusal: 'KEY_VERSION_ROTATED' };

  // 4. Purpose.
  const allowed = input.allowedPurposes ?? DEVICE_REQUEST_PURPOSES;
  if (!allowed.includes(proof.purpose)) return { admitted: false, refusal: 'PURPOSE_NOT_ALLOWED' };

  // 5. Freshness, judged against the server clock in both directions.
  const proofAgeMs = nowMs - epochMs(proof.issued_at);
  if (proofAgeMs < -DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS) return { admitted: false, refusal: 'PROOF_FUTURE_SKEW' };
  if (proofAgeMs > DEVICE_REQUEST_PROOF_MAX_AGE_MS) return { admitted: false, refusal: 'PROOF_STALE' };

  // 6. The proof must be about THIS body.
  if (proof.payload_digest !== input.expectedPayloadDigest) return { admitted: false, refusal: 'PAYLOAD_DIGEST_MISMATCH' };

  // 7. And finally: possession. Without this, everything above is a bearer
  //    credential — which is exactly what C14-03 refuses to ship.
  if (!input.verified) return { admitted: false, refusal: 'POSSESSION_NOT_PROVEN' };

  return { admitted: true, fingerprint: deviceRequestProofFingerprint(proof) };
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
 */
export function evaluateDeviceReconnectHandshake(
  input: Omit<DeviceRequestProofEvaluationInput, 'allowedPurposes'>,
): DeviceRequestProofDecision {
  return evaluateDeviceRequestProof({ ...input, allowedPurposes: ['RECONNECT_HANDSHAKE'] });
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
