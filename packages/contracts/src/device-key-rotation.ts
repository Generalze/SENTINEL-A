import { z } from 'zod';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceDigestSchema,
  DeviceKeyStorageSchema,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  isConsistentDeviceNonceConsumption,
  isExpiredAt,
  parseAuthoritativeInstants,
  refineDeviceInstantWindow,
  type DeviceKeyLifecycleState,
  type DeviceNonceConsumption,
} from './device-identity.js';
import {
  bindClaimedSignatureProfile,
  deviceKeyThumbprintMatches,
  DeviceP256PublicKeySchema,
  DeviceSignatureProfileSchema,
  DeviceSignatureSchema,
  type DeviceSignatureProfile,
} from './device-signature.js';

/**
 * WP-24 / D24-10A — THE KEY-ROTATION POSSESSION CONTRACT.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * D24-10 requires a routine rotation to prove two independent things:
 * CONTINUITY of the credential being replaced, and POSSESSION of the credential
 * replacing it. WP-23 could express the first and could not express the second.
 *
 *   continuity   `DeviceRequestProof`, purpose `DEVICE_KEY_ROTATION`, signed by
 *                the CURRENT key. The purpose already exists in the frozen
 *                enum and needs nothing new.
 *
 *   possession   nothing. The only possession statement WP-23 defines is
 *                enrollment-scoped: `sentinel.device.possession-challenge.v1`
 *                binds `enrollment_request_id` and
 *                `enrollment_request_fingerprint`, and its replay identity
 *                requires the enrollment request id.
 *
 * Repurposing the enrollment statement was the obvious shortcut and is exactly
 * what D24-10's stop condition forbids. A rotation proof and an enrollment
 * proof carrying the same ids would have produced BYTE-IDENTICAL signed bytes,
 * which is the one thing a domain tag exists to prevent, and rotation
 * consumption would have been filed under an enrollment replay identity. So
 * this is a NEW domain rather than a reinterpreted one.
 *
 * WHAT THIS FILE IS NOT
 * ---------------------
 * It performs no curve arithmetic and imports no key. A new public key passes
 * the structural and canonical checks here and is then handed to the RUNTIME
 * crypto provider (Node/OpenSSL) for P-256 import and curve validation before
 * any signature over it can mean anything — D24-05. An off-curve point that
 * satisfies every schema in this file must still be refused there.
 *
 * WP-23 IS NOT REOPENED. This file adds two domains and reuses WP-23's frozen
 * primitives; it changes none of them.
 */

// ---------------------------------------------------------------------------
// Shared primitives (the WP-23 shapes, deliberately identical)
// ---------------------------------------------------------------------------

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

/** Signed statement domain for the NEW key's possession proof. */
export const DEVICE_KEY_ROTATION_POSSESSION_DOMAIN = 'sentinel.device.key-rotation-possession.v1';

/** Domain for the rotation ceremony's one-shot replay identity. */
export const DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN = 'sentinel.device.key-rotation.replay-identity.v1';

/** Canonical request domain, so a rotation request fingerprint is never any other digest. */
export const DEVICE_KEY_ROTATION_REQUEST_DOMAIN = 'sentinel.device.key-rotation-request.v1';

/**
 * D24-10A: the rotation challenge ceiling, with its OWN NAME.
 *
 * It is numerically equal to `DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS` today,
 * and that equality is a coincidence of policy rather than a shared rule. Two
 * ceremonies that happen to share a duration must not become coupled by it: if
 * enrollment's window is ever revisited, rotation's must not move silently
 * along with it, and vice versa. The constant is separately named and
 * separately tested so a future change to either is a visible, arguable diff.
 */
export const DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS = 120_000;

// ---------------------------------------------------------------------------
// The rotation request
// ---------------------------------------------------------------------------

/**
 * D24-10A: THE ROTATION REQUEST IS AN EXACT SEMANTIC OBJECT.
 *
 * "Hash some payload" would have left the continuity proof free-floating: a
 * `DeviceRequestProof` whose `payload_digest` covered an unspecified blob could
 * be captured and re-presented alongside a DIFFERENT replacement key, and the
 * old key would appear to have authorised a key it never saw. The digest binds
 * this exact proposal instead, so the continuity proof cannot be borrowed.
 *
 * `proposed_key_version === current_key_version + 1` is enforced at PARSE, not
 * merely checked later. "Greater than" would admit skipped versions, and a
 * client that can skip versions can shape registry history — leaving gaps that
 * make "which key signed this?" unanswerable for the versions nothing occupies.
 * The server generates the proposed key identity and version; the field exists
 * here so the signed statements can bind it, not so a client can choose it.
 *
 * `new_public_key_thumbprint` is DERIVED from `new_public_key` and refused when
 * it disagrees, exactly as `DeviceRegistryKeyRecord` does. A thumbprint that
 * travels beside a key and is believed is not a binding; it is a second field
 * to forge.
 */
export const DeviceKeyRotationRequestSchema = z
  .object({
    schema_version: z.literal(1),
    rotation_request_id: scopedId,
    organisation_id: scopedId,
    device_id: scopedId,
    /** The credential being superseded, as the registry currently holds it. */
    current_key_id: scopedId,
    current_key_version: DeviceKeyVersionSchema,
    /** SERVER-generated. A client that picks its own key identity shapes history. */
    proposed_key_id: scopedId,
    proposed_key_version: DeviceKeyVersionSchema,
    /** The actual new key, in WP-23's single canonical representation. */
    new_public_key: DeviceP256PublicKeySchema,
    /** Must EQUAL the digest derived from `new_public_key`. Never trusted alone. */
    new_public_key_thumbprint: DeviceDigestSchema,
    /** HARDWARE_BACKED or SOFTWARE. Recorded here; trust consequences are D23-03's. */
    new_key_storage: DeviceKeyStorageSchema,
    /** SERVER-resolved for the proposed key. Never a client's claim (C11-04/C15-01). */
    server_resolved_signature_profile: DeviceSignatureProfileSchema,
    requested_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    // `deviceKeyThumbprintMatches` rather than a direct comparison, for the
    // C15-02 reason: a branded field's own refinement marks the parse dirty
    // rather than aborting it, so this block can still see a non-canonical key.
    // The matcher answers `false` where a deriver would throw.
    if (!deviceKeyThumbprintMatches(value.new_public_key, value.new_public_key_thumbprint)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['new_public_key_thumbprint'],
        message: 'new_public_key_thumbprint must equal the digest derived from new_public_key',
      });
    }
    if (value.proposed_key_version !== value.current_key_version + 1) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['proposed_key_version'],
        message: 'proposed_key_version must be exactly current_key_version + 1 (D24-10A: no skipped versions)',
      });
    }
    if (value.proposed_key_id === value.current_key_id) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['proposed_key_id'],
        message: 'a rotation replaces the key: proposed_key_id must differ from current_key_id',
      });
    }
  });
export type DeviceKeyRotationRequest = z.infer<typeof DeviceKeyRotationRequestSchema>;

/**
 * The canonical bytes of a rotation request.
 *
 * Canonical JSON, domain-tagged, sorted keys — the C11-01 discipline, never a
 * delimiter join, so no field value containing a separator can forge another
 * tuple. Every field of the request is covered: this digest is what the
 * CURRENT key's continuity proof carries as its `payload_digest`, and anything
 * omitted here would be something the old key did not actually authorise.
 */
export function canonicalDeviceKeyRotationRequestStatement(request: DeviceKeyRotationRequest): string {
  return canonicalDeviceJson({
    domain: DEVICE_KEY_ROTATION_REQUEST_DOMAIN,
    schema_version: request.schema_version,
    rotation_request_id: request.rotation_request_id,
    organisation_id: request.organisation_id,
    device_id: request.device_id,
    current_key_id: request.current_key_id,
    current_key_version: request.current_key_version,
    proposed_key_id: request.proposed_key_id,
    proposed_key_version: request.proposed_key_version,
    new_public_key: request.new_public_key,
    new_public_key_thumbprint: request.new_public_key_thumbprint,
    new_key_storage: request.new_key_storage,
    server_resolved_signature_profile: request.server_resolved_signature_profile,
    requested_at: request.requested_at,
  });
}

/** SHA-256 over the canonical rotation-request statement. */
export function deviceKeyRotationRequestFingerprint(request: DeviceKeyRotationRequest): string {
  return deviceCanonicalDigest(JSON.parse(canonicalDeviceKeyRotationRequestStatement(request)) as unknown);
}

// ---------------------------------------------------------------------------
// The rotation challenge
// ---------------------------------------------------------------------------

/**
 * Server-issued, one-shot, and bound to the WHOLE proposal.
 *
 * A challenge that carried only a nonce could be answered for any rotation the
 * device liked; binding the request, its fingerprint and both key identities
 * means a challenge issued for one proposal cannot be answered for another. The
 * fingerprint travels alongside the id for the same reason it does in the
 * enrollment ceremony — an id names a row, a fingerprint names its CONTENTS,
 * and only the second detects a row that was rewritten.
 */
export const DeviceKeyRotationChallengeSchema = z
  .object({
    schema_version: z.literal(1),
    challenge_id: scopedId,
    organisation_id: scopedId,
    device_id: scopedId,
    rotation_request_id: scopedId,
    rotation_request_fingerprint: DeviceDigestSchema,
    current_key_id: scopedId,
    current_key_version: DeviceKeyVersionSchema,
    proposed_key_id: scopedId,
    proposed_key_version: DeviceKeyVersionSchema,
    new_public_key_thumbprint: DeviceDigestSchema,
    nonce: DeviceNonceSchema,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    refineDeviceInstantWindow(value, context, DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS, 'key rotation challenge');
    if (value.proposed_key_version !== value.current_key_version + 1) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['proposed_key_version'],
        message: 'proposed_key_version must be exactly current_key_version + 1 (D24-10A)',
      });
    }
  });
export type DeviceKeyRotationChallenge = z.infer<typeof DeviceKeyRotationChallengeSchema>;

// ---------------------------------------------------------------------------
// The new key's possession statement
// ---------------------------------------------------------------------------

/**
 * What the NEW key signs, and the only thing it signs.
 *
 * The new public key itself is deliberately NOT repeated in these bytes: the
 * rotation request fingerprint already commits to it, and duplicating a value
 * inside a statement that also commits to a digest of that value creates two
 * places for them to disagree. The THUMBPRINT stays explicit because it is the
 * readable cryptographic binding a human or an audit row can check without
 * recomputing a whole request.
 *
 * `signature_profile` is the SERVER-RESOLVED profile for the proposed key.
 * There is no `claimed_signature_profile` here at all — a statement type that
 * cannot express a client's claim cannot be steered by one.
 */
export interface DeviceKeyRotationPossessionStatementInput {
  readonly organisation_id: string;
  readonly device_id: string;
  readonly rotation_request_id: string;
  readonly rotation_request_fingerprint: string;
  readonly current_key_id: string;
  readonly current_key_version: number;
  readonly proposed_key_id: string;
  readonly proposed_key_version: number;
  readonly new_public_key_thumbprint: string;
  readonly rotation_challenge_id: string;
  readonly nonce: string;
  /** SERVER-resolved. Never a submitted claim. */
  readonly signature_profile: DeviceSignatureProfile;
}

export function canonicalDeviceKeyRotationPossessionStatement(input: DeviceKeyRotationPossessionStatementInput): string {
  return canonicalDeviceJson({
    domain: DEVICE_KEY_ROTATION_POSSESSION_DOMAIN,
    schema_version: 1,
    organisation_id: input.organisation_id,
    device_id: input.device_id,
    rotation_request_id: input.rotation_request_id,
    rotation_request_fingerprint: input.rotation_request_fingerprint,
    current_key_id: input.current_key_id,
    current_key_version: input.current_key_version,
    proposed_key_id: input.proposed_key_id,
    proposed_key_version: input.proposed_key_version,
    new_public_key_thumbprint: input.new_public_key_thumbprint,
    rotation_challenge_id: input.rotation_challenge_id,
    nonce: input.nonce,
    signature_profile: input.signature_profile,
  });
}

/** SHA-256 over the canonical new-key possession statement. */
export function deviceKeyRotationPossessionStatementFingerprint(input: DeviceKeyRotationPossessionStatementInput): string {
  return deviceCanonicalDigest(JSON.parse(canonicalDeviceKeyRotationPossessionStatement(input)) as unknown);
}

/**
 * The device's answer. `answered_at` is CLIENT TELEMETRY and is read nowhere in
 * any evaluation — freshness is the server's `verified_at`, exactly as C15-03
 * ruled for the enrollment ceremony.
 */
export const DeviceKeyRotationPossessionResponseSchema = z
  .object({
    schema_version: z.literal(1),
    challenge_id: scopedId,
    rotation_request_id: scopedId,
    /** A non-authoritative claim, equality-bound to the server's profile before use. */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /** Branded: the schema runs WP-23's full canonical decode, so a malformed or high-S value cannot reach a parsed response. */
    signature: DeviceSignatureSchema,
    answered_at: timestamp,
  })
  .strict();
export type DeviceKeyRotationPossessionResponse = z.infer<typeof DeviceKeyRotationPossessionResponseSchema>;

// ---------------------------------------------------------------------------
// The server's verdict
// ---------------------------------------------------------------------------

/**
 * D24-10A: THERE IS NO `newKeyPossessionVerified: true` ANYWHERE.
 *
 * A naked boolean is a verdict about nothing, and C15-03 already removed one
 * from the enrollment ceremony for that reason. This carries everything the
 * check was bound to, so a genuine verdict produced for another rotation,
 * challenge, device, proposed key or request fingerprint is structurally
 * unusable rather than merely unlikely to be misapplied.
 *
 * `source` is a literal for the C14-06 reason: the only admissible provenance
 * is Sentinel's own verifier, and a structure a device could populate would be
 * the loophole.
 */
export const DeviceKeyRotationPossessionVerificationResultSchema = z
  .object({
    schema_version: z.literal(1),
    source: z.literal('SENTINEL_DEVICE_KEY_ROTATION_VERIFIER'),
    /** The server's answer. `false` is a real, recordable verdict. */
    verified: z.boolean(),
    organisation_id: scopedId,
    device_id: scopedId,
    rotation_request_id: scopedId,
    rotation_request_fingerprint: DeviceDigestSchema,
    rotation_challenge_id: scopedId,
    current_key_id: scopedId,
    current_key_version: DeviceKeyVersionSchema,
    proposed_key_id: scopedId,
    proposed_key_version: DeviceKeyVersionSchema,
    new_public_key_thumbprint: DeviceDigestSchema,
    /** The SERVER-selected profile the check actually ran under. */
    signature_profile: DeviceSignatureProfileSchema,
    /** The exact canonical possession statement the signature was checked over. */
    canonical_statement_fingerprint: DeviceDigestSchema,
    /** THE SERVER'S verification instant. This, and not `answered_at`, is freshness. */
    verified_at: timestamp,
  })
  .strict();
export type DeviceKeyRotationPossessionVerificationResult = z.infer<
  typeof DeviceKeyRotationPossessionVerificationResultSchema
>;

// ---------------------------------------------------------------------------
// Replay identity
// ---------------------------------------------------------------------------

export interface DeviceKeyRotationReplayIdentity {
  readonly organisation_id: string;
  readonly device_id: string;
  readonly rotation_request_id: string;
  readonly rotation_challenge_id: string;
  readonly current_key_id: string;
  readonly current_key_version: number;
  readonly proposed_key_id: string;
  readonly proposed_key_version: number;
  readonly nonce: string;
}

/**
 * The identity a durable uniqueness constraint is built over, as STRUCTURE.
 *
 * A hash is not an identity — you cannot query it, audit it, or reason about
 * its parts — so the columns are named and the string form below exists only
 * for comparison and logging. This mirrors `devicePossessionChallengeReplayIdentity`
 * exactly, and for the same reason.
 */
export function deviceKeyRotationReplayIdentity(input: DeviceKeyRotationReplayIdentity): DeviceKeyRotationReplayIdentity {
  return {
    organisation_id: input.organisation_id,
    device_id: input.device_id,
    rotation_request_id: input.rotation_request_id,
    rotation_challenge_id: input.rotation_challenge_id,
    current_key_id: input.current_key_id,
    current_key_version: input.current_key_version,
    proposed_key_id: input.proposed_key_id,
    proposed_key_version: input.proposed_key_version,
    nonce: input.nonce,
  };
}

/** C11-01: canonical JSON, never a delimiter join — a value containing the delimiter would forge another tuple. */
export function deviceKeyRotationReplayKey(input: DeviceKeyRotationReplayIdentity): string {
  return canonicalDeviceJson({
    domain: DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN,
    ...deviceKeyRotationReplayIdentity(input),
  });
}

// ---------------------------------------------------------------------------
// Admissibility
// ---------------------------------------------------------------------------

export const DeviceKeyRotationRefusalSchema = z.enum([
  /** The claimed profile is not the server-resolved one, or the server's is unapproved. */
  'SIGNATURE_PROFILE_CLAIM_MISMATCH',
  /** The request handed in is not the request the rest of the ceremony is about. */
  'ROTATION_REQUEST_MISBOUND',
  /** The challenge is about a different rotation, device, key or proposal. */
  'CHALLENGE_MISBOUND',
  /** The challenge window has closed, judged on the SERVER's verification instant. */
  'CHALLENGE_EXPIRED',
  /** The verification instant precedes the challenge it verified. */
  'CHALLENGE_NOT_YET_ISSUED',
  /** A verdict the server could not yet have produced. */
  'POSSESSION_VERIFIED_IN_FUTURE',
  /** No server verdict at all. A missing verdict is never a passing one. */
  'POSSESSION_VERIFICATION_MISSING',
  /** A genuine verdict, produced for a DIFFERENT rotation. */
  'POSSESSION_VERIFICATION_MISBOUND',
  /** The verdict covered different bytes than this ceremony's statement. */
  'POSSESSION_STATEMENT_MISMATCH',
  /** The verdict ran under a profile the server did not select. */
  'POSSESSION_PROFILE_MISMATCH',
  /** The new key did not prove possession. */
  'POSSESSION_NOT_PROVEN',
  /** The CURRENT key's continuity proof is absent, or covers another request. */
  'CONTINUITY_PROOF_MISBOUND',
  /** The current key did not prove continuity. */
  'CONTINUITY_NOT_PROVEN',
  /** The new key has not passed runtime P-256 import and curve validation (D24-05). */
  'NEW_KEY_NOT_RUNTIME_VALID',
  /** The registry moved between challenge and commit. Never rotate from whatever is current now. */
  'STALE_ROTATION',
  /** The replay fact handed in is about some other ceremony, or is internally inconsistent. */
  'ROTATION_CONSUMPTION_MISBOUND',
  /** The replay fact is not a shape the store may report. */
  'ROTATION_CONSUMPTION_INCONSISTENT',
  /** This one-shot identity was already spent on different bytes. */
  'ROTATION_REUSED_WITH_CHANGED_SEMANTICS',
  /** An instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
]);
export type DeviceKeyRotationRefusal = z.infer<typeof DeviceKeyRotationRefusalSchema>;

/**
 * The CURRENT registry facts, re-read inside the commit transaction.
 *
 * This is the STALE_ROTATION defence. A rotation ceremony has a human-visible
 * duration, and the registry can move inside it — another rotation can land, a
 * key can be revoked, a device can be quarantined. Every one of those makes the
 * proposal stale, and the correct answer is to refuse, never to helpfully
 * rotate from whatever key happens to be current at commit time.
 */
export interface DeviceKeyRotationRegistryFacts {
  readonly organisation_id: string;
  readonly device_id: string;
  /** The key the registry holds as CURRENT right now. */
  readonly current_key_id: string;
  readonly current_key_version: number;
  readonly current_key_status: DeviceKeyLifecycleState;
  /** Key-level withdrawal, asked independently of the device's (C15-R4-final). */
  readonly current_key_revoked: boolean;
  /** Device-level revocation or compromise, asked independently of the key's. */
  readonly device_revoked: boolean;
  /** The SERVER-selected profile for the proposed key. */
  readonly server_resolved_signature_profile: DeviceSignatureProfile;
}

export interface DeviceKeyRotationAdmissibilityInput {
  readonly request: DeviceKeyRotationRequest;
  readonly challenge: DeviceKeyRotationChallenge;
  /** The server's verdict on the NEW key's possession. `null` models "never checked". */
  readonly possessionVerification: DeviceKeyRotationPossessionVerificationResult | null;
  /**
   * The CURRENT key's continuity verdict: did a `DeviceRequestProof` with
   * purpose `DEVICE_KEY_ROTATION`, signed by the registered current key, verify
   * over a statement whose `payload_digest` equals this rotation request's
   * fingerprint? The digest travels separately so the binding is checked here
   * rather than assumed by the caller.
   */
  readonly continuity: {
    readonly verified: boolean;
    readonly purpose_payload_digest: string;
  } | null;
  /**
   * D24-05: has the runtime crypto provider imported and validated the new
   * public key as a P-256 point? Contracts perform structural checks only, so
   * an off-curve key parses everywhere in this file and must be stopped here.
   * There is no default: an evaluator that could be called without it would
   * admit a key nothing ever imported.
   */
  readonly newKeyRuntimeValid: boolean;
  /** The registry, re-read under lock at commit. */
  readonly registered: DeviceKeyRotationRegistryFacts;
  /** The store's report on this ceremony's one-shot identity. REQUIRED, undefaulted. */
  readonly consumption: DeviceNonceConsumption;
  /** The authoritative server clock at commit. */
  readonly now: string;
}

export type DeviceKeyRotationDecision =
  | {
      readonly decision: 'ROTATE';
      readonly rotation_request_fingerprint: string;
      readonly from_key_version: number;
      readonly to_key_version: number;
      /** D23-07: every context issued against the old version is now invalid. */
      readonly invalidates_contexts_at_or_below_key_version: number;
    }
  /** A byte-identical retry of one ceremony. Converge; NEVER rotate twice. */
  | { readonly decision: 'CONVERGE'; readonly rotation_request_fingerprint: string; readonly stored_outcome_ref: string }
  | { readonly decision: 'REFUSE'; readonly refusal: DeviceKeyRotationRefusal };

/**
 * D24-10A: the whole ceremony, judged in one place.
 *
 * Ordering is deliberate and mirrors the enrollment gate: the cheap structural
 * bindings first, the two cryptographic verdicts last. A ceremony that fails
 * for several reasons at once names the most FUNDAMENTAL one — a challenge
 * about a different device is not "an expired challenge", and reporting it as
 * one would send an operator looking at the wrong thing.
 *
 * Both proofs are required and neither substitutes for the other. Continuity
 * without possession registers a key nobody can show they hold — the upload
 * C14-02 refuses. Possession without continuity lets anyone holding a fresh
 * keypair replace a device's credential.
 */
export function evaluateDeviceKeyRotation(input: DeviceKeyRotationAdmissibilityInput): DeviceKeyRotationDecision {
  const { request, challenge, registered } = input;

  // 0. The server resolved the profile. The request merely records one, and it
  //    must be the server's — bound before anything is verified under either.
  const profileBinding = bindClaimedSignatureProfile(
    request.server_resolved_signature_profile,
    registered.server_resolved_signature_profile,
  );
  if (!profileBinding.bound) return { decision: 'REFUSE', refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' };

  const fingerprint = deviceKeyRotationRequestFingerprint(request);

  // 1. The request must be about the device the registry re-read.
  if (request.organisation_id !== registered.organisation_id || request.device_id !== registered.device_id) {
    return { decision: 'REFUSE', refusal: 'ROTATION_REQUEST_MISBOUND' };
  }

  // 2. The challenge must be about THIS request, this device and this exact
  //    proposal. An id names a row; the fingerprint names its contents.
  if (
    challenge.organisation_id !== request.organisation_id ||
    challenge.device_id !== request.device_id ||
    challenge.rotation_request_id !== request.rotation_request_id ||
    challenge.rotation_request_fingerprint !== fingerprint ||
    challenge.current_key_id !== request.current_key_id ||
    challenge.current_key_version !== request.current_key_version ||
    challenge.proposed_key_id !== request.proposed_key_id ||
    challenge.proposed_key_version !== request.proposed_key_version ||
    challenge.new_public_key_thumbprint !== request.new_public_key_thumbprint
  ) {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_MISBOUND' };
  }

  // 3. STALE_ROTATION: the registry as it is NOW, not as it was at issuance.
  //
  //    A rotation proposes to supersede one specific key. If that key is no
  //    longer the current one, is no longer CURRENT, or the credential has been
  //    withdrawn at either level, the proposal describes a world that has gone.
  //    Rotating anyway would silently retarget the ceremony at whatever is
  //    current now — which is precisely how a race becomes an authorisation.
  if (
    registered.current_key_id !== request.current_key_id ||
    registered.current_key_version !== request.current_key_version ||
    registered.current_key_status !== 'CURRENT' ||
    registered.current_key_revoked ||
    registered.device_revoked
  ) {
    return { decision: 'REFUSE', refusal: 'STALE_ROTATION' };
  }

  // 4. D24-05: the new key must have been imported by the runtime crypto
  //    provider. An off-curve point satisfies every schema above.
  if (!input.newKeyRuntimeValid) return { decision: 'REFUSE', refusal: 'NEW_KEY_NOT_RUNTIME_VALID' };

  // 5. The one-shot identity, checked for internal consistency before
  //    relevance, for the C15-R1 reason: the fact crosses an I/O boundary from
  //    the replay store, so its shape is a claim.
  const fact = input.consumption;
  if (!isConsistentDeviceNonceConsumption(fact)) {
    return { decision: 'REFUSE', refusal: 'ROTATION_CONSUMPTION_INCONSISTENT' };
  }
  const replayKey = deviceKeyRotationReplayKey({
    organisation_id: request.organisation_id,
    device_id: request.device_id,
    rotation_request_id: request.rotation_request_id,
    rotation_challenge_id: challenge.challenge_id,
    current_key_id: request.current_key_id,
    current_key_version: request.current_key_version,
    proposed_key_id: request.proposed_key_id,
    proposed_key_version: request.proposed_key_version,
    nonce: challenge.nonce,
  });
  if (fact.replay_key !== replayKey || fact.statement_fingerprint !== fingerprint) {
    return { decision: 'REFUSE', refusal: 'ROTATION_CONSUMPTION_MISBOUND' };
  }
  if (fact.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { decision: 'REFUSE', refusal: 'ROTATION_REUSED_WITH_CHANGED_SEMANTICS' };
  }

  // 6. Continuity: the CURRENT key authorised THIS EXACT proposal. The
  //    payload_digest binding is what stops a valid current-key proof being
  //    borrowed for a different replacement key.
  if (input.continuity === null || input.continuity.purpose_payload_digest !== fingerprint) {
    return { decision: 'REFUSE', refusal: 'CONTINUITY_PROOF_MISBOUND' };
  }
  if (!input.continuity.verified) return { decision: 'REFUSE', refusal: 'CONTINUITY_NOT_PROVEN' };

  // 7. Possession of the NEW key, as a bound server verdict.
  const verification = input.possessionVerification;
  if (verification === null) return { decision: 'REFUSE', refusal: 'POSSESSION_VERIFICATION_MISSING' };
  if (
    verification.organisation_id !== request.organisation_id ||
    verification.device_id !== request.device_id ||
    verification.rotation_request_id !== request.rotation_request_id ||
    verification.rotation_request_fingerprint !== fingerprint ||
    verification.rotation_challenge_id !== challenge.challenge_id ||
    verification.current_key_id !== request.current_key_id ||
    verification.current_key_version !== request.current_key_version ||
    verification.proposed_key_id !== request.proposed_key_id ||
    verification.proposed_key_version !== request.proposed_key_version ||
    verification.new_public_key_thumbprint !== request.new_public_key_thumbprint
  ) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_VERIFICATION_MISBOUND' };
  }
  const expectedStatementFingerprint = deviceKeyRotationPossessionStatementFingerprint({
    organisation_id: request.organisation_id,
    device_id: request.device_id,
    rotation_request_id: request.rotation_request_id,
    rotation_request_fingerprint: fingerprint,
    current_key_id: request.current_key_id,
    current_key_version: request.current_key_version,
    proposed_key_id: request.proposed_key_id,
    proposed_key_version: request.proposed_key_version,
    new_public_key_thumbprint: request.new_public_key_thumbprint,
    rotation_challenge_id: challenge.challenge_id,
    nonce: challenge.nonce,
    signature_profile: profileBinding.profile,
  });
  if (verification.canonical_statement_fingerprint !== expectedStatementFingerprint) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_STATEMENT_MISMATCH' };
  }
  if (verification.signature_profile !== profileBinding.profile) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_PROFILE_MISMATCH' };
  }

  // 8. Chronology, on the SERVER's instants. `answered_at` is read nowhere.
  const window = parseAuthoritativeInstants({
    now: input.now,
    verified: verification.verified_at,
    issued: challenge.issued_at,
    expires: challenge.expires_at,
  });
  if (window === null) return { decision: 'REFUSE', refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  if (window.verified < window.issued) return { decision: 'REFUSE', refusal: 'CHALLENGE_NOT_YET_ISSUED' };
  if (window.verified > window.now) return { decision: 'REFUSE', refusal: 'POSSESSION_VERIFIED_IN_FUTURE' };
  if (isExpiredAt(window.verified, window.expires)) return { decision: 'REFUSE', refusal: 'CHALLENGE_EXPIRED' };

  if (!verification.verified) return { decision: 'REFUSE', refusal: 'POSSESSION_NOT_PROVEN' };

  // 9. C15-R1: an exact retry converges. There is no path from EXACT_DUPLICATE
  //    to a second rotation, which would burn a key version for nothing and
  //    leave the device holding a credential the registry had already retired.
  if (fact.outcome === 'EXACT_DUPLICATE') {
    return { decision: 'CONVERGE', rotation_request_fingerprint: fingerprint, stored_outcome_ref: fact.stored_outcome_ref };
  }

  return {
    decision: 'ROTATE',
    rotation_request_fingerprint: fingerprint,
    from_key_version: request.current_key_version,
    to_key_version: request.proposed_key_version,
    invalidates_contexts_at_or_below_key_version: request.current_key_version,
  };
}
