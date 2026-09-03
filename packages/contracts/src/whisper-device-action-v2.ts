import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import { DEVICE_PURPOSE_PERMITTED_TRUST, deviceTrustPermitsPurpose, type AuthenticatedDeviceContext } from './device-context.js';
import {
  DeviceDigestSchema,
  DeviceKeyLifecycleStateSchema,
  DeviceKeyVersionSchema,
  DeviceNonceSchema,
  DeviceRevocationDispositionSchema,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  canonicalDeviceJson,
  deviceCanonicalDigest,
  deviceKeyStatePermitsNewOperations,
  isConsistentDeviceNonceConsumption,
  isExpiredAt,
  parseAuthoritativeInstants,
  type DeviceKeyLifecycleState,
  type DeviceNonceConsumption,
  type DeviceRevocationDisposition,
} from './device-identity.js';
import {
  DeviceSignatureProfileSchema,
  DeviceSignatureSchema,
  isApprovedDeviceSignatureProfile,
  type DeviceSignatureProfile,
} from './device-signature.js';
import { classifyWhisperRecognitionFreshness, type WhisperFreshnessOutcome } from './whisper.js';

/**
 * ===========================================================================
 * WP-27 — THE M3 DEVICE-ACTION STATEMENT, VERSIONED FORWARD FROM WHISPER v1.
 * ===========================================================================
 *
 * WHY A v2 EXISTS AT ALL, AND WHY v1 IS NOT TOUCHED
 * -------------------------------------------------
 * `whisper.ts` is FROZEN as Milestone 2 shipped it. It pins Ed25519
 * (`WHISPER_SIGNATURE_ALGORITHM`), its `signature_algorithm` field is a
 * `z.literal('Ed25519')`, and its verifier resolves an Ed25519 `KeyObject` from
 * a seam that deliberately resolves nothing. Every one of those decisions was
 * correct for M2 and none of them can be reinterpreted now: a TRUSTED device
 * must hold its private key in hardware-backed storage, and the mainstream
 * mobile keystores guarantee P-256, not Ed25519 (see `device-signature.ts`).
 *
 * So M3 VERSIONS FORWARD. There is no `Ed25519 | P256` union anywhere, no
 * algorithm negotiation, and no path by which a v1 statement can be judged by
 * this module or a v2 statement by v1's. The two are chosen by VERSION and
 * DOMAIN — `schema_version` is a literal on both sides and the domain tags
 * differ — so dispatch is a decision, never a probe.
 *
 * THE CLIENT NEVER NAMES THE ALGORITHM
 * ------------------------------------
 * `WhisperDeviceActionSubmissionV2Schema` has NO `signature_algorithm`, no
 * `signature_profile`, no `curve` and no `hash_algorithm` field, and it is
 * `.strict()`, so presenting one is a parse failure rather than a value some
 * later caller might read. That is C11-04's lesson taken one step further than
 * WP-23 took it: WP-23 kept a `claimed_signature_profile` and equality-bound it
 * to the registry's answer, which is sound but still leaves a client-supplied
 * field beside a verifier. Here the field does not exist. The profile is
 * resolved by the SERVER from the registry key record for
 * `organisation + device_id + key_id + key_version`, and the server's answer is
 * what the canonical statement binds.
 *
 * THE PROFILE, IN ONE PLACE
 * -------------------------
 * `WHISPER_DEVICE_ACTION_V2_PROFILE` names it and
 * `WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS` spells out what it means —
 * EC / secp256r1 (prime256v1) / ECDSA / SHA-256 / canonical IEEE P1363 `r||s`.
 * One declaration, so a reader and an implementer cannot be looking at two
 * different descriptions of the same bytes.
 *
 * WHY IEEE P1363 AND NOT DER. P1363 is a FIXED-LENGTH, SINGLE-REPRESENTATION
 * encoding: 32 bytes of `r` followed by 32 bytes of `s`, and
 * `decodeCanonicalP256Signature` additionally refuses any `s` above
 * `floor(n/2)`. DER admits several encodings of one signature — leading zeros,
 * length forms — so one signature could arrive as several distinct byte
 * strings, each with a different identity for anything that fingerprints,
 * de-duplicates or logs it, and high-S would give every signature a second
 * valid form. Malleability is therefore closed AT THE ENCODING, before a
 * verifier is reachable, rather than by asking a verifier to be strict.
 *
 * This is exactly what `StrongBoxKeyManager` emits — it signs DER and converts
 * through `CanonicalSignature.canonicalWireSignature` — and exactly what
 * `p256-key.importer.ts` verifies with `dsaEncoding: 'ieee-p1363'`. The three
 * agree because there is one definition, `DeviceSignatureSchema`, and all three
 * use it.
 *
 * A CLIENT ASSERTION IS NEVER STORED AS A SERVER-ESTABLISHED FACT
 * --------------------------------------------------------------
 * There is deliberately NO serialized gateway context inside the signed bytes.
 * The device signs CLAIMS it can know — its own tenant, site, operative,
 * hardware, key, signal, action and freshness material. The server
 * INDEPENDENTLY establishes `AuthenticatedDeviceContext` from its own persisted
 * state and then COMPARES, failing closed on any disagreement
 * (`evaluateWhisperDeviceActionV2Admissibility`, step 2).
 *
 * Embedding a serialized context in the preimage would invert that. The bytes
 * would then contain an authority-shaped object that ARRIVED WITH THE REQUEST,
 * and a signature over it proves only that the device is willing to say it —
 * which is precisely the W21-05 / C10-02 hole, restated in a place where it
 * would look like cryptography. Worse, such an object is the natural thing for
 * a later reader to persist or log "because it was signed", at which point a
 * device's assertion about its own trust, scope or key has become a stored
 * fact. The signature authenticates the CLAIMS; the server owns the FACTS; the
 * comparison is where the two meet, and it is the only place they meet.
 */

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

// ---------------------------------------------------------------------------
// Domains and the profile
// ---------------------------------------------------------------------------

/**
 * Domain separator, DISTINCT from v1's `sentinel.whisper.device-action.v1` and
 * from `sentinel.device.request-proof.v1`.
 *
 * A signature minted for one purpose must never verify as another, and a shared
 * tag makes that possible the moment two statements happen to share a shape.
 * The version is IN the tag, so a v1 preimage and a v2 preimage cannot collide
 * even if every other field were identical.
 */
export const WHISPER_DEVICE_ACTION_V2_DOMAIN = 'sentinel.whisper.device-action.v2';

/** The replay identity carries its own domain, for the reason C11-01 gives. */
export const WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN = 'sentinel.whisper.replay-identity.v2';

/**
 * The ONE profile v2 admits, and the only one the registry may resolve for a
 * device-action key. It is `satisfies DeviceSignatureProfile` rather than a
 * fresh string so that the allowlist in `device-signature.ts` stays the single
 * authority over which profiles exist at all.
 */
export const WHISPER_DEVICE_ACTION_V2_PROFILE = 'P256_ECDSA_SHA256' as const satisfies DeviceSignatureProfile;

/**
 * WHAT THE PROFILE MEANS, EXPORTED FROM ONE PLACE.
 *
 * A profile string is a name; these are the decisions it names. They live here,
 * as data, so a client implementer, a verifier and a reviewer read the SAME
 * description — and so that "which curve?" or "which digest?" is never answered
 * by reading a verifier's arguments and inferring.
 *
 * `signature_encoding` is the load-bearing one, and `encoding_rationale` says
 * why: P1363 is canonical and low-S normalised, so signature malleability is
 * closed at the encoding rather than deferred to a verifier's strictness.
 */
export const WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS = {
  profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
  key_type: 'EC',
  curve: 'secp256r1',
  /** OpenSSL's name for the same curve, as `p256-key.importer.ts` asserts it. */
  curve_openssl_name: 'prime256v1',
  signature_algorithm: 'ECDSA',
  digest_algorithm: 'SHA-256',
  signature_encoding: 'IEEE-P1363',
  signature_encoding_detail: 'raw r||s, 32 bytes each, low-S, canonical unpadded base64url',
  public_key_encoding: 'SEC1-UNCOMPRESSED',
  public_key_encoding_detail: '0x04 || X(32) || Y(32), canonical unpadded base64url',
  encoding_rationale:
    'IEEE P1363 rather than DER: DER admits several encodings of one signature, so one signature would have several byte identities for anything that fingerprints, de-duplicates or logs it. P1363 is fixed-length and single-representation, and DeviceSignatureSchema additionally refuses high-S — so malleability is closed AT THE ENCODING, before any verifier is reachable.',
} as const;

/**
 * The purpose a v2 statement is minted under, quoted from the frozen
 * `DeviceRequestPurpose` vocabulary rather than invented here.
 *
 * `DEVICE_PURPOSE_PERMITTED_TRUST.WHISPER_DEVICE_ACTION` is `['TRUSTED']` — that
 * is W21-05, and this module reads that table rather than restating it.
 */
export const WHISPER_DEVICE_ACTION_V2_PURPOSE = 'WHISPER_DEVICE_ACTION' as const;

/** The trust states that may fire a v2 device action. Read, never redefined. */
export const WHISPER_DEVICE_ACTION_V2_PERMITTED_TRUST: readonly DeviceTrust[] =
  DEVICE_PURPOSE_PERMITTED_TRUST[WHISPER_DEVICE_ACTION_V2_PURPOSE];

// ---------------------------------------------------------------------------
// The submission
// ---------------------------------------------------------------------------

/**
 * The SERVER-RESOLVED identity half of a submission.
 *
 * Every field here is established by the platform — the persisted context's own
 * columns — and is handed to the statement builder, never read from a body. It
 * is separated from the claims below for exactly the reason
 * `device-gateway.envelope.ts` separates envelope identity from semantic
 * payload: a transport that let a caller propose one of these would be a
 * transport through which a device could name whose action it is signing.
 *
 * `context_id` is here because it is the SERVER-ISSUED half of the freshness
 * material. A context is minted by a ceremony that required a live human
 * session AND a hardware signature, it carries a hard lifetime ceiling
 * (`DEVICE_CONTEXT_MAX_LIFETIME_MS`), and no device can mint one — so a
 * statement bound to a context id cannot be pre-computed for a context the
 * server never issued, and cannot outlive that context.
 */
const whisperDeviceActionV2IdentityShape = {
  context_id: scopedId,
  organisation_id: scopedId,
  site_id: scopedId,
  actor_user_id: scopedId,
  device_id: scopedId,
} as const;

/**
 * The CLAIM half — what a device actually sends.
 *
 * NOTE WHAT IS ABSENT, AND THAT IT IS ABSENT BY CONSTRUCTION RATHER THAN BY
 * VALIDATION: `signature_algorithm`, `signature_profile`, `curve`,
 * `hash_algorithm`, any public key, any trust word, any protocol reference and
 * any serialized context. `.strict()` makes each of them a parse failure.
 *
 *  - the ALGORITHM is the registry's answer for the resolved key (C11-04);
 *  - a PUBLIC KEY travelling with the claim it authenticates authenticates
 *    nothing (W21-05);
 *  - `device_trust` is the platform's judgement, never the device's (D23-05);
 *  - the RESPONSE PROTOCOL is resolved downstream from the stored signal
 *    version — a device that could sign its own consequence would choose it
 *    (W21-10).
 */
const whisperDeviceActionV2ClaimsShape = {
  /**
   * The version discriminant. A literal, and the reason dispatch is
   * deterministic: a v1 result (`schema_version: 1`) cannot parse here and a v2
   * submission cannot parse as a v1 result.
   */
  schema_version: z.literal(2),
  /**
   * The registry identity of the key the SERVER must verify against. It is a
   * POINTER, not a key: naming a key id grants nothing, and the server resolves
   * the actual public key from its own registry by
   * `organisation + device_id + key_id + key_version`.
   */
  key_id: scopedId,
  key_version: DeviceKeyVersionSchema,
  whisper_signal_id: scopedId,
  whisper_signal_version: z.number().int().positive(),
  /** Pinned, as v1 pins it: DEVICE_ACTION is the only modality M3 admits. */
  modality: z.literal('DEVICE_ACTION'),
  /** W21-06: WHICH action the device witnessed, not merely that one occurred. */
  device_action_id: z.string().min(1).max(256),
  /** The device's claimed recognition instant. Judged against the SERVER clock. */
  recognised_at: timestamp,
  /**
   * C11-04: SIGNED, because it can flip a decision.
   *
   * The downstream gate compares this against a stored `minimum_confidence`, so
   * an unsigned figure raised in flight could cross the threshold and turn a
   * refusal into an acceptance. It remains EVIDENCE — it never authorises on
   * its own and can only ever narrow what is permitted — but its value is fixed
   * by the device that produced it.
   */
  confidence: z.number().min(0).max(1),
  /** The one-shot half of the freshness material. See the identity shape. */
  anti_replay_nonce: DeviceNonceSchema,
  /**
   * The branded canonical form. The schema itself runs the full decode, so a
   * high-S, zero-scalar, wrong-length, DER or non-canonical value cannot exist
   * inside a parsed submission — the whole structure fails to parse (C15-01).
   */
  signature: DeviceSignatureSchema,
} as const;

/**
 * What the CLIENT sends: the claims, and nothing that names an identity the
 * server owns or an algorithm the registry chooses.
 */
export const WhisperDeviceActionV2ClaimsSchema = z.object(whisperDeviceActionV2ClaimsShape).strict();
export type WhisperDeviceActionV2Claims = z.infer<typeof WhisperDeviceActionV2ClaimsSchema>;

/**
 * The whole submission — server-resolved identity plus the device's claims.
 *
 * It is assembled by the server from its own state and the parsed claims; there
 * is no transport that parses this shape directly off a body, which is what
 * makes the identity fields unproposable.
 */
export const WhisperDeviceActionSubmissionV2Schema = z
  .object({ ...whisperDeviceActionV2IdentityShape, ...whisperDeviceActionV2ClaimsShape })
  .strict();
export type WhisperDeviceActionSubmissionV2 = z.infer<typeof WhisperDeviceActionSubmissionV2Schema>;

/** The server-resolved identity, as a value. */
export type WhisperDeviceActionV2Identity = Pick<
  WhisperDeviceActionSubmissionV2,
  'context_id' | 'organisation_id' | 'site_id' | 'actor_user_id' | 'device_id'
>;

/**
 * Assembles a submission from the identity the SERVER established and the
 * claims the device sent.
 *
 * Every field is listed rather than spread, for the reason
 * `deviceRequestProofStatementInput` lists its own: what gets signed and
 * compared must be legible in one place, and a field added to the claims must
 * not slip into an identity position without somebody deciding it should.
 */
export function whisperDeviceActionV2Submission(
  identity: WhisperDeviceActionV2Identity,
  claims: WhisperDeviceActionV2Claims,
): WhisperDeviceActionSubmissionV2 {
  return {
    context_id: identity.context_id,
    organisation_id: identity.organisation_id,
    site_id: identity.site_id,
    actor_user_id: identity.actor_user_id,
    device_id: identity.device_id,
    schema_version: claims.schema_version,
    key_id: claims.key_id,
    key_version: claims.key_version,
    whisper_signal_id: claims.whisper_signal_id,
    whisper_signal_version: claims.whisper_signal_version,
    modality: claims.modality,
    device_action_id: claims.device_action_id,
    recognised_at: claims.recognised_at,
    confidence: claims.confidence,
    anti_replay_nonce: claims.anti_replay_nonce,
    signature: claims.signature,
  };
}

// ---------------------------------------------------------------------------
// The canonical signed statement
// ---------------------------------------------------------------------------

/**
 * C15-01, applied where there is no client claim to bind: the statement input
 * is the submission MINUS its signature, PLUS the profile the SERVER resolved.
 *
 * The type makes the substitution mandatory — a `WhisperDeviceActionSubmissionV2`
 * is not assignable here — so no caller can sign or fingerprint bytes whose
 * profile came from anywhere but the registry.
 */
export type WhisperDeviceActionV2StatementInput = Omit<WhisperDeviceActionSubmissionV2, 'signature'> & {
  /** SERVER-selected, from the registry key record. There is no client field for it. */
  readonly signature_profile: DeviceSignatureProfile;
};

export function whisperDeviceActionV2StatementInput(
  submission: WhisperDeviceActionSubmissionV2,
  serverResolvedProfile: DeviceSignatureProfile,
): WhisperDeviceActionV2StatementInput {
  return {
    context_id: submission.context_id,
    organisation_id: submission.organisation_id,
    site_id: submission.site_id,
    actor_user_id: submission.actor_user_id,
    device_id: submission.device_id,
    schema_version: submission.schema_version,
    key_id: submission.key_id,
    key_version: submission.key_version,
    whisper_signal_id: submission.whisper_signal_id,
    whisper_signal_version: submission.whisper_signal_version,
    modality: submission.modality,
    device_action_id: submission.device_action_id,
    recognised_at: submission.recognised_at,
    confidence: submission.confidence,
    anti_replay_nonce: submission.anti_replay_nonce,
    signature_profile: serverResolvedProfile,
  };
}

/**
 * EXACTLY what the device signs.
 *
 * Domain-tagged canonical JSON through `canonicalDeviceJson`, which sorts keys
 * recursively and REFUSES anything not losslessly representable. Not a
 * delimiter-joined string: every value here is a caller-supplied string that may
 * contain the delimiter, so `"a\nb" + "c"` and `"a" + "b\nc"` would otherwise
 * produce identical bytes and one signature would verify for two identities.
 *
 * WHAT IS BOUND, AND WHY EACH ONE
 * -------------------------------
 *   domain, schema_version        this purpose, this version, and no other
 *   context_id                    the SERVER-ISSUED ceremony this belongs to
 *   organisation_id, site_id      the tenant and the place
 *   actor_user_id                 the operative, so a statement is not portable
 *                                 between two people authorised on one signal
 *   device_id                     the hardware
 *   key_id, key_version           the exact credential; a rotation is a
 *                                 different statement, not a signature that
 *                                 happens to fail
 *   whisper_signal_id + version   the exact configuration identity (W21-02)
 *   modality, device_action_id    the ACTION MEANING (W21-06)
 *   recognised_at                 freshness, judged against the server clock
 *   anti_replay_nonce             the one-shot identity
 *   confidence                    C11-04; see the field's own note
 *   signature_profile             the SERVER's answer, so the statement means
 *                                 "signed under the profile the platform chose"
 *
 * `signature` is excluded for the obvious reason: it is the output.
 */
function whisperDeviceActionV2StatementObject(input: WhisperDeviceActionV2StatementInput): Record<string, unknown> {
  return {
    domain: WHISPER_DEVICE_ACTION_V2_DOMAIN,
    schema_version: input.schema_version,
    context_id: input.context_id,
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    actor_user_id: input.actor_user_id,
    device_id: input.device_id,
    key_id: input.key_id,
    key_version: input.key_version,
    whisper_signal_id: input.whisper_signal_id,
    whisper_signal_version: input.whisper_signal_version,
    modality: input.modality,
    device_action_id: input.device_action_id,
    recognised_at: input.recognised_at,
    confidence: input.confidence,
    anti_replay_nonce: input.anti_replay_nonce,
    signature_profile: input.signature_profile,
  };
}

export function canonicalWhisperDeviceActionV2Statement(input: WhisperDeviceActionV2StatementInput): string {
  return canonicalDeviceJson(whisperDeviceActionV2StatementObject(input));
}

/**
 * SHA-256 over the canonical statement — the digest an audit row may carry and
 * the value the replay store COMPARES (never keys on).
 *
 * Both this and the statement builder read from ONE object literal, so the
 * signed bytes and the fingerprinted bytes cannot drift apart in a future edit
 * — a drift that would let a signature cover something the fingerprint does not.
 */
export function whisperDeviceActionV2Fingerprint(input: WhisperDeviceActionV2StatementInput): string {
  return deviceCanonicalDigest(whisperDeviceActionV2StatementObject(input));
}

// ---------------------------------------------------------------------------
// Replay identity
// ---------------------------------------------------------------------------

export interface WhisperDeviceActionV2ReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly whisper_signal_id: string;
  readonly whisper_signal_version: number;
  readonly anti_replay_nonce: string;
}

/**
 * THE ACTION'S SEMANTIC IDENTITY — AND THE SIGNATURE IS NOT PART OF IT.
 *
 * This is the whole ruling, and it is a property of ECDSA rather than a
 * preference. ECDSA is RANDOMISED: the same key over the same bytes produces a
 * different `(r, s)` on every invocation, and every one of them verifies. If
 * the signature were in the replay identity, a captured statement re-signed by
 * a compromised-but-still-registered device — or simply re-emitted by a client
 * that signs twice — would present a DIFFERENT identity, find no stored row,
 * and execute a second time. The one-shot protection would be defeated by the
 * cheapest possible operation.
 *
 * So the identity is derived from what the action MEANS: tenant, site,
 * operative, hardware, key version, signal family, signal version and the
 * one-shot nonce. Two presentations of the same action collide on the same slot
 * whatever their signatures are, and the store's compared-not-keyed statement
 * fingerprint then separates an exact retry (converge) from a reuse under
 * changed semantics (conflict).
 *
 * WHAT ELSE IS DELIBERATELY OUT.
 *
 *  - `context_id`: it is server-issued and it IS bound into the signed bytes,
 *    but a new context must not open a fresh replay slot for an action already
 *    spent. Keying on it would make "establish a second context" a replay.
 *  - `device_action_id`: leaving it out is the STRICTER choice. Including it
 *    would let one nonce be spent once per action; excluding it means a nonce
 *    re-presented with a different action lands on the SAME slot with a
 *    different fingerprint and is refused as changed semantics.
 *  - `recognised_at` and `confidence`: same reason — they are covered by the
 *    fingerprint, and putting them in the identity would let a one-millisecond
 *    edit mint a fresh slot.
 *
 * The ACTOR is in it for W21-09's reason: one device is legitimately used by
 * several people across shifts, so a nonce consumed by one operative must not
 * consume another's slot. `key_version` is in it because a rotation is a new
 * credential and a slot spent under the old key says nothing about the new one.
 *
 * Structure first, exactly as `deviceRequestProofReplayIdentity` and
 * `deviceActionWhisperReplayIdentity` are: persistence MUST enforce uniqueness
 * over these named fields, because a hash cannot be queried, audited or reasoned
 * about.
 */
export function whisperDeviceActionV2ReplayIdentity(input: {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly key_version: number;
  readonly whisper_signal_id: string;
  readonly whisper_signal_version: number;
  readonly anti_replay_nonce: string;
}): WhisperDeviceActionV2ReplayIdentity {
  return {
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    actor_user_id: input.actor_user_id,
    device_id: input.device_id,
    key_version: input.key_version,
    whisper_signal_id: input.whisper_signal_id,
    whisper_signal_version: input.whisper_signal_version,
    anti_replay_nonce: input.anti_replay_nonce,
  };
}

/**
 * C11-01: canonical JSON, never a delimiter join — mirroring
 * `deviceRequestProofReplayKey` field for field.
 */
export function whisperDeviceActionV2ReplayKey(input: Parameters<typeof whisperDeviceActionV2ReplayIdentity>[0]): string {
  return canonicalDeviceJson({
    domain: WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN,
    ...whisperDeviceActionV2ReplayIdentity(input),
  });
}

// ---------------------------------------------------------------------------
// Admissibility
// ---------------------------------------------------------------------------

/**
 * Every way a v2 statement can be refused.
 *
 * These are INTERNAL audit granularity. A device-facing surface must collapse
 * them into one answer for the reason `DeviceSignatureRejection` and D25-13 both
 * give: telling a caller which check refused it is a free oracle over the
 * registry, the roster and the tenant.
 */
export const WhisperDeviceActionV2RefusalSchema = z.enum([
  /** The submission did not satisfy `WhisperDeviceActionSubmissionV2Schema`. */
  'SUBMISSION_MALFORMED',
  'CONTEXT_NOT_YET_VALID',
  'CONTEXT_EXPIRED',
  'CONTEXT_IDENTITY_MISMATCH',
  'CONTEXT_ORGANISATION_MISMATCH',
  'CONTEXT_ACTOR_MISMATCH',
  'CONTEXT_DEVICE_MISMATCH',
  'CONTEXT_SITE_NOT_AUTHORISED',
  'CONTEXT_KEY_MISMATCH',
  /** The registry record handed in is about another organisation or device. */
  'REGISTRY_IDENTITY_MISMATCH',
  /** No registry key record resolved for this (organisation, device, key id). */
  'REGISTRY_KEY_UNRESOLVABLE',
  /** The registry's profile for this key is not `P256_ECDSA_SHA256`. */
  'SIGNATURE_PROFILE_NOT_SUPPORTED',
  /** D23-09: the registry has moved on to a newer key version. */
  'KEY_VERSION_ROTATED',
  /** The key's lifecycle state does not authorise NEW operations. */
  'KEY_STATE_NOT_OPERATIONAL',
  /** C15-R4-final: DEVICE-level withdrawal, asked on its own. */
  'DEVICE_REVOKED',
  /** C15-R4-final: KEY-level withdrawal, asked on its own. */
  'KEY_REVOKED',
  /** W21-05: current trust does not admit WHISPER_DEVICE_ACTION. */
  'DEVICE_TRUST_NOT_PERMITTED',
  'RECOGNITION_STALE',
  'RECOGNITION_FUTURE_SKEW',
  'SIGNATURE_INVALID',
  /** Same one-shot identity, different signed semantics. */
  'REPLAY_IDENTITY_REUSED',
  /**
   * Same one-shot identity, the SAME signed semantics — already spent.
   *
   * This is a REFUSAL and not a convergence, and the asymmetry with
   * `evaluateDeviceRequestProof` (which converges on an exact duplicate) is
   * deliberate. See the note on the evaluator.
   */
  'REPLAY_IDENTITY_ALREADY_SPENT',
  /** The consumption fact handed in is about some other statement. */
  'NONCE_CONSUMPTION_MISBOUND',
  /** C15-R1: the store's fact is not a shape this contract can act on. */
  'NONCE_CONSUMPTION_INCONSISTENT',
  /** C15-07: an instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
]);
export type WhisperDeviceActionV2Refusal = z.infer<typeof WhisperDeviceActionV2RefusalSchema>;

/**
 * The CURRENT registry record for the device and the key the statement names,
 * read at use.
 *
 * C15-R4-final / D24-09: `device_revoked` and `key_revoked` are TWO FIELDS, not
 * one. The device row and the key row move at different times by different
 * paths — `STOLEN` withdraws the credential at the device level while the key
 * row may still say `CURRENT` for an instant, a leaked key is withdrawn on its
 * own with the device row untouched — so no caller may assume both moved
 * together, and each is asked independently below.
 */
export interface WhisperDeviceActionV2RegistryFacts {
  readonly organisation_id: string;
  readonly device_id: string;
  readonly key_id: string;
  readonly key_version: number;
  /** The SERVER-selected profile. There is no client claim to bind it against. */
  readonly signature_profile: DeviceSignatureProfile;
  readonly key_state: DeviceKeyLifecycleState;
  /** DEVICE-level withdrawal, asked on its own. */
  readonly device_revoked: boolean;
  /** KEY-level withdrawal, asked on its own. */
  readonly key_revoked: boolean;
  readonly revocation_disposition: DeviceRevocationDisposition | null;
  /** The platform's CURRENT effective judgement (D23-05), never a snapshot. */
  readonly trust: DeviceTrust;
}

export interface WhisperDeviceActionV2AdmissibilityInput {
  /** The SERVER-established context. Compared against, never taken from a body. */
  readonly context: AuthenticatedDeviceContext;
  readonly submission: WhisperDeviceActionSubmissionV2;
  /** The authoritative server clock at receipt. */
  readonly now: string;
  readonly registered: WhisperDeviceActionV2RegistryFacts;
  /**
   * The caller's cryptographic check: did this signature verify against the
   * REGISTERED public key over `canonicalWhisperDeviceActionV2Statement`?
   *
   * It is an explicit input so a test can hold every other fact valid and set it
   * to `false` — the captured-statement case, which must refuse.
   */
  readonly verified: boolean;
  /**
   * The store's report on this statement's one-shot identity. REQUIRED, with no
   * default: an evaluator that can decide without knowing whether the nonce was
   * already spent is an evaluator that admits replays.
   */
  readonly consumption: DeviceNonceConsumption;
}

/**
 * THERE IS NO CONVERGENCE ARM, AND THAT IS THE RULING.
 *
 * `evaluateDeviceRequestProof` has one, correctly: a byte-identical TRANSPORT
 * retry is the lost-response case, and C17-03 is explicit that answering it
 * `NOT_USABLE` is Sentinel lying about a ceremony that succeeded. That case is
 * ALREADY handled, one layer up and before this gate is ever reached — the
 * gateway's own request-proof identity converges and the domain effect is never
 * re-entered.
 *
 * So an exact duplicate REACHING THIS GATE means something different: the same
 * action, presented under a DIFFERENT transport proof with a different one-shot
 * transport nonce. That is not a lost response — a lost response is re-sent
 * verbatim — it is a REPLAY of a spent action, and on a duress channel
 * answering it with a success is two bad things at once: a durable oracle
 * confirming that a captured statement is genuine, and a report of an effect
 * that this request did not cause.
 *
 * Refusing costs an honest client a retry it can make correctly (by re-sending
 * the identical proof). Converging costs the platform a success response for an
 * action nobody performed.
 */
export type WhisperDeviceActionV2Decision =
  | { readonly admissible: true; readonly effect: 'PROCEED'; readonly fingerprint: string; readonly replay_key: string }
  | { readonly admissible: false; readonly refusal: WhisperDeviceActionV2Refusal };

/**
 * THE ORDERED GATE, EXPRESSED ONCE.
 *
 * The ordering mirrors `evaluateDeviceRequestProof` deliberately: the cheap,
 * non-cryptographic checks first, POSSESSION LAST, so the case that matters —
 * every field perfect, presented by somebody who does not hold the hardware key
 * — reaches the end and refuses with `SIGNATURE_INVALID` rather than being
 * deflected by an unrelated check.
 *
 * WHAT THIS DOES NOT DECIDE. It does not resolve a Whisper signal, does not
 * consult a roster, a confidence threshold, a context requirement or a response
 * protocol, and it never enters a response path. Those belong to the frozen v1
 * runtime gate (`evaluateWhisperRuntimeEligibility`) and are deliberately not
 * restated here — a second decision tree is a second thing to keep faithful.
 * A `PROCEED` from this function means the STATEMENT IS AUTHENTIC, FRESH, BOUND
 * AND UNSPENT, and it means nothing else.
 */
export function evaluateWhisperDeviceActionV2Admissibility(
  input: WhisperDeviceActionV2AdmissibilityInput,
): WhisperDeviceActionV2Decision {
  const { context, submission, registered } = input;

  // 0. C15-07: every instant, parsed once, fail-closed. An unreadable clock
  //    used to make every comparison below silently answer "fine".
  const instants = parseAuthoritativeInstants({
    now: input.now,
    contextIssued: context.issued_at,
    contextExpires: context.expires_at,
    recognisedAt: submission.recognised_at,
  });
  if (instants === null) return { admissible: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  const nowMs = instants.now;

  // 1. The server-issued context must be live. Expiry is exclusive.
  if (nowMs < instants.contextIssued) return { admissible: false, refusal: 'CONTEXT_NOT_YET_VALID' };
  if (isExpiredAt(nowMs, instants.contextExpires)) return { admissible: false, refusal: 'CONTEXT_EXPIRED' };

  // 2. THE COMPARISON. The device SIGNED these claims; the server ESTABLISHED
  //    the context independently. Every disagreement is a refusal, and the
  //    signature does not soften one — a correctly signed claim about somebody
  //    else's tenant, operative, device or context is a correctly signed lie.
  if (submission.organisation_id !== context.organisation_id) return { admissible: false, refusal: 'CONTEXT_ORGANISATION_MISMATCH' };
  if (submission.actor_user_id !== context.actor_user_id) return { admissible: false, refusal: 'CONTEXT_ACTOR_MISMATCH' };
  if (submission.device_id !== context.device_id) return { admissible: false, refusal: 'CONTEXT_DEVICE_MISMATCH' };
  if (submission.context_id !== context.context_id) return { admissible: false, refusal: 'CONTEXT_IDENTITY_MISMATCH' };
  if (!context.authorised_site_ids.includes(submission.site_id)) return { admissible: false, refusal: 'CONTEXT_SITE_NOT_AUTHORISED' };
  if (submission.key_id !== context.key_id || submission.key_version !== context.key_version) {
    return { admissible: false, refusal: 'CONTEXT_KEY_MISMATCH' };
  }

  // 3. The registry, read at use. A record about another device or another
  //    tenant is not evidence concerning this statement at all.
  if (registered.organisation_id !== context.organisation_id || registered.device_id !== context.device_id) {
    return { admissible: false, refusal: 'REGISTRY_IDENTITY_MISMATCH' };
  }
  if (registered.key_id !== submission.key_id) return { admissible: false, refusal: 'CONTEXT_KEY_MISMATCH' };
  // D23-09: a rotation invalidates every statement bound to the old version.
  if (registered.key_version !== submission.key_version) return { admissible: false, refusal: 'KEY_VERSION_ROTATED' };

  // 4. C15-R4-final: the two withdrawals, asked INDEPENDENTLY. Either one alone
  //    is sufficient to refuse, and neither is inferred from the other.
  if (registered.device_revoked) return { admissible: false, refusal: 'DEVICE_REVOKED' };
  if (registered.key_revoked) return { admissible: false, refusal: 'KEY_REVOKED' };
  if (!deviceKeyStatePermitsNewOperations(registered.key_state)) {
    return { admissible: false, refusal: 'KEY_STATE_NOT_OPERATIONAL' };
  }

  // 5. THE PROFILE IS THE REGISTRY'S. There is no client field to bind it
  //    against, so this is not an equality check — it is a support check, and
  //    an unsupported profile REFUSES rather than falling back to anything.
  if (!isApprovedDeviceSignatureProfile(registered.signature_profile)) {
    return { admissible: false, refusal: 'SIGNATURE_PROFILE_NOT_SUPPORTED' };
  }
  if (registered.signature_profile !== WHISPER_DEVICE_ACTION_V2_PROFILE) {
    return { admissible: false, refusal: 'SIGNATURE_PROFILE_NOT_SUPPORTED' };
  }

  // 6. W21-05, through the frozen purpose table: TRUSTED only.
  if (!deviceTrustPermitsPurpose(registered.trust, WHISPER_DEVICE_ACTION_V2_PURPOSE)) {
    return { admissible: false, refusal: 'DEVICE_TRUST_NOT_PERMITTED' };
  }

  // 7. Freshness, judged against the AUTHORITATIVE server clock in both
  //    directions, under the FROZEN v1 bounds. There is deliberately no second
  //    freshness opinion here: a device under-reporting its age must not extend
  //    the window, and one claiming to sign from the future must not either.
  const freshness = classifyWhisperDeviceActionV2Freshness(new Date(instants.recognisedAt), new Date(nowMs));
  if (freshness === 'FUTURE_SKEW') return { admissible: false, refusal: 'RECOGNITION_FUTURE_SKEW' };
  if (freshness === 'STALE') return { admissible: false, refusal: 'RECOGNITION_STALE' };

  const fingerprint = whisperDeviceActionV2Fingerprint(
    whisperDeviceActionV2StatementInput(submission, registered.signature_profile),
  );
  const replayKey = whisperDeviceActionV2ReplayKey(submission);

  // 8. The one-shot identity. C15-R1: CONSISTENCY BEFORE RELEVANCE — the fact
  //    crossed an I/O boundary, so its shape is a claim, and an EXACT_DUPLICATE
  //    naming no stored outcome must not fall through to PROCEED.
  const fact = input.consumption;
  if (!isConsistentDeviceNonceConsumption(fact)) {
    return { admissible: false, refusal: 'NONCE_CONSUMPTION_INCONSISTENT' };
  }
  if (fact.replay_key !== replayKey || fact.statement_fingerprint !== fingerprint) {
    return { admissible: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' };
  }
  if (fact.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { admissible: false, refusal: 'REPLAY_IDENTITY_REUSED' };
  }

  // 9. And finally: possession of the registered private key. It is checked
  //    BEFORE the spent-identity refusal below so that a caller who does not
  //    hold the key learns nothing about which identities are already spent —
  //    the ordering is the oracle argument, not an accident.
  if (!input.verified) return { admissible: false, refusal: 'SIGNATURE_INVALID' };

  // No fall-through. PROCEED is reachable ONLY from FIRST_SEEN, the one outcome
  // that means nothing has happened under this identity yet.
  if (fact.outcome === 'EXACT_DUPLICATE') {
    return { admissible: false, refusal: 'REPLAY_IDENTITY_ALREADY_SPENT' };
  }
  return { admissible: true, effect: 'PROCEED', fingerprint, replay_key: replayKey };
}

/**
 * Freshness under the FROZEN v1 bounds.
 *
 * It delegates to `classifyWhisperRecognitionFreshness` rather than restating
 * `MAX_WHISPER_RECOGNITION_AGE_MS` and `MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS`.
 * A second copy of a timing ceiling is a second freshness opinion, and the
 * cheapest way to acquire one is to copy a number "for readability" and then
 * edit the copy. The argument for the two-minute window is unchanged by the
 * change of signature algorithm: a duress signal captured long ago is more
 * likely a replayed artefact than a live emergency.
 */
export function classifyWhisperDeviceActionV2Freshness(recognisedAt: Date, receivedAt: Date): WhisperFreshnessOutcome {
  return classifyWhisperRecognitionFreshness(recognisedAt, receivedAt);
}

// ---------------------------------------------------------------------------
// The server-owned verification result
// ---------------------------------------------------------------------------

/**
 * WHAT THE SERVER CONCLUDED — A VALUE, NOT A BOOLEAN.
 *
 * `DevicePossessionVerificationResult`'s discipline, applied here: a bare
 * `true` is a verdict about nothing. Handed onward it says only "some check
 * somewhere succeeded", so a genuine verdict produced for another statement,
 * another operative, another device or an older key version could be presented
 * beside facts it never ran against. Every field below was established by the
 * server during the evaluation, so the result CARRIES WHAT IT IS ABOUT and a
 * borrowed verdict is a visible mismatch rather than an invisible one.
 *
 * `source` is a literal for the same reason WP-23 makes it one: a verification
 * result that did not come from Sentinel's own verifier is not a verification
 * result, and there is no other value this field can take.
 *
 * WHAT `VERIFIED_STATEMENT` MEANS, PRECISELY. The statement is authentic under
 * the registered key, bound to the server-established context, fresh, and its
 * one-shot identity has been spent. IT IS NOT AN ELIGIBILITY VERDICT: no signal
 * was resolved, no roster consulted, no threshold compared, no context
 * requirement evaluated and no response protocol entered. Reading it as
 * "a recognition was accepted" would be reading it as something it does not say.
 */
export const WhisperDeviceActionV2VerificationOutcomeSchema = z.enum([
  'VERIFIED_STATEMENT',
  /** A byte-identical re-presentation of a statement already verified. */
  'CONVERGED_ON_VERIFIED_STATEMENT',
  'REFUSED',
]);
export type WhisperDeviceActionV2VerificationOutcome = z.infer<typeof WhisperDeviceActionV2VerificationOutcomeSchema>;

export const WhisperDeviceActionV2VerificationResultSchema = z
  .object({
    schema_version: z.literal(2),
    source: z.literal('SENTINEL_SERVER_VERIFICATION'),
    outcome: WhisperDeviceActionV2VerificationOutcomeSchema,
    /** The PRECISE internal reason, and `null` whenever the outcome is not a refusal. */
    refusal: WhisperDeviceActionV2RefusalSchema.nullable(),
    /** Exactly WHAT was verified — the server-established identity, not a claim. */
    context_id: scopedId,
    organisation_id: scopedId,
    site_id: scopedId,
    actor_user_id: scopedId,
    device_id: scopedId,
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    /** The SERVER-resolved profile the check actually ran under. */
    signature_profile: DeviceSignatureProfileSchema,
    /** The registry's CURRENT effective standing at the moment of the verdict. */
    device_trust: DeviceTrustSchema,
    key_state: DeviceKeyLifecycleStateSchema,
    revocation_disposition: DeviceRevocationDispositionSchema.nullable(),
    whisper_signal_id: scopedId,
    whisper_signal_version: z.number().int().positive(),
    device_action_id: z.string().min(1).max(256),
    /** The digest of the exact canonical statement the verdict was produced against. */
    statement_fingerprint: DeviceDigestSchema,
    /** The digest of the replay identity that was spent. Never the nonce itself. */
    replay_identity_digest: DeviceDigestSchema,
    /** What a later exact re-presentation converges ON. `null` before one exists. */
    stored_outcome_ref: z.string().min(1).max(512).nullable(),
    /** THE SERVER'S instant. This, and not `recognised_at`, is freshness. */
    verified_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    // A refusal with no reason, and a success carrying one, are both incoherent
    // states — and an incoherent verdict is exactly what a later reader
    // interprets generously.
    if (value.outcome === 'REFUSED' && value.refusal === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['refusal'], message: 'a REFUSED result must name its refusal' });
    }
    if (value.outcome !== 'REFUSED' && value.refusal !== null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['refusal'], message: 'only a REFUSED result may name a refusal' });
    }
    if (value.outcome === 'CONVERGED_ON_VERIFIED_STATEMENT' && value.stored_outcome_ref === null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['stored_outcome_ref'],
        message: 'a convergence must name the stored outcome it converged on',
      });
    }
  });
export type WhisperDeviceActionV2VerificationResult = z.infer<typeof WhisperDeviceActionV2VerificationResultSchema>;

/** True only for the two outcomes that mean the statement is authentic. */
export function whisperDeviceActionV2StatementIsVerified(result: WhisperDeviceActionV2VerificationResult): boolean {
  return result.outcome === 'VERIFIED_STATEMENT' || result.outcome === 'CONVERGED_ON_VERIFIED_STATEMENT';
}

/**
 * The v1/v2 dispatch discriminant, stated as a function so no caller has to
 * guess and no caller may probe.
 *
 * It reads ONE field — `schema_version` — and answers with a version or
 * `null`. There is deliberately no branch that inspects a signature, a key, an
 * algorithm name or a length to decide which path a payload belongs to: an
 * implementation that guessed would be an implementation an attacker could
 * steer, and "try v2, fall back to v1" is a downgrade with a friendly name.
 */
export function whisperDeviceActionSchemaVersionOf(value: unknown): 1 | 2 | null {
  if (typeof value !== 'object' || value === null) return null;
  const version: unknown = (value as { schema_version?: unknown }).schema_version;
  if (version === 1) return 1;
  if (version === 2) return 2;
  return null;
}

/**
 * A parse helper that exists so the version discriminant and the schema can
 * never disagree: it refuses anything whose `schema_version` is not 2 BEFORE
 * the schema runs, so a v1 payload is refused as a version mismatch rather than
 * as a bag of field errors that a caller might retry differently.
 */
export function parseWhisperDeviceActionV2Claims(
  value: unknown,
): { readonly ok: true; readonly claims: WhisperDeviceActionV2Claims } | { readonly ok: false; readonly refusal: 'SUBMISSION_MALFORMED' } {
  if (whisperDeviceActionSchemaVersionOf(value) !== 2) return { ok: false, refusal: 'SUBMISSION_MALFORMED' };
  const parsed = WhisperDeviceActionV2ClaimsSchema.safeParse(value);
  return parsed.success ? { ok: true, claims: parsed.data } : { ok: false, refusal: 'SUBMISSION_MALFORMED' };
}
