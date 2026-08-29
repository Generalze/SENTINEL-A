import { createHash } from 'node:crypto';
import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import { DeviceSignatureProfileSchema, DeviceSignatureSchema } from './device-signature.js';

/**
 * WP-23 device identity, enrollment, custody, keys, attestation and trust
 * (directive D23-01..D23-16 with the C14-01..C14-06 corrections).
 *
 * THE GOVERNING SENTENCE
 * ----------------------
 * A device credential proves WHICH HARDWARE is speaking. A user session proves
 * WHO is speaking. Neither creates the other, and a production Field operation
 * needs both, plus site/context authority, plus Constitution policy where
 * applicable. Every schema and every helper in this module exists to keep those
 * four facts separate and to make it structurally impossible for one of them to
 * be manufactured out of another.
 *
 * WHAT THIS MODULE IS NOT (D23-16)
 * --------------------------------
 * There is no registry, no gateway, no endpoint, no persistence and no
 * cryptography here. Every function is pure and every schema describes a shape.
 * Where a decision needs a cryptographic or database fact, that fact arrives as
 * an explicitly SERVER-OWNED input — never as a field a device could populate.
 */

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

/** A SHA-256 digest pinned to its exact lowercase hex shape (the C11-01 form). */
export const DeviceDigestSchema = z.string().regex(/^[0-9a-f]{64}$/u, 'must be lowercase 64-character SHA-256 hex');

/** Anti-replay nonces are opaque to this contract but bounded and non-trivial. */
export const DeviceNonceSchema = z.string().min(16).max(256);

/** A positive key version. Version 0 does not exist; the first key is 1. */
export const DeviceKeyVersionSchema = z.number().int().positive().max(1_000_000);

/** A trace identifier shape shared by the whole WP-23 contract surface. */
export const DeviceTraceIdSchema = z.string().min(1).max(256);

function epochMs(value: string): number {
  return Date.parse(value);
}

// ---------------------------------------------------------------------------
// Canonical JSON (the WP-20/WP-21A discipline, reused by the whole WP-23 set)
// ---------------------------------------------------------------------------

function isPlainJsonRecord(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function describeUnsupported(value: object): string {
  const name: unknown = (value as { constructor?: { name?: unknown } }).constructor?.name;
  return typeof name === 'string' && name.length > 0 ? name : 'non-plain object';
}

/**
 * C11-03/C11-06 applied to device identity: the canonicaliser REFUSES what it
 * cannot represent losslessly rather than quietly normalising it.
 *
 * A device fingerprint is the thing an approval binds to and the thing a
 * signature covers. `JSON.stringify` drops `undefined`, renders `NaN` and
 * `Infinity` as `null`, empties a `Date` or a class instance, and turns a
 * sparse hole into `null` — each of which would let two MATERIALLY DIFFERENT
 * enrollment requests share one digest. Two different requests sharing a digest
 * is the whole C14-02 attack: an approval that named request A would then also
 * name request B.
 */
function assertJsonSafe(value: unknown, path: string, seen: Set<object> = new Set()): void {
  if (value === null) return;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return;
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError(`${path} is not canonically representable: non-finite number`);
      return;
    case 'object': {
      const object = value as object;
      if (seen.has(object)) throw new TypeError(`${path} is not canonically representable: cyclic reference`);
      seen.add(object);
      if (Array.isArray(object)) {
        assertDenseJsonArray(object, path, seen);
        seen.delete(object);
        return;
      }
      if (!isPlainJsonRecord(object)) throw new TypeError(`${path} is not canonically representable: ${describeUnsupported(object)}`);
      if (Object.getOwnPropertySymbols(object).length > 0) {
        throw new TypeError(`${path} is not canonically representable: symbol-keyed property`);
      }
      for (const key of Object.getOwnPropertyNames(object)) {
        const descriptor = Object.getOwnPropertyDescriptor(object, key);
        if (descriptor === undefined) continue;
        if (!descriptor.enumerable || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
          throw new TypeError(`${path}.${key} is not canonically representable: non-enumerable or accessor property`);
        }
        assertJsonSafe(descriptor.value, `${path}.${key}`, seen);
      }
      seen.delete(object);
      return;
    }
    default:
      throw new TypeError(`${path} is not canonically representable: ${typeof value}`);
  }
}

/** C11-07: an array must be a GENUINE, DENSE JSON array, inspected by descriptor. */
function assertDenseJsonArray(value: readonly unknown[], path: string, seen: Set<object>): void {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError(`${path} is not canonically representable: array with a non-standard prototype`);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new TypeError(`${path} is not canonically representable: symbol-keyed property on an array`);
  }
  const { length } = value;
  for (const name of Object.getOwnPropertyNames(value)) {
    if (name === 'length') continue;
    const index = Number(name);
    if (!Number.isInteger(index) || index < 0 || index >= length || String(index) !== name) {
      throw new TypeError(`${path}.${name} is not canonically representable: JSON arrays carry no named properties`);
    }
  }
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) throw new TypeError(`${path}[${index}] is not canonically representable: sparse array hole`);
    if (!descriptor.enumerable || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
      throw new TypeError(`${path}[${index}] is not canonically representable: non-enumerable or accessor index`);
    }
    assertJsonSafe(descriptor.value, `${path}[${index}]`, seen);
  }
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

/**
 * Canonical JSON for every WP-23 statement: object keys sort recursively,
 * array order is preserved, and anything not losslessly representable is
 * REFUSED rather than normalised.
 */
export function canonicalDeviceJson(value: unknown): string {
  assertJsonSafe(value, 'value');
  return JSON.stringify(sortKeysDeep(value)) ?? 'null';
}

/** True when `value` is a record this module can canonicalise without loss. */
export function isCanonicalDeviceJsonRecord(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  try {
    assertJsonSafe(value, 'value');
    return true;
  } catch {
    return false;
  }
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** SHA-256 hex over the canonical JSON form of `value`. The one digest recipe WP-23 uses. */
export function deviceCanonicalDigest(value: unknown): string {
  return sha256Hex(canonicalDeviceJson(value));
}

// ---------------------------------------------------------------------------
// The numeric ceilings (the W21-08 discipline: named, reviewable, in the contract)
// ---------------------------------------------------------------------------

/**
 * EVERY CONSTANT BELOW IS A MAXIMUM, NOT A SETTING.
 *
 * A runtime may choose to be stricter. Raising one of these is a change to the
 * security contract and needs the lead's approval and a visible diff — it is
 * never a configuration knob, an environment variable, or a per-tenant policy.
 * They live here, in the contract, for exactly the reason W21-08 put the
 * Whisper freshness bounds here: a bound hidden inside a service is a bound
 * nobody reviews.
 */

/**
 * A bootstrap grant is a live handshake, not a credential to carry around.
 * Ten minutes is the window between a Command principal issuing it and the
 * device in front of them starting enrollment. Longer turns it into the
 * indefinite QR code D23-04 explicitly refuses.
 */
export const DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS = 600_000;

/**
 * An enrollment request must be approved and completed while the human who is
 * approving it can still see the device. Fifteen minutes covers a real approval
 * round trip; beyond that the request is re-made rather than resumed, so an
 * approval never lands on a request nobody remembers.
 */
export const DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS = 900_000;

/**
 * A possession challenge is answered by hardware that is present, now. Two
 * minutes matches MAX_WHISPER_RECOGNITION_AGE_MS for the same reason: a
 * challenge outstanding longer than that is more likely captured than live.
 */
export const DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS = 120_000;

/**
 * D23-07: the context's lifetime IS the maximum window in which revocation can
 * be outrun. Five minutes keeps that window small enough to accept even before
 * C14-03's sender-constraint is applied — and with the sender-constraint, a
 * lifted context is inert anyway.
 */
export const DEVICE_CONTEXT_MAX_LIFETIME_MS = 300_000;

/**
 * A per-request possession proof is minted for one request. One minute is
 * generous for a real round trip and short enough that a captured proof has
 * almost no reuse value — and its nonce is one-shot regardless.
 */
export const DEVICE_REQUEST_PROOF_MAX_AGE_MS = 60_000;

/**
 * Ordinary clock drift is tolerated; a device claiming to be signing from the
 * future to extend its own acceptance window is not. Same five seconds, same
 * reasoning, as MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS.
 */
export const DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS = 5_000;

/**
 * C14-05: a third-party attestation provider being unreachable is NOT device
 * evidence. An already-verified device rides its last-known-good result for six
 * hours — long enough to cover a normal provider outage without instantly
 * disabling every known-good duress device, short enough that the fail-closed
 * end state still arrives within one shift.
 */
export const DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS = 21_600_000;

/**
 * D23-11: cached offline authority expires. Six hours matches the attestation
 * grace deliberately — the two are the same bet, that one shift is the longest
 * we will act on evidence we cannot currently refresh.
 */
export const DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS = 21_600_000;

// ---------------------------------------------------------------------------
// Custody, key storage and the D23-01/D23-02 principal boundary
// ---------------------------------------------------------------------------

/**
 * C14-02: CUSTODY IS NOT IDENTITY.
 *
 * `PERSONAL` — the device is assigned to one operative and is expected to be in
 * that person's sole custody.
 * `CONTROLLED_SHARED` — the device is issued to a site and legitimately passes
 * between operatives across shifts, under a named custody régime.
 *
 * Both are enrollment PROVENANCE. `enrolled_by_user_id` records the human who
 * stood behind the enrollment and `intended_user_id` records who it was meant
 * for; NEITHER is the currently authenticated actor, and neither may harden
 * into permanent hardware identity. M2's replay design already assumes more
 * than one actor may legitimately use one device — the actor is part of the
 * replay identity for exactly that reason — so a contract that fused
 * `intended_user_id` into device identity would break a rule that already
 * exists. Every live authorisation question is answered from the CURRENT
 * session, never from these fields.
 */
export const DEVICE_CUSTODY_MODES = ['PERSONAL', 'CONTROLLED_SHARED'] as const;
export const DeviceCustodySchema = z.enum(DEVICE_CUSTODY_MODES);
export type DeviceCustody = z.infer<typeof DeviceCustodySchema>;

/**
 * D23-03: a platform that cannot hold its private key in hardware-backed
 * storage (Secure Enclave / StrongBox / equivalent) may still enrol — it simply
 * cannot hold a TRUSTED credential. The contract says so rather than quietly
 * widening the profile list to accommodate it.
 */
export const DeviceKeyStorageSchema = z.enum(['HARDWARE_BACKED', 'SOFTWARE']);
export type DeviceKeyStorage = z.infer<typeof DeviceKeyStorageSchema>;

/** D23-03: only a hardware-backed key can carry a TRUSTED credential. */
export function deviceKeyStoragePermitsTrusted(storage: DeviceKeyStorage): boolean {
  return storage === 'HARDWARE_BACKED';
}

/**
 * D23-01/D23-02: the two lists that must never be joined.
 *
 * These are documentation with teeth — they are asserted in the Crucible so a
 * future edit that moves `user_roles` into the device column, or `device_trust`
 * into the session column, fails a test rather than shipping.
 */
export const DEVICE_CREDENTIAL_ESTABLISHES = ['device_identity', 'device_key_continuity', 'device_trust'] as const;
export const USER_SESSION_ESTABLISHES = ['user_identity', 'user_roles', 'user_site_scope'] as const;

export const DevicePrincipalRefusalSchema = z.enum([
  'USER_NOT_AUTHENTICATED',
  'DEVICE_NOT_AUTHENTICATED',
  'DEVICE_TRUST_INSUFFICIENT',
  'SITE_AUTHORITY_MISSING',
  'POLICY_NOT_SATISFIED',
]);
export type DevicePrincipalRefusal = z.infer<typeof DevicePrincipalRefusalSchema>;

/**
 * The four facts, every time (D23-01 + D23-02).
 *
 * Each input is an independently established SERVER fact. There is deliberately
 * no code path in which supplying one of them satisfies another: an
 * authenticated user with no device credential is refused, and a perfectly
 * TRUSTED device with no session is refused. That symmetry is the whole ruling.
 */
export interface DeviceOperationPrincipals {
  /** A session proved WHO. It says nothing about the hardware. */
  readonly userAuthenticated: boolean;
  /** A device credential proved WHICH HARDWARE. It says nothing about the person. */
  readonly deviceAuthenticated: boolean;
  /** The platform's judgement about the device, from the registry (D23-05). */
  readonly deviceTrust: DeviceTrust;
  /** Which trust states this particular operation admits (W21-05 style). */
  readonly requiredTrust: readonly DeviceTrust[];
  /** Recomputed per operation from current roles and site scope (C12-01). */
  readonly siteAuthorityGranted: boolean;
  /** Constitution policy, where applicable, evaluated now. */
  readonly policySatisfied: boolean;
}

export type DeviceOperationAdmission =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly refusal: DevicePrincipalRefusal };

export function evaluateDeviceOperationPrincipals(input: DeviceOperationPrincipals): DeviceOperationAdmission {
  if (!input.userAuthenticated) return { admitted: false, refusal: 'USER_NOT_AUTHENTICATED' };
  if (!input.deviceAuthenticated) return { admitted: false, refusal: 'DEVICE_NOT_AUTHENTICATED' };
  if (!input.requiredTrust.includes(input.deviceTrust)) return { admitted: false, refusal: 'DEVICE_TRUST_INSUFFICIENT' };
  if (!input.siteAuthorityGranted) return { admitted: false, refusal: 'SITE_AUTHORITY_MISSING' };
  if (!input.policySatisfied) return { admitted: false, refusal: 'POLICY_NOT_SATISFIED' };
  return { admitted: true };
}

// ---------------------------------------------------------------------------
// Attestation (D23-06 / C14-05)
// ---------------------------------------------------------------------------

/**
 * C14-05: a provider OUTAGE and a FAILED verification are different facts and
 * are named separately.
 *
 * VERIFIED     positive device evidence.
 * NEGATIVE     the provider verified and said no. Device evidence.
 * INVALID      the evidence did not parse or did not bind. Device evidence.
 * REVOKED      the attestation key or app record was revoked. Device evidence.
 * UNAVAILABLE  the provider could not be reached. NOT device evidence — it is
 *              neither positive nor negative, and treating it as failure would
 *              let a third party's downtime quarantine an entire fleet.
 */
export const DeviceAttestationOutcomeSchema = z.enum(['VERIFIED', 'NEGATIVE', 'INVALID', 'REVOKED', 'UNAVAILABLE']);
export type DeviceAttestationOutcome = z.infer<typeof DeviceAttestationOutcomeSchema>;

/** The outcomes that are DEVICE evidence and may immediately lower trust. */
export const DEVICE_NEGATIVE_ATTESTATION_OUTCOMES: readonly DeviceAttestationOutcome[] = ['NEGATIVE', 'INVALID', 'REVOKED'];

/**
 * Attestation EVIDENCE as it travels inside a contract.
 *
 * D23-14: there is deliberately NO blob field. The raw platform attestation
 * token is verified at the boundary and discarded; what survives into any
 * contract, audit row or fingerprint is the OUTCOME plus an opaque reference
 * the platform can correlate. A structure with nowhere to put a blob cannot
 * leak one.
 */
export const DeviceAttestationEvidenceSchema = z
  .object({
    outcome: DeviceAttestationOutcomeSchema,
    /** SERVER time at which the platform evaluated the evidence. */
    evaluated_at: timestamp,
    /** An opaque correlation handle. Never the attestation token itself. */
    attestation_reference: scopedId.nullable(),
  })
  .strict();
export type DeviceAttestationEvidence = z.infer<typeof DeviceAttestationEvidenceSchema>;

/**
 * CURRENT           verified now.
 * LAST_KNOWN_GOOD   provider unavailable, but a prior VERIFIED result is still
 *                   inside the grace window.
 * EXPIRED           provider unavailable and the grace has run out.
 * NEGATIVE          the device failed verification. Not a time problem.
 * INELIGIBLE        provider unavailable and there is NO prior verified result
 *                   to ride on. A device in this state has never been vouched
 *                   for and cannot become TRUSTED on an outage.
 */
export const DeviceAttestationStandingSchema = z.enum(['CURRENT', 'LAST_KNOWN_GOOD', 'EXPIRED', 'NEGATIVE', 'INELIGIBLE']);
export type DeviceAttestationStanding = z.infer<typeof DeviceAttestationStandingSchema>;

export interface DeviceAttestationStandingInput {
  readonly outcome: DeviceAttestationOutcome;
  /** SERVER-recorded time of the most recent VERIFIED result, or null. */
  readonly lastVerifiedAt: string | null;
  /** The authoritative server clock. */
  readonly now: string;
  /** Whether the registry holds any prior VERIFIED attestation for this device. */
  readonly hasPriorVerified: boolean;
}

export interface DeviceAttestationStandingResult {
  readonly standing: DeviceAttestationStanding;
  /** Age of the last-known-good result in ms, or null when it is not the basis. */
  readonly lastKnownGoodAgeMs: number | null;
}

/**
 * C14-05, ruled in one place so no runtime has to re-derive it.
 *
 * The asymmetry is deliberate: negative evidence acts IMMEDIATELY and needs no
 * grace, because a device that failed verification is a device we know
 * something bad about. An outage acts SLOWLY and only against devices that
 * already earned a positive result, because an outage tells us nothing about
 * any device at all.
 */
export function evaluateAttestationStanding(input: DeviceAttestationStandingInput): DeviceAttestationStandingResult {
  if (DEVICE_NEGATIVE_ATTESTATION_OUTCOMES.includes(input.outcome)) {
    return { standing: 'NEGATIVE', lastKnownGoodAgeMs: null };
  }
  if (input.outcome === 'VERIFIED') return { standing: 'CURRENT', lastKnownGoodAgeMs: null };

  // UNAVAILABLE. No new positive evidence, and no negative evidence either.
  if (!input.hasPriorVerified || input.lastVerifiedAt === null) {
    return { standing: 'INELIGIBLE', lastKnownGoodAgeMs: null };
  }
  const ageMs = epochMs(input.now) - epochMs(input.lastVerifiedAt);
  // A server-recorded verification cannot legitimately be in the future; if the
  // clocks disagree we treat the result as fresh rather than inventing an age.
  const effectiveAgeMs = ageMs < 0 ? 0 : ageMs;
  if (effectiveAgeMs > DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS) {
    return { standing: 'EXPIRED', lastKnownGoodAgeMs: effectiveAgeMs };
  }
  return { standing: 'LAST_KNOWN_GOOD', lastKnownGoodAgeMs: effectiveAgeMs };
}

/**
 * The only two standings that can support TRUSTED.
 *
 * EXPIRED cannot: the grace is over and W21-05 requires TRUSTED to fire
 * Whisper, so a device we can no longer vouch for falls back to the loud
 * channels. INELIGIBLE cannot: a first enrollment during an outage has never
 * been verified at all (C14-05).
 */
export function attestationStandingPermitsTrusted(standing: DeviceAttestationStanding): boolean {
  return standing === 'CURRENT' || standing === 'LAST_KNOWN_GOOD';
}

// ---------------------------------------------------------------------------
// Enrollment lifecycle (D23-04 / C14-02)
// ---------------------------------------------------------------------------

export const DEVICE_ENROLLMENT_STATES = ['REQUESTED', 'APPROVED', 'POSSESSION_PROVEN', 'ENROLLED', 'REJECTED', 'EXPIRED', 'REVOKED'] as const;
export const DeviceEnrollmentStateSchema = z.enum(DEVICE_ENROLLMENT_STATES);
export type DeviceEnrollmentState = z.infer<typeof DeviceEnrollmentStateSchema>;

/**
 * The exact ceremony, in order, with no shortcut.
 *
 * REQUESTED -> APPROVED -> POSSESSION_PROVEN -> ENROLLED is the C14-02 sequence
 * and there is no edge that skips a step: REQUESTED cannot reach ENROLLED,
 * because the two things that stand between them — a human approving THIS
 * request, and the hardware proving possession of THE APPROVED key — are the
 * entire defence against the stolen-grant preemption attack.
 *
 * REJECTED, EXPIRED and REVOKED are terminal. A terminal enrollment never
 * resurrects; the device makes a NEW request, which gets a new fingerprint and
 * needs a new human approval (D23-09).
 */
export const ALLOWED_DEVICE_ENROLLMENT_TRANSITIONS: Readonly<Record<DeviceEnrollmentState, readonly DeviceEnrollmentState[]>> = {
  REQUESTED: ['APPROVED', 'REJECTED', 'EXPIRED'],
  APPROVED: ['POSSESSION_PROVEN', 'REJECTED', 'EXPIRED'],
  POSSESSION_PROVEN: ['ENROLLED', 'REJECTED', 'EXPIRED'],
  ENROLLED: ['REVOKED'],
  REJECTED: [],
  EXPIRED: [],
  REVOKED: [],
};

export const TERMINAL_DEVICE_ENROLLMENT_STATES: readonly DeviceEnrollmentState[] = ['REJECTED', 'EXPIRED', 'REVOKED'];

export function isTerminalDeviceEnrollmentState(state: DeviceEnrollmentState): boolean {
  return TERMINAL_DEVICE_ENROLLMENT_STATES.includes(state);
}

export function canTransitionDeviceEnrollment(from: DeviceEnrollmentState, to: DeviceEnrollmentState): boolean {
  return ALLOWED_DEVICE_ENROLLMENT_TRANSITIONS[from].includes(to);
}

// ---------------------------------------------------------------------------
// The bootstrap grant (D23-04)
// ---------------------------------------------------------------------------

/**
 * The SERVER's record of a bootstrap grant.
 *
 * D23-14: there is no token field, here or anywhere else in WP-23. The secret
 * the device presents exists only in transit; what the contract models is the
 * grant's identity, scope, lifetime and burn state. A structure with nowhere to
 * put a token cannot leak one into an audit row.
 *
 * D23-04: single-use, short-lived, bound to exactly one organisation + site +
 * intended user, attributable to the issuing human, and revocable before use.
 * `single_use` is a literal rather than a boolean for a reason — there is no
 * multi-use grant to configure.
 */
export const DeviceEnrollmentBootstrapGrantSchema = z
  .object({
    schema_version: z.literal(1),
    grant_id: scopedId,
    organisation_id: scopedId,
    site_id: scopedId,
    /** Enrollment provenance, NOT hardware identity (C14-02). */
    intended_user_id: scopedId,
    /** The human this grant is auditable to (D23-04). */
    issued_by_user_id: scopedId,
    issued_at: timestamp,
    expires_at: timestamp,
    single_use: z.literal(true),
    /** Set when the grant is burned. A second use is a conflict, never a second device. */
    consumed_at: timestamp.nullable(),
    revoked_at: timestamp.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    const issued = epochMs(value.issued_at);
    const expires = epochMs(value.expires_at);
    if (!(expires > issued)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be after issued_at' });
    } else if (expires - issued > DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: `bootstrap grant lifetime must not exceed ${DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS} ms`,
      });
    }
  });
export type DeviceEnrollmentBootstrapGrant = z.infer<typeof DeviceEnrollmentBootstrapGrantSchema>;

export const DeviceBootstrapGrantStandingSchema = z.enum(['USABLE', 'EXPIRED', 'CONSUMED', 'REVOKED']);
export type DeviceBootstrapGrantStanding = z.infer<typeof DeviceBootstrapGrantStandingSchema>;

/**
 * Revoked and consumed are checked BEFORE expiry so a burned grant reads as
 * burned rather than as merely old — the audit distinction matters when the
 * second use is an attacker's.
 */
export function classifyDeviceBootstrapGrant(grant: DeviceEnrollmentBootstrapGrant, now: string): DeviceBootstrapGrantStanding {
  if (grant.revoked_at !== null) return 'REVOKED';
  if (grant.consumed_at !== null) return 'CONSUMED';
  if (epochMs(now) > epochMs(grant.expires_at)) return 'EXPIRED';
  return 'USABLE';
}

/** D23-04: an enrollment must happen inside the exact scope the grant names. */
export function bootstrapGrantMatchesScope(
  grant: DeviceEnrollmentBootstrapGrant,
  scope: { readonly organisation_id: string; readonly site_id: string; readonly intended_user_id: string },
): boolean {
  return grant.organisation_id === scope.organisation_id && grant.site_id === scope.site_id && grant.intended_user_id === scope.intended_user_id;
}

// ---------------------------------------------------------------------------
// The enrollment request and its fingerprint (C14-02)
// ---------------------------------------------------------------------------

/** Domain separator: an enrollment-request digest can serve no other purpose. */
export const DEVICE_ENROLLMENT_REQUEST_DOMAIN = 'sentinel.device.enrollment-request.v1';

/** Domain separator for the possession challenge statement. */
export const DEVICE_POSSESSION_CHALLENGE_DOMAIN = 'sentinel.device.possession-challenge.v1';

/** Domain separator for sequence-namespace derivation. */
export const DEVICE_SEQUENCE_NAMESPACE_DOMAIN = 'sentinel.device.sequence-namespace.v1';

/**
 * What the device asks for.
 *
 * D23-03: the device generates its own keypair in hardware-backed storage and
 * Sentinel receives ONLY a public-key thumbprint. There is no private-key
 * field, no escrow field, no backup field and no migration field — not here and
 * not anywhere in WP-23 — so no enrollment, support or debug path can carry
 * one.
 */
export const DeviceEnrollmentRequestSchema = z
  .object({
    schema_version: z.literal(1),
    enrollment_request_id: scopedId,
    organisation_id: scopedId,
    site_id: scopedId,
    /** Provenance: who this enrollment was meant for, not who is authenticated now. */
    intended_user_id: scopedId,
    bootstrap_grant_id: scopedId,
    custody: DeviceCustodySchema,
    signature_profile: DeviceSignatureProfileSchema,
    key_storage: DeviceKeyStorageSchema,
    /** SHA-256 over the canonical SPKI encoding of the PUBLIC key. */
    public_key_thumbprint: DeviceDigestSchema,
    attestation: DeviceAttestationEvidenceSchema,
    requested_at: timestamp,
  })
  .strict();
export type DeviceEnrollmentRequest = z.infer<typeof DeviceEnrollmentRequestSchema>;

/**
 * C14-02: the digest an approval binds to.
 *
 * Every field that distinguishes one enrollment from another is inside the
 * digest — including the public-key thumbprint, which is what makes an
 * attacker's substituted key visible. Approving a device CLASS, a site, or a
 * time window would leave the attacker's request satisfying the same approval;
 * approving THIS digest does not.
 */
export function deviceEnrollmentRequestFingerprint(request: DeviceEnrollmentRequest): string {
  return deviceCanonicalDigest({
    domain: DEVICE_ENROLLMENT_REQUEST_DOMAIN,
    schema_version: request.schema_version,
    enrollment_request_id: request.enrollment_request_id,
    organisation_id: request.organisation_id,
    site_id: request.site_id,
    intended_user_id: request.intended_user_id,
    bootstrap_grant_id: request.bootstrap_grant_id,
    custody: request.custody,
    signature_profile: request.signature_profile,
    key_storage: request.key_storage,
    public_key_thumbprint: request.public_key_thumbprint,
    attestation_outcome: request.attestation.outcome,
    requested_at: request.requested_at,
  });
}

/**
 * The Command principal's approval of ONE request.
 *
 * `enrollment_request_fingerprint` is the load-bearing field: it is the exact
 * digest above, so an approval cannot drift onto a different request no matter
 * how similar. C14-02 in one column of a schema.
 */
export const DeviceEnrollmentApprovalSchema = z
  .object({
    schema_version: z.literal(1),
    approval_id: scopedId,
    enrollment_request_id: scopedId,
    enrollment_request_fingerprint: DeviceDigestSchema,
    organisation_id: scopedId,
    site_id: scopedId,
    custody: DeviceCustodySchema,
    /** The Command principal holding the explicit enrollment capability (D23-04). */
    approved_by_user_id: scopedId,
    approved_at: timestamp,
  })
  .strict();
export type DeviceEnrollmentApproval = z.infer<typeof DeviceEnrollmentApprovalSchema>;

/**
 * C14-02: does this approval name THIS request?
 *
 * Identity, fingerprint, scope and custody must all agree. The fingerprint
 * alone would be sufficient cryptographically; the rest are checked because a
 * mismatch there means two server records disagree, which is a defect worth
 * refusing on rather than resolving in favour of either.
 */
export function approvalMatchesEnrollmentRequest(approval: DeviceEnrollmentApproval, request: DeviceEnrollmentRequest): boolean {
  return (
    approval.enrollment_request_id === request.enrollment_request_id &&
    approval.enrollment_request_fingerprint === deviceEnrollmentRequestFingerprint(request) &&
    approval.organisation_id === request.organisation_id &&
    approval.site_id === request.site_id &&
    approval.custody === request.custody
  );
}

// ---------------------------------------------------------------------------
// Possession challenge and response (D23-03)
// ---------------------------------------------------------------------------

export const DevicePossessionChallengeSchema = z
  .object({
    schema_version: z.literal(1),
    challenge_id: scopedId,
    enrollment_request_id: scopedId,
    /** Server-issued, one-shot, scoped to the identity that consumes it (D23-12). */
    nonce: DeviceNonceSchema,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    const issued = epochMs(value.issued_at);
    const expires = epochMs(value.expires_at);
    if (!(expires > issued)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be after issued_at' });
    } else if (expires - issued > DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: `possession challenge lifetime must not exceed ${DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS} ms`,
      });
    }
  });
export type DevicePossessionChallenge = z.infer<typeof DevicePossessionChallengeSchema>;

export const DevicePossessionResponseSchema = z
  .object({
    schema_version: z.literal(1),
    challenge_id: scopedId,
    enrollment_request_id: scopedId,
    signature_profile: DeviceSignatureProfileSchema,
    /** Canonical P-256 form; refused before any verifier is entered (C14-01). */
    signature: DeviceSignatureSchema,
    answered_at: timestamp,
  })
  .strict();
export type DevicePossessionResponse = z.infer<typeof DevicePossessionResponseSchema>;

export interface DevicePossessionStatementInput {
  readonly challenge_id: string;
  readonly enrollment_request_id: string;
  readonly enrollment_request_fingerprint: string;
  readonly nonce: string;
  readonly public_key_thumbprint: string;
}

/**
 * EXACTLY what the enrolling device signs.
 *
 * The APPROVED request's fingerprint is inside the statement, so a signature
 * proving possession of an attacker's key cannot be presented against an
 * approval issued for someone else's request: the bytes would not match.
 * Domain-tagged canonical JSON, for the C11-01 reason — a delimiter-joined
 * string lets a value containing the delimiter forge a different tuple.
 */
export function canonicalDevicePossessionStatement(input: DevicePossessionStatementInput): string {
  return canonicalDeviceJson({
    domain: DEVICE_POSSESSION_CHALLENGE_DOMAIN,
    challenge_id: input.challenge_id,
    enrollment_request_id: input.enrollment_request_id,
    enrollment_request_fingerprint: input.enrollment_request_fingerprint,
    nonce: input.nonce,
    public_key_thumbprint: input.public_key_thumbprint,
  });
}

export function devicePossessionStatementFingerprint(input: DevicePossessionStatementInput): string {
  return sha256Hex(canonicalDevicePossessionStatement(input));
}

// ---------------------------------------------------------------------------
// The enrollment commit gate (C14-02)
// ---------------------------------------------------------------------------

/**
 * The four facts a commit requires. Named as data so the Crucible can enumerate
 * them and prove that removing ANY ONE refuses.
 */
export const DEVICE_ENROLLMENT_REQUIRED_FACTS = [
  'BOOTSTRAP_GRANT_CONSUMABLE',
  'APPROVAL_MATCHING_REQUEST_FINGERPRINT',
  'INTENDED_USER_AUTHENTICATED',
  'FRESH_CHALLENGE_ANSWERED_BY_APPROVED_KEY',
] as const;
export type DeviceEnrollmentRequiredFact = (typeof DEVICE_ENROLLMENT_REQUIRED_FACTS)[number];

export const DeviceEnrollmentRefusalSchema = z.enum([
  'BOOTSTRAP_GRANT_MISSING',
  'BOOTSTRAP_GRANT_UNUSABLE',
  'BOOTSTRAP_SCOPE_MISMATCH',
  'REQUEST_EXPIRED',
  'APPROVAL_MISSING',
  'APPROVAL_FINGERPRINT_MISMATCH',
  'USER_NOT_AUTHENTICATED',
  'USER_NOT_INTENDED',
  'CHALLENGE_MISSING',
  'CHALLENGE_MISBOUND',
  'CHALLENGE_EXPIRED',
  'POSSESSION_NOT_PROVEN',
]);
export type DeviceEnrollmentRefusal = z.infer<typeof DeviceEnrollmentRefusalSchema>;

export interface DeviceEnrollmentCommitInput {
  readonly request: DeviceEnrollmentRequest;
  /** The server's grant record. `null` models "no grant at all". */
  readonly grant: DeviceEnrollmentBootstrapGrant | null;
  /** The Command approval, or `null` when nobody approved this exact request. */
  readonly approval: DeviceEnrollmentApproval | null;
  readonly challenge: DevicePossessionChallenge | null;
  /**
   * The SERVER's cryptographic verdict on the challenge response, checked
   * against the public key IN THE APPROVED REQUEST. Never a device claim.
   */
  readonly possessionVerified: boolean;
  readonly possessionAnsweredAt: string | null;
  /**
   * Who is authenticated RIGHT NOW, from the session — deliberately a separate
   * input from `request.intended_user_id`, because provenance is not identity.
   */
  readonly authenticatedUserId: string | null;
  /** The authoritative server clock. */
  readonly now: string;
}

export type DeviceEnrollmentCommitDecision =
  | { readonly decision: 'COMMIT'; readonly enrollment_request_fingerprint: string }
  | { readonly decision: 'REFUSE'; readonly refusal: DeviceEnrollmentRefusal };

/**
 * C14-02: A BOOTSTRAP GRANT ALONE IS NEVER SUFFICIENT.
 *
 * The attack this function exists to lose:
 *
 *   steal an unused bootstrap grant
 *     + generate an attacker keypair
 *     + prove possession of the ATTACKER's private key
 *     = attacker wins the enrollment
 *
 * Proof-of-possession proves possession of THE KEY BEING ENROLLED. It says
 * nothing about whether that is the hardware the issuer intended. So all four
 * facts are required, together, and every one of them is a SERVER fact:
 *
 *   1. a usable, in-scope, single-use grant
 *   2. an approval binding THE EXACT request fingerprint
 *   3. the intended user authenticated in a live session
 *   4. a fresh challenge answered by the APPROVED key
 *
 * Attestation deliberately does NOT gate the commit. A device with weak or
 * unavailable attestation still enrols — at a lower trust state, decided by
 * `initialDeviceTrustOnEnrollment`. Refusing the enrollment outright would make
 * a provider outage an enrollment outage, which is exactly the conflation
 * C14-05 corrected.
 */
export function evaluateDeviceEnrollmentCommit(input: DeviceEnrollmentCommitInput): DeviceEnrollmentCommitDecision {
  const { request } = input;

  // 1. The grant.
  if (input.grant === null) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_MISSING' };
  if (input.grant.grant_id !== request.bootstrap_grant_id) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_SCOPE_MISMATCH' };
  if (classifyDeviceBootstrapGrant(input.grant, input.now) !== 'USABLE') {
    return { decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_UNUSABLE' };
  }
  if (!bootstrapGrantMatchesScope(input.grant, request)) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_SCOPE_MISMATCH' };

  // The request itself must still be live.
  const requestAgeMs = epochMs(input.now) - epochMs(request.requested_at);
  if (requestAgeMs > DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS) return { decision: 'REFUSE', refusal: 'REQUEST_EXPIRED' };

  // 2. The approval, bound to the exact request fingerprint.
  if (input.approval === null) return { decision: 'REFUSE', refusal: 'APPROVAL_MISSING' };
  if (!approvalMatchesEnrollmentRequest(input.approval, request)) {
    return { decision: 'REFUSE', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' };
  }

  // 3. The intended user, authenticated now.
  if (input.authenticatedUserId === null) return { decision: 'REFUSE', refusal: 'USER_NOT_AUTHENTICATED' };
  if (input.authenticatedUserId !== request.intended_user_id) return { decision: 'REFUSE', refusal: 'USER_NOT_INTENDED' };

  // 4. A fresh challenge, answered by the approved key.
  if (input.challenge === null) return { decision: 'REFUSE', refusal: 'CHALLENGE_MISSING' };
  if (input.challenge.enrollment_request_id !== request.enrollment_request_id) {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_MISBOUND' };
  }
  if (input.possessionAnsweredAt === null) return { decision: 'REFUSE', refusal: 'POSSESSION_NOT_PROVEN' };
  const answeredAt = epochMs(input.possessionAnsweredAt);
  if (answeredAt > epochMs(input.challenge.expires_at) || answeredAt < epochMs(input.challenge.issued_at)) {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_EXPIRED' };
  }
  if (!input.possessionVerified) return { decision: 'REFUSE', refusal: 'POSSESSION_NOT_PROVEN' };

  return { decision: 'COMMIT', enrollment_request_fingerprint: deviceEnrollmentRequestFingerprint(request) };
}

/**
 * D23-03 + C14-05: what trust a freshly committed enrollment starts at.
 *
 * TRUSTED requires BOTH a hardware-backed key and a currently verified
 * attestation. A first enrollment during a provider outage has no prior
 * verified result to ride, so its standing is INELIGIBLE and it starts
 * DEGRADED — it can operate every ordinary path and simply cannot fire Whisper
 * until verification returns.
 */
export function initialDeviceTrustOnEnrollment(input: {
  readonly keyStorage: DeviceKeyStorage;
  readonly attestationStanding: DeviceAttestationStanding;
}): DeviceTrust {
  if (input.attestationStanding === 'NEGATIVE') return 'QUARANTINED';
  if (!deviceKeyStoragePermitsTrusted(input.keyStorage)) return 'DEGRADED';
  // LAST_KNOWN_GOOD cannot occur on a FIRST enrollment (there is no prior
  // verified result), but it is admitted here so a re-enrollment during a
  // provider outage behaves the same way a live device does.
  return attestationStandingPermitsTrusted(input.attestationStanding) ? 'TRUSTED' : 'DEGRADED';
}

// ---------------------------------------------------------------------------
// Device identity, key identity and the sequence namespace (D23-09)
// ---------------------------------------------------------------------------

export const DeviceKeyIdentitySchema = z
  .object({
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    signature_profile: DeviceSignatureProfileSchema,
    key_storage: DeviceKeyStorageSchema,
    public_key_thumbprint: DeviceDigestSchema,
  })
  .strict();
export type DeviceKeyIdentity = z.infer<typeof DeviceKeyIdentitySchema>;

/**
 * The registry-known identity.
 *
 * `trust` lives HERE — server-owned state (D23-05) — and has no counterpart in
 * anything a device submits. `enrolled_by_user_id` and `intended_user_id` are
 * enrollment PROVENANCE and are never consulted to answer a live authorisation
 * question (C14-02).
 */
export const DeviceIdentitySchema = z
  .object({
    schema_version: z.literal(1),
    device_id: scopedId,
    organisation_id: scopedId,
    custody: DeviceCustodySchema,
    /** Provenance. Not the current actor, not permanent hardware identity. */
    enrolled_by_user_id: scopedId,
    intended_user_id: scopedId,
    /** Derived, never supplied. See `deviceSequenceNamespaceId`. */
    sequence_namespace_id: scopedId,
    key: DeviceKeyIdentitySchema,
    /** The platform's judgement, never the device's self-report (D23-05). */
    trust: DeviceTrustSchema,
    enrolled_at: timestamp,
    revoked_at: timestamp.nullable(),
  })
  .strict();
export type DeviceIdentity = z.infer<typeof DeviceIdentitySchema>;

/**
 * C10-03 / D23-09: THERE IS NO SEQUENCE RESET, AND NO CALLER CAN ASK FOR ONE.
 *
 * The namespace is a pure function of the organisation and the device id, and
 * of NOTHING ELSE. There is no epoch parameter, no generation counter, no
 * "reset" argument and no exported reset function anywhere in WP-23. Extra
 * properties on the input object are ignored by construction, so a caller
 * cannot smuggle a discriminator in.
 *
 * The consequence is the ruling: the ONLY way to obtain a fresh offline
 * sequence namespace is to obtain a new `device_id`, which means a new
 * enrollment with a new human approval. A device that could rewind its own
 * cursor could re-admit a consumed position and duplicate the effect already
 * recorded there.
 */
export function deviceSequenceNamespaceId(identity: { readonly organisation_id: string; readonly device_id: string }): string {
  return `device-seq:${deviceCanonicalDigest({
    domain: DEVICE_SEQUENCE_NAMESPACE_DOMAIN,
    organisation_id: identity.organisation_id,
    device_id: identity.device_id,
  })}`;
}

/** Why the enrolled hardware credential's continuity was lost (D23-09). */
export const DeviceContinuityLossReasonSchema = z.enum(['WIPE', 'RE_PROVISION', 'CONTINUITY_LOSS', 'COMPROMISE_RECOVERY', 'RE_ENROLLMENT']);
export type DeviceContinuityLossReason = z.infer<typeof DeviceContinuityLossReasonSchema>;

export interface DeviceKeyChangeSubject {
  readonly device_id: string;
  readonly sequence_namespace_id: string;
  readonly key_id: string;
  readonly key_version: number;
  readonly public_key_thumbprint: string;
}

/**
 * The proposed next key, carrying the SERVER-established continuity facts that
 * decide which side of the D23-09 line it falls on.
 *
 * `proved_possession_of_previous_key` is the dividing line the clarification
 * names: continuity of the enrolled hardware credential, not the key material.
 * A device that can still prove possession of its current registered key is
 * ROTATING. One that cannot is RE-ENROLLING, whatever it says about itself.
 */
export interface DeviceKeyChangeProposal extends DeviceKeyChangeSubject {
  readonly proved_possession_of_previous_key: boolean;
  readonly continuity_loss_reason: DeviceContinuityLossReason | null;
}

export const DeviceKeyChangeRefusalSchema = z.enum(['SEQUENCE_NAMESPACE_RESET_ATTEMPTED', 'KEY_VERSION_NOT_ADVANCED']);
export type DeviceKeyChangeRefusal = z.infer<typeof DeviceKeyChangeRefusalSchema>;

export type DeviceKeyChangeClassification =
  | {
      readonly classification: 'ROTATION';
      readonly device_id: string;
      readonly sequence_namespace_id: string;
      readonly from_key_version: number;
      readonly to_key_version: number;
      /** D23-07: every context issued against the old version is now invalid. */
      readonly invalidates_contexts_at_or_below_key_version: number;
    }
  | {
      readonly classification: 'NEW_IDENTITY';
      readonly reason: DeviceContinuityLossReason;
      /** A new identity gets a NEW device_id and therefore a fresh namespace. */
      readonly requires_new_device_id: true;
      readonly requires_fresh_sequence_namespace: true;
    }
  | { readonly classification: 'REFUSED'; readonly refusal: DeviceKeyChangeRefusal };

/**
 * D23-09 with the C14 clarification: routine rotation is not reincarnation.
 *
 *   routine AUTHENTICATED key rotation
 *     -> same device_id, same offline sequence namespace, new key version
 *     -> outstanding contexts bound to the old version become invalid
 *
 *   wipe / re-provision / irrecoverable continuity loss / compromise recovery /
 *   actual re-enrollment
 *     -> NEW device_id, new key identity, fresh sequence namespace
 *
 * The REFUSED arm exists because one shape is neither: the same `device_id`,
 * with credential continuity intact, presented with a DIFFERENT sequence
 * namespace. That is not a rotation and not a re-enrollment — it is a namespace
 * reset wearing a rotation's clothes, and naming it as a refusal is how the
 * contract says the reset path does not exist.
 */
export function classifyDeviceKeyChange(previous: DeviceKeyChangeSubject, next: DeviceKeyChangeProposal): DeviceKeyChangeClassification {
  const continuityLost = next.continuity_loss_reason !== null || !next.proved_possession_of_previous_key;

  if (next.device_id !== previous.device_id) {
    return {
      classification: 'NEW_IDENTITY',
      reason: next.continuity_loss_reason ?? 'RE_ENROLLMENT',
      requires_new_device_id: true,
      requires_fresh_sequence_namespace: true,
    };
  }

  if (continuityLost) {
    // Same device_id but no credential continuity: the old identity is RETIRED,
    // not reused. Reusing it would let the re-enrolled device inherit a replay
    // namespace whose consumed positions it no longer knows.
    return {
      classification: 'NEW_IDENTITY',
      reason: next.continuity_loss_reason ?? 'CONTINUITY_LOSS',
      requires_new_device_id: true,
      requires_fresh_sequence_namespace: true,
    };
  }

  if (next.sequence_namespace_id !== previous.sequence_namespace_id) {
    return { classification: 'REFUSED', refusal: 'SEQUENCE_NAMESPACE_RESET_ATTEMPTED' };
  }
  if (next.key_version <= previous.key_version) {
    return { classification: 'REFUSED', refusal: 'KEY_VERSION_NOT_ADVANCED' };
  }

  return {
    classification: 'ROTATION',
    device_id: previous.device_id,
    sequence_namespace_id: previous.sequence_namespace_id,
    from_key_version: previous.key_version,
    to_key_version: next.key_version,
    invalidates_contexts_at_or_below_key_version: previous.key_version,
  };
}

// ---------------------------------------------------------------------------
// Trust transitions (D23-05 / D23-07)
// ---------------------------------------------------------------------------

/**
 * The transition matrix over the canonical six states from `device.ts`.
 *
 * COMPROMISED has NO outgoing edges. That is D23-05's terminal ruling: a
 * decision no device can reverse. Restoring a compromised identity is not a
 * transition, it is a new enrollment producing a new device_id (D23-09).
 *
 * QUARANTINED is reachable from every non-terminal state, because the point of
 * quarantine is to act on suspicion BEFORE certainty. Self-transitions are
 * absent by construction — a transition to the state you are already in is a
 * no-op, and admitting it would let an audit trail claim a decision happened.
 */
export const ALLOWED_DEVICE_TRUST_TRANSITIONS: Readonly<Record<DeviceTrust, readonly DeviceTrust[]>> = {
  TRUSTED: ['DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
  DEGRADED: ['TRUSTED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
  SUSPICIOUS: ['TRUSTED', 'DEGRADED', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
  QUARANTINED: ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'COMPROMISED', 'OFFLINE'],
  COMPROMISED: [],
  OFFLINE: ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED'],
};

export function isTerminalDeviceTrust(trust: DeviceTrust): boolean {
  return ALLOWED_DEVICE_TRUST_TRANSITIONS[trust].length === 0;
}

/** The named capability a human needs to restore trust to a suspected device. */
export const DEVICE_TRUST_RESTORATION_CAPABILITY = 'device.trust.restore';

/** The states a controlled restoration is climbing OUT of. */
export const DEVICE_TRUST_RESTORATION_REQUIRED_FROM: readonly DeviceTrust[] = ['SUSPICIOUS', 'QUARANTINED'];

/** The states that represent regained operational capability. */
export const DEVICE_TRUST_UPWARD_TARGETS: readonly DeviceTrust[] = ['TRUSTED', 'DEGRADED'];

export interface DeviceControlledRestorationDecision {
  readonly decided_by_user_id: string;
  readonly capability: typeof DEVICE_TRUST_RESTORATION_CAPABILITY;
  readonly decided_at: string;
}

/**
 * The SERVER-side facts a trust transition is judged on.
 *
 * `deviceReportedHealth` is present for one reason only: so the contract can
 * demonstrate, in a test, that it is NEVER READ. D23-05 lets a device supply
 * evidence and never the conclusion, and the cheapest way to prove a field is
 * not consulted is to accept it and show the answer does not move.
 */
export interface DeviceTrustTransitionBasis {
  /** An explicit human decision with the named capability. Never a device claim. */
  readonly controlledRestoration: DeviceControlledRestorationDecision | null;
  readonly attestationStanding: DeviceAttestationStanding;
  readonly keyStorage: DeviceKeyStorage;
  /** The device can still prove possession of its current registered key. */
  readonly credentialContinuityIntact: boolean;
  /** Server-known revocation, at reconciliation time (D23-08). */
  readonly revoked: boolean;
  /** OFFLINE -> TRUSTED only: this device held a qualifying basis before it went dark. */
  readonly previouslyEligible: boolean;
  /** Accepted and deliberately ignored. See above. */
  readonly deviceReportedHealth?: unknown;
}

export const DeviceTrustTransitionRefusalSchema = z.enum([
  'TRANSITION_NOT_IN_MATRIX',
  'SOURCE_STATE_TERMINAL',
  'CREDENTIAL_REVOKED',
  'RESTORATION_DECISION_REQUIRED',
  'RESTORATION_CAPABILITY_MISSING',
  'CREDENTIAL_CONTINUITY_LOST',
  'ATTESTATION_NOT_QUALIFYING',
  'KEY_STORAGE_NOT_HARDWARE_BACKED',
  'RECONNECT_BASIS_NOT_ESTABLISHED',
]);
export type DeviceTrustTransitionRefusal = z.infer<typeof DeviceTrustTransitionRefusalSchema>;

export type DeviceTrustTransitionDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly refusal: DeviceTrustTransitionRefusal };

/**
 * D23-05 / D23-07, ruled here rather than in a service.
 *
 * Downward transitions are cheap: evidence lowers trust immediately, and
 * QUARANTINED is always one step away. Upward transitions are expensive, and
 * every one of the requirements below is a SERVER fact:
 *
 *  - out of SUSPICIOUS/QUARANTINED needs an explicit controlled-restoration
 *    decision by a human holding `device.trust.restore`, PLUS qualifying
 *    current evidence. A device-submitted health claim is never one of these.
 *  - into TRUSTED needs a hardware-backed key (D23-03) and an attestation
 *    standing of CURRENT or LAST_KNOWN_GOOD (C14-05).
 *  - OFFLINE -> TRUSTED additionally needs intact credential continuity, no
 *    revocation, and a previously eligible basis. A BLIND RECONNECT — a device
 *    reappearing with nothing established — refuses.
 *  - a revoked credential can climb nowhere at all (D23-08).
 */
export function evaluateDeviceTrustTransition(
  from: DeviceTrust,
  to: DeviceTrust,
  basis: DeviceTrustTransitionBasis,
): DeviceTrustTransitionDecision {
  if (isTerminalDeviceTrust(from)) return { allowed: false, refusal: 'SOURCE_STATE_TERMINAL' };
  if (!ALLOWED_DEVICE_TRUST_TRANSITIONS[from].includes(to)) return { allowed: false, refusal: 'TRANSITION_NOT_IN_MATRIX' };

  const upward = DEVICE_TRUST_UPWARD_TARGETS.includes(to);
  if (!upward) return { allowed: true };

  // Everything below this line is an upward transition.
  if (basis.revoked) return { allowed: false, refusal: 'CREDENTIAL_REVOKED' };

  if (DEVICE_TRUST_RESTORATION_REQUIRED_FROM.includes(from)) {
    if (basis.controlledRestoration === null) return { allowed: false, refusal: 'RESTORATION_DECISION_REQUIRED' };
    if (basis.controlledRestoration.capability !== DEVICE_TRUST_RESTORATION_CAPABILITY) {
      return { allowed: false, refusal: 'RESTORATION_CAPABILITY_MISSING' };
    }
    if (!basis.credentialContinuityIntact) return { allowed: false, refusal: 'CREDENTIAL_CONTINUITY_LOST' };
    if (basis.attestationStanding === 'NEGATIVE' || basis.attestationStanding === 'INELIGIBLE') {
      return { allowed: false, refusal: 'ATTESTATION_NOT_QUALIFYING' };
    }
  }

  if (from === 'OFFLINE' && to === 'TRUSTED') {
    if (!basis.credentialContinuityIntact) return { allowed: false, refusal: 'CREDENTIAL_CONTINUITY_LOST' };
    if (!basis.previouslyEligible) return { allowed: false, refusal: 'RECONNECT_BASIS_NOT_ESTABLISHED' };
  }

  if (to === 'TRUSTED') {
    if (!deviceKeyStoragePermitsTrusted(basis.keyStorage)) return { allowed: false, refusal: 'KEY_STORAGE_NOT_HARDWARE_BACKED' };
    if (!attestationStandingPermitsTrusted(basis.attestationStanding)) return { allowed: false, refusal: 'ATTESTATION_NOT_QUALIFYING' };
    if (!basis.credentialContinuityIntact) return { allowed: false, refusal: 'CREDENTIAL_CONTINUITY_LOST' };
  }

  return { allowed: true };
}

/** Predicate form of `evaluateDeviceTrustTransition`. */
export function canTransitionDeviceTrust(from: DeviceTrust, to: DeviceTrust, basis: DeviceTrustTransitionBasis): boolean {
  return evaluateDeviceTrustTransition(from, to, basis).allowed;
}
