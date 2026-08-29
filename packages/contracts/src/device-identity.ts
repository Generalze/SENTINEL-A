import { createHash } from 'node:crypto';
import { z } from 'zod';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';
import {
  bindClaimedSignatureProfile,
  DeviceP256PublicKeySchema,
  DeviceSignatureProfileSchema,
  DeviceSignatureSchema,
  deviceKeyThumbprintMatches,
  type DeviceSignatureProfile,
  type DeviceSignatureProfileBinding,
} from './device-signature.js';

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

// ---------------------------------------------------------------------------
// Authoritative time (C15-07)
// ---------------------------------------------------------------------------

/**
 * C15-07: THERE IS ONE TIME PARSER AND IT FAILS CLOSED.
 *
 * `Date.parse` returns `NaN` for anything it cannot read, and every comparison
 * against `NaN` is `false`. A bare `Date.parse(a) > Date.parse(b)` therefore
 * ADMITS an unparseable instant — the expiry check silently answers "not
 * expired", the skew check silently answers "no skew". That is the exact
 * opposite of fail-closed, and it was reachable in every evaluator in WP-23.
 *
 * So no evaluation path compares raw `Date.parse` results any more. Every
 * instant an evaluator depends on goes through `parseAuthoritativeInstants`,
 * which refuses the whole set if ANY member is unparseable, and the caller
 * turns that refusal into a named `TIME_NOT_AUTHORITATIVE` outcome. A missing
 * or malformed clock reading is a refusal, never a default.
 *
 * The refusal label is shared so all four modules name the same failure.
 */
export const DEVICE_TIME_NOT_AUTHORITATIVE = 'TIME_NOT_AUTHORITATIVE' as const;
export type DeviceTimeNotAuthoritative = typeof DEVICE_TIME_NOT_AUTHORITATIVE;

/** A single instant, or `null` when it is not a finite, parseable time. */
export function parseAuthoritativeInstant(value: string): number | null {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Parses a whole bag of instants at once and returns `null` if ANY of them is
 * unparseable. All-or-nothing on purpose: a partially parsed set invites a
 * caller to compare the good half and quietly skip the rest.
 */
export function parseAuthoritativeInstants<K extends string>(values: Readonly<Record<K, string>>): Readonly<Record<K, number>> | null {
  const parsed = {} as Record<K, number>;
  for (const key of Object.keys(values) as K[]) {
    const ms = parseAuthoritativeInstant(values[key]);
    if (ms === null) return null;
    parsed[key] = ms;
  }
  return parsed;
}

/**
 * C15-07: expiry is an EXCLUSIVE boundary, everywhere.
 *
 * `now >= expires_at` is expired. The instant named as the expiry is the first
 * instant the thing is no longer valid, not the last instant it is — stated
 * once, here, so no evaluator has to re-decide it and no two evaluators can
 * decide it differently. The boundary tests assert exactly at the instant.
 */
export function isExpiredAt(nowMs: number, expiresAtMs: number): boolean {
  return nowMs >= expiresAtMs;
}

/**
 * The one lifetime-window refinement every WP-23 window schema uses.
 *
 * Ordering (`expires_at > issued_at`), the named ceiling, and the fail-closed
 * time parse in one place, so a bootstrap grant, a possession challenge, a
 * device context and a policy lease cannot drift into four different opinions
 * about what an impossible window is.
 */
export function refineDeviceInstantWindow(
  value: { readonly issued_at: string; readonly expires_at: string },
  context: z.RefinementCtx,
  maxLifetimeMs: number,
  label: string,
): void {
  const instants = parseAuthoritativeInstants({ issued: value.issued_at, expires: value.expires_at });
  if (instants === null) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: `${label} instants must be authoritative` });
    return;
  }
  if (!(instants.expires > instants.issued)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'expires_at must be after issued_at' });
    return;
  }
  if (instants.expires - instants.issued > maxLifetimeMs) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['expires_at'],
      message: `${label} lifetime must not exceed ${maxLifetimeMs} ms`,
    });
  }
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

// ---------------------------------------------------------------------------
// Revocation disposition (D23-15 / C14-06), defined here because trust,
// registry facts and offline resolution all need to name the same three cases.
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

// ---------------------------------------------------------------------------
// The registry key record (C15-02)
// ---------------------------------------------------------------------------

/**
 * C15-02: ROUTINE ROTATION AND COMPROMISE ARE NOT THE SAME STATE.
 *
 * WP-23 had a single `revoked` flag, which forced four genuinely different
 * situations through one bit and lost the distinction that matters most: a key
 * superseded last Tuesday by ordinary rotation is still the key that signed
 * last Monday's evidence, while a key we believe an attacker holds signed
 * nothing we should believe. Collapsing them either destroys the ability to
 * verify history, or keeps a compromised key verifying. Neither is acceptable.
 *
 * CURRENT      the key in force. Verifies history AND authorises new work.
 * ROTATED      superseded by routine, authenticated rotation. It may still
 *              verify evidence produced while it was current — that evidence
 *              was legitimate when made — but it authorises NOTHING new.
 * REVOKED      withdrawn. Neither authorises nor verifies: we no longer stand
 *              behind anything it says.
 * COMPROMISED  believed to be in an attacker's hands. Neither, and TERMINAL —
 *              a compromised key is never rehabilitated, mirroring D23-05's
 *              terminal COMPROMISED trust state.
 */
export const DEVICE_KEY_LIFECYCLE_STATES = ['CURRENT', 'ROTATED', 'REVOKED', 'COMPROMISED'] as const;
export const DeviceKeyLifecycleStateSchema = z.enum(DEVICE_KEY_LIFECYCLE_STATES);
export type DeviceKeyLifecycleState = z.infer<typeof DeviceKeyLifecycleStateSchema>;

/**
 * The allowed transitions. Every edge runs DOWNHILL in authority and there is
 * no edge back — a rotated key never becomes current again (that would be a
 * rollback to a key whose replacement already exists), and COMPROMISED has no
 * outgoing edge at all.
 *
 * ROTATED -> REVOKED and ROTATED -> COMPROMISED both exist because learning
 * something bad about a historical key must be expressible: it is exactly how
 * historical evidence signed by that key stops being believable.
 */
export const ALLOWED_DEVICE_KEY_LIFECYCLE_TRANSITIONS: Readonly<Record<DeviceKeyLifecycleState, readonly DeviceKeyLifecycleState[]>> = {
  CURRENT: ['ROTATED', 'REVOKED', 'COMPROMISED'],
  ROTATED: ['REVOKED', 'COMPROMISED'],
  REVOKED: ['COMPROMISED'],
  COMPROMISED: [],
};

export function canTransitionDeviceKeyLifecycle(from: DeviceKeyLifecycleState, to: DeviceKeyLifecycleState): boolean {
  return ALLOWED_DEVICE_KEY_LIFECYCLE_TRANSITIONS[from].includes(to);
}

export function isTerminalDeviceKeyLifecycleState(state: DeviceKeyLifecycleState): boolean {
  return ALLOWED_DEVICE_KEY_LIFECYCLE_TRANSITIONS[state].length === 0;
}

/** Only the key in force may authorise NEW operations. */
export function deviceKeyStatePermitsNewOperations(state: DeviceKeyLifecycleState): boolean {
  return state === 'CURRENT';
}

/** A routinely superseded key may still verify what it legitimately signed. */
export function deviceKeyStatePermitsHistoricalVerification(state: DeviceKeyLifecycleState): boolean {
  return state === 'CURRENT' || state === 'ROTATED';
}

/**
 * C15-02: THE REGISTRY MUST BE ABLE TO ACTUALLY VERIFY.
 *
 * A record holding only `public_key_thumbprint` can recognise a key it is
 * handed; it cannot check an ECDSA signature, which needs the point. So the
 * registry record carries the CANONICAL PUBLIC KEY, and the thumbprint beside
 * it is refused unless it equals the digest DERIVED from that key — an
 * independently supplied digest is a second claim, not corroboration.
 *
 * `signature_profile` here is THE SERVER-SELECTED PROFILE and the only
 * authority on the subject (C15-01). Every `claimed_signature_profile` on a
 * submitted structure is equality-bound to this field before verification.
 */
export const DeviceRegistryKeyRecordSchema = z
  .object({
    schema_version: z.literal(1),
    organisation_id: scopedId,
    device_id: scopedId,
    key_id: scopedId,
    key_version: DeviceKeyVersionSchema,
    /** The actual key. Without this the registry cannot verify anything. */
    public_key: DeviceP256PublicKeySchema,
    /** Must EQUAL the digest derived from `public_key`. Never trusted alone. */
    public_key_thumbprint: DeviceDigestSchema,
    /** SERVER-selected. The client's claim is checked against this, never the reverse. */
    signature_profile: DeviceSignatureProfileSchema,
    key_storage: DeviceKeyStorageSchema,
    status: DeviceKeyLifecycleStateSchema,
    registered_at: timestamp,
    /** Set when routine rotation superseded this version. */
    rotated_at: timestamp.nullable(),
    /** Set when the key was revoked or declared compromised. */
    revoked_at: timestamp.nullable(),
    revocation_disposition: DeviceRevocationDispositionSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    // `deviceKeyThumbprintMatches` rather than `derive(...) !== ...`: a branded
    // field's own refinement marks the parse DIRTY rather than aborting it, so
    // this block can still see a non-canonical key. The matcher answers `false`
    // where the deriver would throw, keeping a bad key a ZodError.
    if (!deviceKeyThumbprintMatches(value.public_key, value.public_key_thumbprint)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['public_key_thumbprint'],
        message: 'public_key_thumbprint must equal the digest derived from public_key',
      });
    }
    // The status and the timestamps must tell the same story. A record saying
    // CURRENT while carrying a revocation instant is two facts in conflict, and
    // resolving it in favour of either would be guessing.
    if (value.status === 'CURRENT' && (value.rotated_at !== null || value.revoked_at !== null)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['status'], message: 'a CURRENT key carries no rotation or revocation instant' });
    }
    if (value.status === 'ROTATED' && value.rotated_at === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['rotated_at'], message: 'a ROTATED key must record when it was superseded' });
    }
    if ((value.status === 'REVOKED' || value.status === 'COMPROMISED') && value.revoked_at === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['revoked_at'], message: 'a REVOKED or COMPROMISED key must record when it was withdrawn' });
    }
    if (value.status !== 'REVOKED' && value.status !== 'COMPROMISED' && value.revocation_disposition !== null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['revocation_disposition'],
        message: 'only a REVOKED or COMPROMISED key carries a revocation disposition',
      });
    }
  });
export type DeviceRegistryKeyRecord = z.infer<typeof DeviceRegistryKeyRecordSchema>;

/**
 * C15-01: resolve the profile from the REGISTRY, then bind the client's claim
 * to it. The return value is what a canonical statement goes on to sign.
 */
export function resolveRegistrySignatureProfile(record: DeviceRegistryKeyRecord, claimed: unknown): DeviceSignatureProfileBinding {
  return bindClaimedSignatureProfile(claimed, record.signature_profile);
}

// ---------------------------------------------------------------------------
// One-shot consumption (C15-05)
// ---------------------------------------------------------------------------

/**
 * C15-05: A NONCE THAT IS NOT CONSUMED IS NOT A NONCE.
 *
 * WP-23 called several fields "one-shot, scoped to the identity that consumes
 * it" and then never gave any evaluator a way to know whether that had
 * happened — so every evaluator would have admitted the same proof twice. The
 * consumption fact is I/O, and I/O does not belong in contracts (D23-16); what
 * belongs here is the SEAM: the identity a store must key on, the three
 * outcomes the store can report, and an evaluator input that REQUIRES one.
 *
 * There is deliberately no default and no optional field. An evaluator that
 * could be called without the consumption fact is an evaluator that admits a
 * replay whenever a caller forgets — which is how this defect appears in the
 * first place.
 *
 * FIRST_SEEN
 *   this identity has never been presented. Proceed.
 *
 * EXACT_DUPLICATE
 *   same replay identity AND same canonical-statement fingerprint. This is a
 *   retry of one request, not a second request: converge on the outcome already
 *   stored and cause NO second effect. That is WP-20's request-bound
 *   idempotency rule, unchanged.
 *
 * REUSED_WITH_CHANGED_SEMANTICS
 *   same replay identity, DIFFERENT statement fingerprint. Someone is reusing a
 *   one-shot identity to mean something new. Conflict, and no effect — never a
 *   convergence, because there is no shared outcome to converge on.
 */
export const DEVICE_NONCE_CONSUMPTION_OUTCOMES = ['FIRST_SEEN', 'EXACT_DUPLICATE', 'REUSED_WITH_CHANGED_SEMANTICS'] as const;
export const DeviceNonceConsumptionOutcomeSchema = z.enum(DEVICE_NONCE_CONSUMPTION_OUTCOMES);
export type DeviceNonceConsumptionOutcome = z.infer<typeof DeviceNonceConsumptionOutcomeSchema>;

/**
 * The server's report about a one-shot identity.
 *
 * `source` is a literal for the C14-06 reason: the only admissible provenance
 * is Sentinel's own store, and a structure a device could populate would be the
 * loophole. `replay_key` and `statement_fingerprint` are echoed back so the
 * evaluator can prove the fact it was handed is about the request in front of
 * it — a consumption fact for a DIFFERENT request is not evidence about this
 * one.
 */
export interface DeviceNonceConsumption {
  readonly source: 'SENTINEL_NONCE_STORE';
  readonly outcome: DeviceNonceConsumptionOutcome;
  /** The canonical replay-identity string this fact is about. */
  readonly replay_key: string;
  /** The canonical-statement fingerprint this fact is about. */
  readonly statement_fingerprint: string;
  /**
   * On EXACT_DUPLICATE, a pointer to the outcome already recorded, so the
   * caller converges on it. `null` in every other case.
   */
  readonly stored_outcome_ref: string | null;
}

/**
 * The pure classifier a persistence layer wraps. Given what is being presented
 * and what (if anything) the store already holds for that identity, it says
 * which of the three cases this is. No I/O, no clock, no side effect — the
 * store performs the atomic insert-or-read and calls this to name the result.
 */
export function classifyDeviceNonceConsumption(input: {
  readonly replay_key: string;
  readonly statement_fingerprint: string;
  readonly stored: { readonly statement_fingerprint: string; readonly stored_outcome_ref: string } | null;
}): DeviceNonceConsumption {
  if (input.stored === null) {
    return {
      source: 'SENTINEL_NONCE_STORE',
      outcome: 'FIRST_SEEN',
      replay_key: input.replay_key,
      statement_fingerprint: input.statement_fingerprint,
      stored_outcome_ref: null,
    };
  }
  if (input.stored.statement_fingerprint === input.statement_fingerprint) {
    return {
      source: 'SENTINEL_NONCE_STORE',
      outcome: 'EXACT_DUPLICATE',
      replay_key: input.replay_key,
      statement_fingerprint: input.statement_fingerprint,
      stored_outcome_ref: input.stored.stored_outcome_ref,
    };
  }
  return {
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'REUSED_WITH_CHANGED_SEMANTICS',
    replay_key: input.replay_key,
    statement_fingerprint: input.statement_fingerprint,
    stored_outcome_ref: null,
  };
}

/** Domain separator for the enrollment possession-challenge replay identity. */
export const DEVICE_POSSESSION_CHALLENGE_REPLAY_IDENTITY_DOMAIN = 'sentinel.device.possession-challenge.replay-identity.v1';

/** Domain separator for the bootstrap-grant replay identity. */
export const DEVICE_BOOTSTRAP_GRANT_REPLAY_IDENTITY_DOMAIN = 'sentinel.device.bootstrap-grant.replay-identity.v1';

export interface DevicePossessionChallengeReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly intended_user_id: string;
  readonly enrollment_request_id: string;
  readonly challenge_id: string;
  readonly nonce: string;
}

/**
 * C15-05, mirroring `deviceActionWhisperReplayIdentity`: the identity a durable
 * uniqueness constraint is built over, as STRUCTURE. A hash is not an identity
 * — you cannot query it, audit it, or reason about its parts — so the columns
 * are named and the string form below exists only for comparison and logging.
 */
export function devicePossessionChallengeReplayIdentity(input: {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly intended_user_id: string;
  readonly enrollment_request_id: string;
  readonly challenge_id: string;
  readonly nonce: string;
}): DevicePossessionChallengeReplayIdentity {
  return {
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    intended_user_id: input.intended_user_id,
    enrollment_request_id: input.enrollment_request_id,
    challenge_id: input.challenge_id,
    nonce: input.nonce,
  };
}

/** C11-01: canonical JSON, never a delimiter join — a value containing the delimiter would forge another tuple. */
export function devicePossessionChallengeReplayKey(input: Parameters<typeof devicePossessionChallengeReplayIdentity>[0]): string {
  return canonicalDeviceJson({
    domain: DEVICE_POSSESSION_CHALLENGE_REPLAY_IDENTITY_DOMAIN,
    ...devicePossessionChallengeReplayIdentity(input),
  });
}

export interface DeviceBootstrapGrantReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly intended_user_id: string;
  readonly grant_id: string;
}

/** D23-04's `single_use: true` given a mechanism instead of a promise. */
export function deviceBootstrapGrantReplayIdentity(grant: {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly intended_user_id: string;
  readonly grant_id: string;
}): DeviceBootstrapGrantReplayIdentity {
  return {
    organisation_id: grant.organisation_id,
    site_id: grant.site_id,
    intended_user_id: grant.intended_user_id,
    grant_id: grant.grant_id,
  };
}

export function deviceBootstrapGrantReplayKey(grant: Parameters<typeof deviceBootstrapGrantReplayIdentity>[0]): string {
  return canonicalDeviceJson({
    domain: DEVICE_BOOTSTRAP_GRANT_REPLAY_IDENTITY_DOMAIN,
    ...deviceBootstrapGrantReplayIdentity(grant),
  });
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
 * INCONSISTENT      the recorded times do not describe a possible history —
 *                   an unparseable instant, or a "last verified" that has not
 *                   happened yet (C15-07). Fail-closed: it is not evidence of
 *                   anything, so it vouches for nothing.
 */
export const DeviceAttestationStandingSchema = z.enum([
  'CURRENT',
  'LAST_KNOWN_GOOD',
  'EXPIRED',
  'NEGATIVE',
  'INELIGIBLE',
  'INCONSISTENT',
]);
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

  const instants = parseAuthoritativeInstants({ now: input.now, lastVerified: input.lastVerifiedAt });
  if (instants === null) return { standing: 'INCONSISTENT', lastKnownGoodAgeMs: null };

  const ageMs = instants.now - instants.lastVerified;
  // C15-07: A SERVER-RECORDED VERIFICATION IN THE FUTURE IS NOT FRESH EVIDENCE.
  //
  // This used to clamp a negative age to zero, which read a future timestamp as
  // "verified just now" and handed the device the freshest possible
  // last-known-good standing. That is backwards: the one situation in which a
  // future `lastVerifiedAt` appears is a clock nobody controls or a record
  // somebody wrote — precisely when the value should count for LESS, not more.
  // An impossible history is named as such and vouches for nothing.
  if (ageMs < 0) return { standing: 'INCONSISTENT', lastKnownGoodAgeMs: null };

  // C15-07's exclusive-boundary rule is about `expires_at` — an INSTANT after
  // which a thing is dead. This is the documented exception it allows: the
  // grace is a MAXIMUM AGE, the same kind of ceiling as the lifetime bounds
  // above, and those are inclusive ("must not exceed"). A result exactly as old
  // as the grace has not exceeded it. Treating one boundary as an instant and
  // its sibling as a budget is the only way both read consistently.
  if (ageMs > DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS) {
    return { standing: 'EXPIRED', lastKnownGoodAgeMs: ageMs };
  }
  return { standing: 'LAST_KNOWN_GOOD', lastKnownGoodAgeMs: ageMs };
}

/**
 * The only two standings that can support TRUSTED.
 *
 * EXPIRED cannot: the grace is over and W21-05 requires TRUSTED to fire
 * Whisper, so a device we can no longer vouch for falls back to the loud
 * channels. INELIGIBLE cannot: a first enrollment during an outage has never
 * been verified at all (C14-05). INCONSISTENT cannot: a record that does not
 * describe a possible history is not evidence (C15-07).
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
    refineDeviceInstantWindow(value, context, DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS, 'bootstrap grant');
  });
export type DeviceEnrollmentBootstrapGrant = z.infer<typeof DeviceEnrollmentBootstrapGrantSchema>;

export const DeviceBootstrapGrantStandingSchema = z.enum(['USABLE', 'EXPIRED', 'CONSUMED', 'REVOKED', DEVICE_TIME_NOT_AUTHORITATIVE]);
export type DeviceBootstrapGrantStanding = z.infer<typeof DeviceBootstrapGrantStandingSchema>;

/**
 * Revoked and consumed are checked BEFORE expiry so a burned grant reads as
 * burned rather than as merely old — the audit distinction matters when the
 * second use is an attacker's.
 *
 * C15-07: the expiry boundary is EXCLUSIVE (`now >= expires_at` is expired) and
 * an unreadable clock is `TIME_NOT_AUTHORITATIVE`, which is not `USABLE` — so
 * the commit gate's `!== 'USABLE'` test refuses it without needing to know
 * about it.
 */
export function classifyDeviceBootstrapGrant(grant: DeviceEnrollmentBootstrapGrant, now: string): DeviceBootstrapGrantStanding {
  if (grant.revoked_at !== null) return 'REVOKED';
  if (grant.consumed_at !== null) return 'CONSUMED';
  const instants = parseAuthoritativeInstants({ now, expires: grant.expires_at });
  if (instants === null) return DEVICE_TIME_NOT_AUTHORITATIVE;
  if (isExpiredAt(instants.now, instants.expires)) return 'EXPIRED';
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
    /**
     * C15-01: A CLAIM, NOT AN AUTHORITY.
     *
     * The device says which profile it believes it used. The server decides
     * which profile is in force, and the two are equality-bound before any
     * verification. The name says so, so no future caller can mistake this for
     * the profile that selects a verifier.
     */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    key_storage: DeviceKeyStorageSchema,
    /**
     * C15-02: the ACTUAL key, in the one canonical representation. Without it
     * the registry could recognise this device and never verify it.
     */
    public_key: DeviceP256PublicKeySchema,
    /** Convenience name for the key. Refused unless it equals the DERIVED digest. */
    public_key_thumbprint: DeviceDigestSchema,
    attestation: DeviceAttestationEvidenceSchema,
    requested_at: timestamp,
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
  });
export type DeviceEnrollmentRequest = z.infer<typeof DeviceEnrollmentRequestSchema>;

/**
 * C15-03: THE APPROVAL BINDS THE WHOLE REQUEST.
 *
 * This digest used to bind `attestation.outcome` alone, which meant two
 * MATERIALLY DIFFERENT evidence records — a different `attestation_reference`,
 * or the same outcome evaluated at a different time — produced the SAME
 * fingerprint. A human approving "VERIFIED at 09:00, reference A" was
 * therefore also approving "VERIFIED at 03:00, reference B", including a stale
 * or borrowed evaluation the approver never saw. That is C14-02's own attack
 * surviving inside the field C14-02 did not descend into.
 *
 * So the WHOLE evidence object goes in, spread rather than field-picked. The
 * spread is load-bearing: `DeviceAttestationEvidenceSchema` is `.strict()`, so
 * the object holds exactly its declared fields, and any field added to it in
 * future is bound automatically instead of being silently left outside the
 * approval. `canonicalDeviceJson` sorts keys recursively, so nesting does not
 * make the digest order-dependent.
 *
 * The canonical public key is bound as well as its thumbprint (C15-02) — the
 * key is what the enrollment is ABOUT, and binding only a digest of it would
 * make the approval depend on a value nobody recomputed.
 *
 * `claimed_signature_profile` is bound as the CLAIM it is (C15-01): the
 * approval covers what the device asserted, and the server's own selected
 * profile is bound separately in the possession statement and the commit gate.
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
    claimed_signature_profile: request.claimed_signature_profile,
    key_storage: request.key_storage,
    public_key: request.public_key,
    public_key_thumbprint: request.public_key_thumbprint,
    attestation: { ...request.attestation },
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
    refineDeviceInstantWindow(value, context, DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS, 'possession challenge');
  });
export type DevicePossessionChallenge = z.infer<typeof DevicePossessionChallengeSchema>;

export const DevicePossessionResponseSchema = z
  .object({
    schema_version: z.literal(1),
    challenge_id: scopedId,
    enrollment_request_id: scopedId,
    /** C15-01: a non-authoritative claim, equality-bound to the server's profile. */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /**
     * C15-01: `DeviceSignatureSchema` now runs the full canonical decode, so a
     * high-S, zero-scalar, wrong-length or non-canonical signature cannot exist
     * inside a parsed response at all.
     */
    signature: DeviceSignatureSchema,
    /**
     * CLIENT TELEMETRY. C15-03: freshness is judged on the SERVER's verification
     * instant (`DevicePossessionVerificationResult.verified_at`), never on this.
     * It is retained only so a device's own claim can be recorded and compared.
     */
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
  /**
   * C15-01: THE SERVER'S SELECTED PROFILE, never the device's claim.
   *
   * It is bound into the signed bytes so the statement means "signed under the
   * profile the platform chose". A statement binding the client's field would
   * let a device sign under one profile while the server verified under
   * another, and the signature would still be over bytes both agreed on.
   */
  readonly signature_profile: DeviceSignatureProfile;
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
    signature_profile: input.signature_profile,
  });
}

export function devicePossessionStatementFingerprint(input: DevicePossessionStatementInput): string {
  return sha256Hex(canonicalDevicePossessionStatement(input));
}

/**
 * C15-03: PROOF OF POSSESSION IS A BOUND SERVER VERDICT, NOT A BOOLEAN.
 *
 * The commit gate used to take `possessionVerified: boolean` plus a
 * device-supplied `possessionAnsweredAt`. A bare `true` says nothing about
 * WHICH challenge, WHICH key or WHICH statement it was produced for, so a
 * genuine `true` from one ceremony could be handed to another — and the
 * freshness it was judged on came from the device.
 *
 * This structure makes that borrowing impossible. Every field the verdict
 * depended on travels WITH the verdict, and the commit gate checks each one
 * equals the corresponding approved value. A verification result for a
 * different challenge, a different key or different bytes is then visibly a
 * result about something else, rather than an indistinguishable `true`.
 *
 * `source` is a literal and there is no device-populatable field: this is
 * Sentinel's own verdict about Sentinel's own check.
 */
export const DevicePossessionVerificationResultSchema = z
  .object({
    schema_version: z.literal(1),
    source: z.literal('SENTINEL_SERVER_VERIFICATION'),
    /** The server's answer. `false` is a real, recordable verdict. */
    verified: z.boolean(),
    challenge_id: scopedId,
    enrollment_request_id: scopedId,
    /** The fingerprint of the request this verdict was produced against. */
    enrollment_request_fingerprint: DeviceDigestSchema,
    /** The APPROVED key's identity, so a verdict for another key cannot be borrowed. */
    public_key_thumbprint: DeviceDigestSchema,
    /** The exact canonical possession statement the signature was checked over. */
    possession_statement_fingerprint: DeviceDigestSchema,
    /** The SERVER-selected profile the check ran under (C15-01). */
    signature_profile: DeviceSignatureProfileSchema,
    /** THE SERVER'S verification instant. This, and not `answered_at`, is freshness. */
    verified_at: timestamp,
  })
  .strict();
export type DevicePossessionVerificationResult = z.infer<typeof DevicePossessionVerificationResultSchema>;

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
  /** C15-05: the grant's one-shot identity was presented again with new meaning. */
  'BOOTSTRAP_GRANT_REUSED',
  /** C15-05: the consumption fact handed in is about some other grant. */
  'BOOTSTRAP_CONSUMPTION_MISBOUND',
  'REQUEST_EXPIRED',
  /** C15-07: the request claims to have been made in the future. */
  'REQUEST_NOT_YET_MADE',
  'APPROVAL_MISSING',
  'APPROVAL_FINGERPRINT_MISMATCH',
  /** C15-07: the approval claims to have happened in the future. */
  'APPROVAL_NOT_YET_MADE',
  'USER_NOT_AUTHENTICATED',
  'USER_NOT_INTENDED',
  'CHALLENGE_MISSING',
  'CHALLENGE_MISBOUND',
  'CHALLENGE_EXPIRED',
  /** C15-07: the challenge claims to have been issued in the future. */
  'CHALLENGE_NOT_YET_ISSUED',
  /** C15-05: the challenge's one-shot identity was presented again with new meaning. */
  'CHALLENGE_REUSED',
  /** C15-05: the consumption fact handed in is about some other challenge. */
  'CHALLENGE_CONSUMPTION_MISBOUND',
  'POSSESSION_NOT_PROVEN',
  /** C15-03: no server verdict at all. A missing verdict is never a passing one. */
  'POSSESSION_VERIFICATION_MISSING',
  /** C15-03: a genuine verdict, produced for a DIFFERENT ceremony. */
  'POSSESSION_VERIFICATION_MISBOUND',
  /** C15-03: the verdict covered different bytes than this request's statement. */
  'POSSESSION_STATEMENT_MISMATCH',
  /** C15-01/C15-03: the verdict ran under a profile the server did not select. */
  'POSSESSION_PROFILE_MISMATCH',
  /** C15-01: the request's claimed profile is not the server-selected one. */
  'SIGNATURE_PROFILE_CLAIM_MISMATCH',
  /** C15-07: an instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
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
   * C15-03: the SERVER's verdict, carrying everything it was bound to. `null`
   * models "the server never checked", which refuses — a missing verdict is
   * never a passing one.
   */
  readonly possessionVerification: DevicePossessionVerificationResult | null;
  /**
   * C15-01: the profile the SERVER selected for this enrollment. The request's
   * `claimed_signature_profile` is equality-bound to it, and the possession
   * statement binds it rather than the claim.
   */
  readonly serverSelectedSignatureProfile: DeviceSignatureProfile;
  /**
   * C15-05: the store's report on the bootstrap grant's one-shot identity.
   * REQUIRED — there is no default, because an evaluator that can be called
   * without it admits a replayed grant whenever a caller forgets.
   */
  readonly grantConsumption: DeviceNonceConsumption;
  /** C15-05: the store's report on the possession challenge's one-shot identity. */
  readonly challengeConsumption: DeviceNonceConsumption;
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
  /**
   * C15-05: a byte-identical retry of one ceremony. It causes NO second
   * enrollment; the caller converges on the outcome already recorded.
   */
  | { readonly decision: 'CONVERGE'; readonly enrollment_request_fingerprint: string; readonly stored_outcome_ref: string }
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
  const fingerprint = deviceEnrollmentRequestFingerprint(request);

  // 0. C15-01: the server chooses the profile. A request claiming a different
  //    one is refused here, before anything is verified under either.
  const profileBinding = bindClaimedSignatureProfile(request.claimed_signature_profile, input.serverSelectedSignatureProfile);
  if (!profileBinding.bound) return { decision: 'REFUSE', refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' };

  // 1. The grant.
  if (input.grant === null) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_MISSING' };
  if (input.grant.grant_id !== request.bootstrap_grant_id) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_SCOPE_MISMATCH' };
  const grantStanding = classifyDeviceBootstrapGrant(input.grant, input.now);
  // C15-07: an unreadable clock is named as such rather than being reported as
  // a property of the grant — the grant is fine; our clock is not.
  if (grantStanding === DEVICE_TIME_NOT_AUTHORITATIVE) return { decision: 'REFUSE', refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  if (grantStanding !== 'USABLE') return { decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_UNUSABLE' };
  if (!bootstrapGrantMatchesScope(input.grant, request)) return { decision: 'REFUSE', refusal: 'BOOTSTRAP_SCOPE_MISMATCH' };

  // C15-05: D23-04's `single_use: true` enforced rather than promised. The fact
  //   must be ABOUT this grant, and reuse under new meaning is a conflict.
  const grantReplayKey = deviceBootstrapGrantReplayKey({
    organisation_id: input.grant.organisation_id,
    site_id: input.grant.site_id,
    intended_user_id: input.grant.intended_user_id,
    grant_id: input.grant.grant_id,
  });
  if (input.grantConsumption.replay_key !== grantReplayKey || input.grantConsumption.statement_fingerprint !== fingerprint) {
    return { decision: 'REFUSE', refusal: 'BOOTSTRAP_CONSUMPTION_MISBOUND' };
  }
  if (input.grantConsumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_REUSED' };
  }

  // C15-07: every instant this decision turns on, parsed once, fail-closed.
  const instants = parseAuthoritativeInstants({ now: input.now, requested: request.requested_at });
  if (instants === null) return { decision: 'REFUSE', refusal: DEVICE_TIME_NOT_AUTHORITATIVE };

  // The request itself must still be live — and must not claim to come from the
  // future, which would otherwise buy an attacker an arbitrarily long window.
  const requestAgeMs = instants.now - instants.requested;
  if (requestAgeMs < 0) return { decision: 'REFUSE', refusal: 'REQUEST_NOT_YET_MADE' };
  if (requestAgeMs > DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS) return { decision: 'REFUSE', refusal: 'REQUEST_EXPIRED' };

  // 2. The approval, bound to the exact request fingerprint.
  if (input.approval === null) return { decision: 'REFUSE', refusal: 'APPROVAL_MISSING' };
  if (!approvalMatchesEnrollmentRequest(input.approval, request)) {
    return { decision: 'REFUSE', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' };
  }
  const approvalInstants = parseAuthoritativeInstants({ approved: input.approval.approved_at });
  if (approvalInstants === null) return { decision: 'REFUSE', refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  if (approvalInstants.approved > instants.now) return { decision: 'REFUSE', refusal: 'APPROVAL_NOT_YET_MADE' };

  // 3. The intended user, authenticated now.
  if (input.authenticatedUserId === null) return { decision: 'REFUSE', refusal: 'USER_NOT_AUTHENTICATED' };
  if (input.authenticatedUserId !== request.intended_user_id) return { decision: 'REFUSE', refusal: 'USER_NOT_INTENDED' };

  // 4. A fresh challenge, answered by the approved key.
  if (input.challenge === null) return { decision: 'REFUSE', refusal: 'CHALLENGE_MISSING' };
  if (input.challenge.enrollment_request_id !== request.enrollment_request_id) {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_MISBOUND' };
  }

  // C15-05: the challenge is one-shot too.
  const challengeReplayKey = devicePossessionChallengeReplayKey({
    organisation_id: request.organisation_id,
    site_id: request.site_id,
    intended_user_id: request.intended_user_id,
    enrollment_request_id: request.enrollment_request_id,
    challenge_id: input.challenge.challenge_id,
    nonce: input.challenge.nonce,
  });
  if (input.challengeConsumption.replay_key !== challengeReplayKey || input.challengeConsumption.statement_fingerprint !== fingerprint) {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_CONSUMPTION_MISBOUND' };
  }
  if (input.challengeConsumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
    return { decision: 'REFUSE', refusal: 'CHALLENGE_REUSED' };
  }

  // 5. C15-03: the server's possession verdict, bound to THIS ceremony.
  const verification = input.possessionVerification;
  if (verification === null) return { decision: 'REFUSE', refusal: 'POSSESSION_VERIFICATION_MISSING' };
  // Identity first: a genuine `verified: true` produced for a different
  // challenge, a different request or a different key is a result about
  // something else, and must not be borrowable.
  if (
    verification.challenge_id !== input.challenge.challenge_id ||
    verification.enrollment_request_id !== request.enrollment_request_id ||
    verification.enrollment_request_fingerprint !== fingerprint ||
    verification.public_key_thumbprint !== request.public_key_thumbprint
  ) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_VERIFICATION_MISBOUND' };
  }
  // The verdict must have covered exactly the bytes this ceremony defines.
  const expectedStatementFingerprint = devicePossessionStatementFingerprint({
    challenge_id: input.challenge.challenge_id,
    enrollment_request_id: request.enrollment_request_id,
    enrollment_request_fingerprint: fingerprint,
    nonce: input.challenge.nonce,
    public_key_thumbprint: request.public_key_thumbprint,
    signature_profile: profileBinding.profile,
  });
  if (verification.possession_statement_fingerprint !== expectedStatementFingerprint) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_STATEMENT_MISMATCH' };
  }
  if (verification.signature_profile !== profileBinding.profile) {
    return { decision: 'REFUSE', refusal: 'POSSESSION_PROFILE_MISMATCH' };
  }

  // C15-03/C15-07: freshness on the SERVER's verification instant, judged
  // against the challenge window. `answered_at` — the device's claim — is not
  // read anywhere in this function.
  const window = parseAuthoritativeInstants({
    verified: verification.verified_at,
    issued: input.challenge.issued_at,
    expires: input.challenge.expires_at,
  });
  if (window === null) return { decision: 'REFUSE', refusal: DEVICE_TIME_NOT_AUTHORITATIVE };
  if (window.issued > instants.now) return { decision: 'REFUSE', refusal: 'CHALLENGE_NOT_YET_ISSUED' };
  // Verification cannot precede the issuance of the thing it verified.
  if (window.verified < window.issued) return { decision: 'REFUSE', refusal: 'CHALLENGE_NOT_YET_ISSUED' };
  if (isExpiredAt(window.verified, window.expires)) return { decision: 'REFUSE', refusal: 'CHALLENGE_EXPIRED' };

  if (!verification.verified) return { decision: 'REFUSE', refusal: 'POSSESSION_NOT_PROVEN' };

  // C15-05: an exact retry converges on what already happened rather than
  // enrolling a second device off one ceremony.
  if (input.challengeConsumption.outcome === 'EXACT_DUPLICATE' || input.grantConsumption.outcome === 'EXACT_DUPLICATE') {
    const storedOutcomeRef = input.challengeConsumption.stored_outcome_ref ?? input.grantConsumption.stored_outcome_ref;
    if (storedOutcomeRef !== null) {
      return { decision: 'CONVERGE', enrollment_request_fingerprint: fingerprint, stored_outcome_ref: storedOutcomeRef };
    }
  }

  return { decision: 'COMMIT', enrollment_request_fingerprint: fingerprint };
}

/**
 * D23-03 + C14-05 + C15-08: what trust a freshly committed enrollment starts at.
 *
 * TRUSTED requires BOTH a hardware-backed key and a CURRENT verified
 * attestation. A first enrollment during a provider outage has no prior
 * verified result to ride, so its standing is INELIGIBLE and it starts
 * DEGRADED — it can operate every ordinary path and simply cannot fire Whisper
 * until verification returns.
 *
 * C15-08: LAST_KNOWN_GOOD IS NOT AN INHERITANCE.
 *
 * This used to accept LAST_KNOWN_GOOD, reasoning that "a re-enrollment during
 * an outage should behave like a live device". It should not. D23-09 is
 * explicit that a re-enrollment produces a NEW IDENTITY — new device_id, new
 * key, fresh sequence namespace — and last-known-good is precisely a statement
 * of CONTINUITY: it says "this device was verified before, and the provider is
 * merely unreachable now". A new identity has no "before". Admitting
 * LAST_KNOWN_GOOD here let a brand-new identity, created during an outage,
 * inherit the standing the OLD identity earned and start life TRUSTED — the
 * fastest route to a Whisper-capable credential being a wipe and re-enrol
 * while the attestation provider happens to be down.
 *
 * LAST_KNOWN_GOOD still supports the continuity of an ALREADY-ESTABLISHED
 * identity: `evaluateDeviceTrustTransition` accepts it, because there the
 * device being vouched for is the same device that earned the result.
 */
export function initialDeviceTrustOnEnrollment(input: {
  readonly keyStorage: DeviceKeyStorage;
  readonly attestationStanding: DeviceAttestationStanding;
}): DeviceTrust {
  if (input.attestationStanding === 'NEGATIVE') return 'QUARANTINED';
  if (!deviceKeyStoragePermitsTrusted(input.keyStorage)) return 'DEGRADED';
  return input.attestationStanding === 'CURRENT' ? 'TRUSTED' : 'DEGRADED';
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
  .strict()
  .superRefine((value, context) => {
    // C15-08: DERIVED MEANS DERIVED.
    //
    // "Derived, never supplied" was a comment on a field that accepted any
    // string, so an arbitrary namespace could be written straight into an
    // identity — which is exactly the sequence-namespace reset D23-09 says does
    // not exist, arriving through the front door rather than through
    // `classifyDeviceKeyChange`. The contract now recomputes it and refuses.
    const derived = deviceSequenceNamespaceId(value);
    if (value.sequence_namespace_id !== derived) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['sequence_namespace_id'],
        message: 'sequence_namespace_id must equal the value derived from organisation_id and device_id',
      });
    }
    // C15-08 / D23-03: an impossible combination must fail to PARSE, not merely
    // fail a later check. A TRUSTED credential on a software-backed key is the
    // state D23-03 exists to forbid; if it can be constructed it will
    // eventually be constructed.
    if (value.trust === 'TRUSTED' && !deviceKeyStoragePermitsTrusted(value.key.key_storage)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['trust'],
        message: 'a TRUSTED identity requires a hardware-backed key (D23-03)',
      });
    }
  });
export type DeviceIdentity = z.infer<typeof DeviceIdentitySchema>;

/**
 * C15-08: THE CUSTODY ASSOCIATION, AS A CONTRACT.
 *
 * WP-23 stated the custody rules in prose and left WP-24 to invent the shape it
 * would persist. Prose does not constrain a migration. This locks it: which
 * human a PERSONAL device is assigned to, which named régime governs a
 * CONTROLLED_SHARED one, and which sites the device is bound to.
 *
 * The two custody modes have MUTUALLY EXCLUSIVE shapes, enforced rather than
 * described. A PERSONAL device names its operative and no régime; a
 * CONTROLLED_SHARED device names its régime and no single operative — because a
 * shared device with a permanent assignee is the fusion of custody into
 * identity that C14-02 forbids, and a personal device under a shared régime is
 * an accountability gap wearing a policy's name.
 *
 * NONE OF THIS IS LIVE AUTHORITY. The association records who the device is FOR
 * and where it belongs; every authorisation question is still answered from the
 * current session and current entitlement (C14-02, C15-04).
 */
export const DeviceCustodyAssociationSchema = z
  .object({
    schema_version: z.literal(1),
    organisation_id: scopedId,
    device_id: scopedId,
    custody: DeviceCustodySchema,
    /** PERSONAL only: the operative this device is assigned to. */
    assigned_user_id: scopedId.nullable(),
    /** CONTROLLED_SHARED only: the named custody régime governing hand-over. */
    custody_regime_id: scopedId.nullable(),
    /** The sites this device is bound to. At least one; a device belongs somewhere. */
    associated_site_ids: z.array(scopedId).min(1).max(256),
    associated_at: timestamp,
    /** Set when the association ends. A released device is bound to nothing. */
    released_at: timestamp.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.custody === 'PERSONAL') {
      if (value.assigned_user_id === null) {
        context.addIssue({ code: z.ZodIssueCode.custom, path: ['assigned_user_id'], message: 'a PERSONAL device names the operative it is assigned to' });
      }
      if (value.custody_regime_id !== null) {
        context.addIssue({ code: z.ZodIssueCode.custom, path: ['custody_regime_id'], message: 'a PERSONAL device is not governed by a shared custody régime' });
      }
    } else {
      if (value.assigned_user_id !== null) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['assigned_user_id'],
          message: 'a CONTROLLED_SHARED device has no permanent assignee (C14-02: custody is not identity)',
        });
      }
      if (value.custody_regime_id === null) {
        context.addIssue({ code: z.ZodIssueCode.custom, path: ['custody_regime_id'], message: 'a CONTROLLED_SHARED device names the régime governing hand-over' });
      }
    }
    if (new Set(value.associated_site_ids).size !== value.associated_site_ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['associated_site_ids'], message: 'associated_site_ids must be unique' });
    }
  });
export type DeviceCustodyAssociation = z.infer<typeof DeviceCustodyAssociationSchema>;

/** Is this device bound to that site, and is the association still live? */
export function deviceCustodyAssociationBindsSite(association: DeviceCustodyAssociation, site_id: string): boolean {
  return association.released_at === null && association.associated_site_ids.includes(site_id);
}

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
