/**
 * WP-24 Shield device registry constants (directive D24-01..D24-15).
 *
 * Everything here is either a §62 action string, a persisted enumeration
 * value, or a name for a ceremony. Every RULE this module obeys lives in
 * `packages/contracts/src/device-*.ts` and is IMPORTED, never restated
 * (D24-01) — so there is deliberately no timing ceiling, no trust matrix and
 * no lifecycle table in this file. If a constant here ever starts to look like
 * a policy, it is in the wrong place.
 */

// ---------------------------------------------------------------------------
// §62 device-security authority (D24-02 / D24-02a / D24-02b)
// ---------------------------------------------------------------------------

/**
 * The seven actions, as they appear in `identity/roles.ts`. They are named
 * constants here for the reason WP-20's executor names its own: a service that
 * spells an action inline can drift from the registry by one character and
 * fail open, and nothing would notice.
 *
 * D24-02's three riding rules are enforced by the ROLE TABLE, not by this
 * file: `admin` appears in none of these grants, a device's intended user
 * gains nothing from being named on it, and an internal machine lookup is not
 * modelled as a human `device.registry.read` at all.
 */
export const ACTION_DEVICE_REGISTRY_READ = 'device.registry.read';
export const ACTION_DEVICE_ENROLLMENT_ISSUE = 'device.enrollment.issue';
export const ACTION_DEVICE_ENROLLMENT_APPROVE = 'device.enrollment.approve';
export const ACTION_DEVICE_TRUST_MANAGE = 'device.trust.manage';
export const ACTION_DEVICE_KEY_ROTATE = 'device.key.rotate';
export const ACTION_DEVICE_REVOKE = 'device.revoke';

/**
 * D24-02b: NOT an invention of this work package.
 *
 * `DEVICE_TRUST_RESTORATION_CAPABILITY` in `device-identity.ts` already fixes
 * this exact string, and `evaluateDeviceTrustTransition` refuses a controlled
 * restoration whose decision carries any other value. The action is re-exported
 * from the contract rather than re-typed so the two can never drift.
 */
export { DEVICE_TRUST_RESTORATION_CAPABILITY as ACTION_DEVICE_TRUST_RESTORE } from '@sentinel/contracts';

import { DEVICE_SIGNATURE_PROFILES, type DeviceSignatureProfile } from '@sentinel/contracts';

// ---------------------------------------------------------------------------
// Bootstrap grant secret (D24-03a)
// ---------------------------------------------------------------------------

/**
 * D24-03a's entropy floor, in bytes. 32 bytes is 256 bits, which is the rule
 * the directive states rather than a number chosen here; it is expressed in
 * bytes because `randomBytes` takes bytes and a conversion in the call site is
 * a conversion that can be got wrong.
 *
 * The secret is returned to the issuing caller EXACTLY ONCE and persisted only
 * as `tokenDigest`. It never enters a log, a security-event payload or an
 * error message — `device-security-audit.ts` has no builder that can carry it.
 */
export const BOOTSTRAP_TOKEN_ENTROPY_BYTES = 32;

/** The one digest recipe for the bootstrap token: SHA-256, lowercase hex. */
export const BOOTSTRAP_TOKEN_DIGEST_ALGORITHM = 'sha256';

/**
 * Possession and rotation challenge nonce size, in bytes.
 *
 * `DeviceNonceSchema` bounds a nonce at 16..256 characters and says nothing
 * about how it is generated, because generation is I/O and I/O does not belong
 * in contracts. This is the runtime's answer: 32 random bytes, base64url, 43
 * characters — comfortably inside the contract bound and far above the point
 * where a nonce could be guessed inside a two-minute challenge window.
 */
export const CHALLENGE_NONCE_ENTROPY_BYTES = 32;

// ---------------------------------------------------------------------------
// Ceremony names for the durable replay table (D24-11)
// ---------------------------------------------------------------------------

/**
 * `DeviceNonceConsumption.ceremony` is a LABEL, never a key.
 *
 * The unique constraint is `(organisation_id, replay_identity_digest)` and the
 * digest is taken over the CONTRACT's canonical replay key, which is already
 * domain-separated per ceremony. This column exists so an operator reading the
 * table can tell at a glance which ceremony burned an identity; adding it to
 * the uniqueness would let one ceremony's row hide another's, which is the
 * exact detection D24-11 says the row exists to perform.
 */
export const CEREMONY_BOOTSTRAP_GRANT = 'BOOTSTRAP_GRANT';
export const CEREMONY_POSSESSION_CHALLENGE = 'POSSESSION_CHALLENGE';
export const CEREMONY_KEY_ROTATION = 'KEY_ROTATION';

// ---------------------------------------------------------------------------
// Persisted lifecycle values that are NOT contract enumerations
// ---------------------------------------------------------------------------

/**
 * The rotation request's own state column.
 *
 * `DEVICE_ENROLLMENT_STATES` covers the enrollment ceremony and is imported
 * for `EnrollmentRequest.state`. Rotation has no contract state machine — the
 * ceremony is judged in one shot by `evaluateDeviceKeyRotation` — so these
 * three values describe only how far the SERVER has got, and no decision is
 * ever taken from them alone.
 */
export const ROTATION_STATE_REQUESTED = 'REQUESTED';
export const ROTATION_STATE_CHALLENGED = 'CHALLENGED';
export const ROTATION_STATE_ROTATED = 'ROTATED';

/**
 * The `previous_trust` written on the FIRST trust record of a device's life.
 *
 * A newly enrolled device has no previous trust: the six-state vocabulary
 * describes a REGISTERED device, and there is no "not yet enrolled" member of
 * it. Writing one of the six here would claim a transition that never
 * happened, and `ALLOWED_DEVICE_TRUST_TRANSITIONS` has no self-edges, so it
 * would also be a transition the contract forbids.
 *
 * So the initial record names this sentinel and is produced by
 * `initialDeviceTrustOnEnrollment` — NOT by `evaluateDeviceTrustTransition`,
 * which is the evaluator for movement between two real states. Every
 * subsequent change goes through the transition evaluator without exception.
 */
export const DEVICE_TRUST_PREVIOUS_NONE = 'NONE';

/** The reason code on that first record, so it is greppable as what it is. */
export const TRUST_REASON_ENROLLMENT_INITIAL = 'ENROLLMENT_INITIAL_TRUST';

// ---------------------------------------------------------------------------
// Security event types (D24-12)
// ---------------------------------------------------------------------------

/**
 * The eighteen event types D24-12 enumerates, as a frozen tuple.
 *
 * A tuple rather than eighteen loose strings so `device-security-audit.ts` can
 * key its payload allowlist by type and the compiler can prove every member
 * has a builder. A nineteenth event added without a builder will not compile.
 */
export const DEVICE_SECURITY_EVENT_TYPES = [
  'BOOTSTRAP_ISSUED',
  'BOOTSTRAP_REVOKED',
  'BOOTSTRAP_CONSUMED',
  'BOOTSTRAP_REPLAY_REFUSED',
  'ENROLLMENT_REQUESTED',
  'ENROLLMENT_APPROVED',
  'ENROLLMENT_REFUSED',
  'POSSESSION_VERIFIED',
  'DEVICE_ENROLLED',
  'TRUST_CHANGED',
  'DEVICE_QUARANTINED',
  'DEVICE_LOST',
  'DEVICE_STOLEN',
  'DEVICE_REVOKED',
  'KEY_ROTATED',
  'KEY_REVOKED',
  'KEY_COMPROMISED',
  'REPLAY_CONFLICT',
] as const;

export type DeviceSecurityEventType = (typeof DEVICE_SECURITY_EVENT_TYPES)[number];

// ---------------------------------------------------------------------------
// The server-selected signature profile (C15-01 / D24-05)
// ---------------------------------------------------------------------------

/**
 * The profile the SERVER selects for a key it is registering for the first
 * time.
 *
 * C15-01's rule is that the authority on a profile is the server's registry
 * record for `key_id + key_version`, and every `claimed_signature_profile` is
 * equality-bound to it before verification. That rule answers "which profile
 * governs an EXISTING key" — it is read from `DeviceKey.signatureProfile`.
 * This constant answers the one question the registry cannot: which profile a
 * key gets when it has no record yet.
 *
 * It is READ FROM the contract's own allowlist rather than retyped, so the two
 * cannot drift. `DEVICE_SIGNATURE_PROFILES` has exactly one member today and
 * the contract says why: "an allowlist with a single member is still an
 * allowlist, and adding a second is a visible diff that has to argue for
 * itself". If a second is ever added, THIS line is one of the places that diff
 * must argue about, because selecting index 0 would then be a policy rather
 * than a restatement.
 */
export const SERVER_SELECTED_SIGNATURE_PROFILE: DeviceSignatureProfile = DEVICE_SIGNATURE_PROFILES[0];
