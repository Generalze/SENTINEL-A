/**
 * WP-26 device enrollment ingress constants (directive D26-01..D26-11).
 *
 * Everything here is either a timing ceiling this work package OWNS, a name for
 * a version, or a platform vocabulary value Android itself defines. Every RULE
 * this module obeys about enrollment, trust, custody or signatures lives in
 * `packages/contracts/src/device-*.ts` and is IMPORTED, never restated (D24-01,
 * D25-12) — so there is deliberately no trust matrix, no lifecycle table and no
 * enrollment ceiling in this file. If a constant here ever starts to look like
 * a policy the contracts should own, it is in the wrong place.
 */

// ---------------------------------------------------------------------------
// D26-04A — the attestation challenge
// ---------------------------------------------------------------------------

/**
 * THE MAXIMUM LIFETIME OF A D26-04A ATTESTATION CHALLENGE, IN MILLISECONDS.
 *
 * ITS OWN NAME, AND DELIBERATELY NOT SHARED WITH ANYTHING.
 *
 * It is numerically equal to `DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS` and to
 * `DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS` today, and it is a SEPARATE
 * constant for the reason D24-10A gives for keeping rotation policy and
 * enrollment policy apart: two windows that happen to agree are not one window,
 * and a shared constant is how a change to one silently becomes a change to
 * three. This one governs the interval between "the server issued a nonce" and
 * "the phone finished generating a StrongBox key against it and submitted the
 * certificate", which is a different physical process from signing a challenge
 * with a key that already exists.
 *
 * The boundary is EXCLUSIVE, per the WP-23/WP-24/WP-25 doctrine: at exactly
 * `expires_at` the challenge is dead.
 *
 * WHAT AN EXPIRY MEANS HERE. The phone discards the unfinished key and starts
 * the attestation step again with a fresh challenge. An old attestation is NOT
 * accepted merely because the bootstrap grant still has time left — the two
 * windows are independent bounds and the challenge is additionally CLAMPED so
 * it can never outlive the grant.
 */
export const DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS = 120_000;

/**
 * The attestation challenge's entropy, in bytes. 32 bytes is 256 bits, which is
 * the floor D26-04A states rather than a number chosen here; it is expressed in
 * bytes because `randomBytes` takes bytes and a conversion at the call site is
 * a conversion that can be got wrong.
 *
 * THIS VALUE IS NOT A SECRET. It is a FRESHNESS VALUE: the server hands it to
 * the phone in the clear, the phone embeds it in an attestation certificate
 * that anyone holding the device could read, and possession of it authorises
 * precisely nothing. The entropy is there so that the value cannot be PREDICTED
 * — a challenge an attacker can guess in advance is a challenge they can have a
 * key pre-generated against, which is the exact replay D26-04A exists to close.
 */
export const ATTESTATION_CHALLENGE_ENTROPY_BYTES = 32;

// ---------------------------------------------------------------------------
// D26-04B — the verifier and its trust material
// ---------------------------------------------------------------------------

/**
 * The identity of the verifier that produced a verdict, recorded on every
 * artifact.
 *
 * A verdict is only meaningful relative to the code that reached it. When the
 * rules below change, this string changes with them, so a stored artifact can
 * always be read as "this is what THAT verifier concluded" rather than as an
 * assertion floating free of its implementation.
 */
export const ANDROID_KEY_ATTESTATION_VERIFIER_VERSION = 'wp26.android-key-attestation.v1';

/**
 * How long a revocation snapshot may be relied on, in milliseconds.
 *
 * Exclusive boundary. Past it the snapshot is STALE, and C14-05 is unambiguous
 * about what stale means: `UNAVAILABLE`, never "assume not revoked". Twenty-four
 * hours is chosen as the shortest interval a deployment can realistically keep
 * up with while still being short enough that a revoked attestation key cannot
 * quietly keep vouching for hardware for days. It is this module's own bound and
 * belongs to no contract.
 */
export const ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS = 86_400_000;

/**
 * The maximum number of certificates a submitted chain may contain.
 *
 * A real Android Key Attestation chain is four certificates and occasionally
 * five. The bound exists so that an unauthenticated pre-registration surface
 * cannot be made to do unbounded signature verification by anyone who can open
 * a session, which is the ordinary shape of a cryptographic denial-of-service.
 */
export const MAX_ATTESTATION_CHAIN_LENGTH = 8;

/**
 * The maximum size of ONE submitted certificate, in bytes, before base64
 * decoding.
 *
 * Same reasoning as the chain-length bound, one level down: a single enormous
 * "certificate" must be refused by a length check rather than by a DER parser
 * discovering it the slow way.
 */
export const MAX_ATTESTATION_CERTIFICATE_BASE64_LENGTH = 8192;

// ---------------------------------------------------------------------------
// The Android platform's own vocabularies (D26-04B)
//
// These are ANDROID's numbers, not Sentinel's. They are named here so the
// verifier compares against a word rather than against a bare integer, and so
// that a reviewer checking them against the platform documentation has one
// place to look.
// ---------------------------------------------------------------------------

/** `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }`. */
export const ANDROID_SECURITY_LEVEL_SOFTWARE = 0;
export const ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
export const ANDROID_SECURITY_LEVEL_STRONGBOX = 2;

/** `Algorithm`: EC is 3. WP-26's profile is P-256 ECDSA and nothing else (C14-01). */
export const ANDROID_KEY_ALGORITHM_EC = 3;

/** `EcCurve`: P_256 is 1. */
export const ANDROID_EC_CURVE_P256 = 1;

/** The key size WP-26's signature profile fixes. */
export const ANDROID_KEY_SIZE_P256 = 256;

/** `KeyPurpose`: SIGN is 2, VERIFY is 3. Everything else is another kind of key. */
export const ANDROID_KEY_PURPOSE_SIGN = 2;
export const ANDROID_KEY_PURPOSE_VERIFY = 3;

/**
 * `KeyOrigin`: GENERATED is 0.
 *
 * D26-02's whole point in one integer. `IMPORTED` (2) means key material
 * arrived from outside the secure hardware, which means it EXISTED outside the
 * secure hardware, which means the non-exportability guarantee never held. A
 * StrongBox certificate for an imported key attests to storage, not to origin,
 * and WP-26 is asking about origin.
 */
export const ANDROID_KEY_ORIGIN_GENERATED = 0;

/** `VerifiedBootState`: Verified is 0. */
export const ANDROID_VERIFIED_BOOT_STATE_VERIFIED = 0;
