import { z } from 'zod';

/**
 * WP-23 / C14-01 — the M3 physical-device signature profile.
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * Whisper v1 pins Ed25519 and stays exactly as Milestone 2 shipped it. But a
 * TRUSTED device must hold its private key in hardware-backed storage, and the
 * mainstream mobile keystores guarantee P-256: Secure Enclave signs P-256, and
 * StrongBox guarantees ECDSA/ECDH P-256 among its hardware-backed algorithms.
 * Neither offers an equivalent hardware-backed Ed25519 path. Requiring a
 * hardware key AND Ed25519 therefore made Proof C unreachable on the target
 * platform — so M3 versions FORWARD with its own profile rather than
 * reinterpreting v1.
 *
 * WHAT THIS MODULE IS NOT
 * -----------------------
 * It performs no cryptography. It defines the exact bytes a signature is
 * allowed to be, and refuses everything else *before* any verifier is entered.
 * The actual curve arithmetic belongs to the runtime (WP-25/WP-27) against a
 * key resolved from the server registry by `key_id + key_version` — never an
 * algorithm the client named.
 */

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

/**
 * The approved profiles. One entry, deliberately: an allowlist with a single
 * member is still an allowlist, and adding a second is a visible diff that has
 * to argue for itself.
 */
export const DEVICE_SIGNATURE_PROFILES = ['P256_ECDSA_SHA256'] as const;
export const DeviceSignatureProfileSchema = z.enum(DEVICE_SIGNATURE_PROFILES);
export type DeviceSignatureProfile = z.infer<typeof DeviceSignatureProfileSchema>;

/**
 * The client never names the algorithm — that is C11-04's lesson carried into
 * M3. The profile travels only so a mismatch is refused at the contract
 * boundary; the verifier is chosen by the server from the registry entry for
 * `key_id + key_version`.
 */
export function isApprovedDeviceSignatureProfile(value: unknown): value is DeviceSignatureProfile {
  return DeviceSignatureProfileSchema.safeParse(value).success;
}

// ---------------------------------------------------------------------------
// Curve constants
// ---------------------------------------------------------------------------

/** Order of the P-256 base point. */
export const P256_CURVE_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

/** floor(n/2). A signature is low-S when `s <= this`. */
export const P256_HALF_CURVE_ORDER = BigInt('0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8');

/** IEEE P1363 raw form: r (32 bytes) || s (32 bytes). */
export const P256_SCALAR_BYTES = 32;
export const P256_SIGNATURE_BYTES = P256_SCALAR_BYTES * 2;

/** 64 bytes encode to exactly 86 base64url characters with no padding. */
export const P256_SIGNATURE_BASE64URL_LENGTH = 86;

// ---------------------------------------------------------------------------
// Rejection vocabulary
// ---------------------------------------------------------------------------

/**
 * Every way a signature can be refused before verification. These are internal
 * audit granularity: a device-facing surface must collapse them, because
 * telling a caller *which* malformation it produced is a free oracle.
 */
export const DeviceSignatureRejectionSchema = z.enum([
  'ENCODING_NOT_BASE64URL',
  'ENCODING_PADDED',
  'ENCODING_NOT_CANONICAL',
  'WRONG_LENGTH',
  'R_OUT_OF_RANGE',
  'S_OUT_OF_RANGE',
  'S_NOT_LOW',
]);
export type DeviceSignatureRejection = z.infer<typeof DeviceSignatureRejectionSchema>;

export interface DeviceSignatureScalars {
  readonly r: bigint;
  readonly s: bigint;
  readonly bytes: Uint8Array;
}

export type DeviceSignatureDecodeResult =
  | { readonly ok: true; readonly scalars: DeviceSignatureScalars }
  | { readonly ok: false; readonly rejection: DeviceSignatureRejection };

/**
 * The wire form. Length is pinned here as well as in the decoder so a malformed
 * value is refused by the schema before any decode is attempted.
 */
export const DeviceSignatureSchema = z
  .string()
  .length(P256_SIGNATURE_BASE64URL_LENGTH)
  .regex(/^[A-Za-z0-9_-]+$/u, 'signature must be canonical unpadded base64url');

// ---------------------------------------------------------------------------
// Canonical decoding
// ---------------------------------------------------------------------------

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToScalarBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(P256_SCALAR_BYTES);
  let remaining = value;
  for (let index = P256_SCALAR_BYTES - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

/**
 * C14-01: exactly one accepted representation.
 *
 * IEEE P1363 raw `r || s`, 64 bytes, as canonical unpadded base64url. **DER is
 * not an alternate accepted input** — it is a different length and fails here
 * like any other malformed value. That matters more for ECDSA than it did for
 * Ed25519: DER admits several encodings of the same signature, and accepting
 * "whatever verifies" would let one signature arrive in multiple forms, each
 * with a different byte identity for anything that fingerprints or de-duplicates
 * it.
 *
 * Every check is structural. None of them touches a key, so this is safe to run
 * on untrusted input before a verifier exists.
 */
export function decodeCanonicalP256Signature(value: string): DeviceSignatureDecodeResult {
  if (value.includes('=')) return { ok: false, rejection: 'ENCODING_PADDED' };
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) return { ok: false, rejection: 'ENCODING_NOT_BASE64URL' };

  const decoded = Buffer.from(value, 'base64url');
  // `Buffer.from(..., 'base64url')` is lenient — it skips what it cannot read.
  // Re-encoding and demanding equality is what rules out the non-canonical
  // encodings that would otherwise decode to the same bytes.
  if (decoded.toString('base64url') !== value) return { ok: false, rejection: 'ENCODING_NOT_CANONICAL' };
  if (decoded.byteLength !== P256_SIGNATURE_BYTES) return { ok: false, rejection: 'WRONG_LENGTH' };

  const bytes = new Uint8Array(decoded);
  const r = bytesToBigInt(bytes.subarray(0, P256_SCALAR_BYTES));
  const s = bytesToBigInt(bytes.subarray(P256_SCALAR_BYTES));

  if (r < 1n || r >= P256_CURVE_ORDER) return { ok: false, rejection: 'R_OUT_OF_RANGE' };
  if (s < 1n || s >= P256_CURVE_ORDER) return { ok: false, rejection: 'S_OUT_OF_RANGE' };
  // C14-01: an incoming high-S signature is REFUSED, never silently
  // normalised. Normalising on receipt would mean two distinct wire values
  // both verify, which is exactly the malleability the single-representation
  // rule exists to remove.
  if (s > P256_HALF_CURVE_ORDER) return { ok: false, rejection: 'S_NOT_LOW' };

  return { ok: true, scalars: { r, s, bytes } };
}

/** True when `s` is already in the accepted lower half of the order. */
export function isLowS(s: bigint): boolean {
  return s >= 1n && s <= P256_HALF_CURVE_ORDER;
}

/**
 * SIGNER-SIDE ONLY, and deliberately named so it cannot be mistaken for
 * verification behaviour.
 *
 * A signing implementation may produce a mathematically equivalent high-S
 * result; converting it to `n - s` before transport is legitimate because the
 * signer holds the key and is choosing which of two equivalent forms to send.
 * A verifier doing the same thing would be accepting a value the contract
 * refuses. The asymmetry is the point.
 */
export function lowSCanonicaliseForSigning(s: bigint): bigint {
  if (s < 1n || s >= P256_CURVE_ORDER) throw new RangeError('s is outside the P-256 scalar range');
  return s > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - s : s;
}

/** Encodes scalars into the one accepted wire form. Refuses anything it could not itself decode. */
export function encodeCanonicalP256Signature(r: bigint, s: bigint): string {
  if (r < 1n || r >= P256_CURVE_ORDER) throw new RangeError('r is outside the P-256 scalar range');
  if (!isLowS(s)) throw new RangeError('s must be low-S; canonicalise on the signer before encoding');
  const bytes = new Uint8Array(P256_SIGNATURE_BYTES);
  bytes.set(bigIntToScalarBytes(r), 0);
  bytes.set(bigIntToScalarBytes(s), P256_SCALAR_BYTES);
  return Buffer.from(bytes).toString('base64url');
}

// ---------------------------------------------------------------------------
// The verification boundary
// ---------------------------------------------------------------------------

export type DeviceSignatureVerification =
  | { readonly outcome: 'VERIFIED' }
  | { readonly outcome: 'REFUSED'; readonly rejection: DeviceSignatureRejection }
  | { readonly outcome: 'INVALID_SIGNATURE' }
  | { readonly outcome: 'PROFILE_NOT_APPROVED' };

/**
 * The gate a runtime verifier must sit behind.
 *
 * `verify` is the caller's cryptographic check, invoked with already-validated
 * scalars and **only** when every structural rule has passed. That ordering is
 * the contract: malformed base64url, padding, wrong length, DER, out-of-range
 * scalars and high-S must all fail before a key is ever touched, so a
 * malleable or malformed value cannot reach curve arithmetic and cannot be
 * "rescued" by a permissive library.
 *
 * The regression that matters here asserts the callback was **not called**.
 */
export function verifyCanonicalDeviceSignature(
  input: { readonly profile: unknown; readonly signature: string },
  verify: (scalars: DeviceSignatureScalars) => boolean,
): DeviceSignatureVerification {
  if (!isApprovedDeviceSignatureProfile(input.profile)) return { outcome: 'PROFILE_NOT_APPROVED' };
  const decoded = decodeCanonicalP256Signature(input.signature);
  if (!decoded.ok) return { outcome: 'REFUSED', rejection: decoded.rejection };
  return verify(decoded.scalars) ? { outcome: 'VERIFIED' } : { outcome: 'INVALID_SIGNATURE' };
}
