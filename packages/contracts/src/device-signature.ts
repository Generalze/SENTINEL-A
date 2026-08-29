import { createHash } from 'node:crypto';
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
 * It performs no curve arithmetic. It defines the exact bytes a signature and
 * a public key are allowed to be, refuses everything else *before* any verifier
 * is entered, and derives one digest (SHA-256 over canonical key bytes) so a
 * thumbprint is COMPUTED rather than believed. The actual point arithmetic
 * belongs to the runtime (WP-25/WP-27) against a key resolved from the server
 * registry by `key_id + key_version` — never an algorithm the client named.
 *
 * C15-01: THE PARSE *IS* THE BOUNDARY
 * -----------------------------------
 * `DeviceSignatureSchema` used to check only "86 characters of base64url",
 * which meant a high-S, zero-scalar, out-of-range or non-round-tripping value
 * could sit inside a fully parsed `DeviceRequestProof`, possession response,
 * offline envelope or Edge receipt and be refused only if some later caller
 * remembered to run the decoder. It no longer can: the schema runs the full
 * canonical decode and BRANDS its output, so a `CanonicalP256Signature` is a
 * value that provably decoded. There is one parse boundary and no way past it.
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

/**
 * C15-01: THE CLIENT DOES NOT CHOOSE THE PROFILE.
 *
 * A `signature_profile` field on anything a device submits is a CLAIM, never an
 * authority — which is why every such field in WP-23 is now named
 * `claimed_signature_profile`. The authority is the profile recorded on the
 * server's registry key record for `key_id + key_version` (see
 * `DeviceRegistryKeyRecordSchema`), and the Edge equivalent for Edge receipts.
 *
 * A claim is admissible only when it EQUALS the server-resolved profile. That
 * equality is checked here, before verification, so a client cannot steer the
 * verifier and cannot make a signature mean something the registry did not
 * select. Canonical signed statements bind the value this function RETURNS —
 * the server's — and never the field the client sent.
 */
export type DeviceSignatureProfileBinding =
  | { readonly bound: true; readonly profile: DeviceSignatureProfile }
  | { readonly bound: false; readonly refusal: 'PROFILE_NOT_APPROVED' | 'PROFILE_CLAIM_MISMATCH' };

export function bindClaimedSignatureProfile(claimed: unknown, serverResolved: unknown): DeviceSignatureProfileBinding {
  if (!isApprovedDeviceSignatureProfile(serverResolved)) return { bound: false, refusal: 'PROFILE_NOT_APPROVED' };
  if (claimed !== serverResolved) return { bound: false, refusal: 'PROFILE_CLAIM_MISMATCH' };
  return { bound: true, profile: serverResolved };
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
 * C15-01: the wire form, and the ONLY way to obtain one.
 *
 * The schema runs the full canonical decode — canonical unpadded base64url,
 * exactly 64 bytes, `1 <= r < n`, `1 <= s <= floor(n/2)` — and brands its
 * output. The brand is the load-bearing part: `CanonicalP256Signature` is not
 * "a string that looked right", it is a string that DECODED, and TypeScript
 * will not let an unparsed string stand in for one. Every signature field in
 * WP-23 is typed by this schema, so a high-S or malformed value cannot exist
 * inside a parsed `DeviceRequestProof`, possession response, offline envelope
 * or Edge receipt at all — the compound parse fails, not some later caller who
 * remembered to check.
 *
 * The rejection reason is attached to the issue for internal audit granularity
 * and deliberately collapsed at any device-facing surface, for the reason
 * `DeviceSignatureRejection` already documents: naming the malformation is a
 * free oracle.
 */
export const DeviceSignatureSchema = z
  .string()
  .superRefine((value, context) => {
    const decoded = decodeCanonicalP256Signature(value);
    if (decoded.ok) return;
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: `signature is not a canonical P-256 signature: ${decoded.rejection}`,
      params: { rejection: decoded.rejection },
    });
  })
  .brand<'CanonicalP256Signature'>();

/** A signature that provably decoded. Only `DeviceSignatureSchema` can mint one. */
export type CanonicalP256Signature = z.infer<typeof DeviceSignatureSchema>;

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
// The canonical PUBLIC KEY (C15-02)
// ---------------------------------------------------------------------------

/**
 * C15-02: A THUMBPRINT CANNOT VERIFY AN ECDSA SIGNATURE.
 *
 * WP-23 shipped `public_key_thumbprint` and nothing else, which is a digest of
 * a key — enough to recognise a key you already hold, useless for verifying a
 * signature. A registry that cannot verify is not a registry. So exactly one
 * representation of a P-256 public key is defined, here, next to the signature
 * rules and for the same reason: one accepted representation means one byte
 * identity, and one byte identity means a thumbprint is a stable name.
 *
 * The representation is the uncompressed SEC1 point `0x04 || X(32) || Y(32)`,
 * 65 bytes, canonical unpadded base64url.
 *
 * COMPRESSED POINTS, DER/SPKI AND PEM ARE NOT ALTERNATE INPUTS. A compressed
 * point (`0x02`/`0x03`, 33 bytes) names the SAME key as its uncompressed form
 * with DIFFERENT bytes, so admitting both would give one key two thumbprints —
 * and a device could then present whichever one the registry was not looking
 * for. DER and PEM are worse: both admit several encodings of one key. Each is
 * refused structurally, by prefix and by length.
 */
export const P256_PUBLIC_KEY_UNCOMPRESSED_PREFIX = 0x04;
export const P256_PUBLIC_KEY_BYTES = 65;
/** 65 bytes encode to exactly 87 base64url characters with no padding. */
export const P256_PUBLIC_KEY_BASE64URL_LENGTH = 87;

/** The P-256 field prime. A coordinate is a field element, so it is `< p`. */
export const P256_FIELD_PRIME = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF');

export const DeviceP256PublicKeyRejectionSchema = z.enum([
  'ENCODING_NOT_BASE64URL',
  'ENCODING_PADDED',
  'ENCODING_NOT_CANONICAL',
  'WRONG_LENGTH',
  'NOT_UNCOMPRESSED_POINT',
  'COORDINATE_OUT_OF_RANGE',
]);
export type DeviceP256PublicKeyRejection = z.infer<typeof DeviceP256PublicKeyRejectionSchema>;

export interface DeviceP256PublicKeyPoint {
  readonly x: bigint;
  readonly y: bigint;
  readonly bytes: Uint8Array;
}

export type DeviceP256PublicKeyDecodeResult =
  | { readonly ok: true; readonly point: DeviceP256PublicKeyPoint }
  | { readonly ok: false; readonly rejection: DeviceP256PublicKeyRejection };

/**
 * Structural only, and safe on untrusted input: no point is put on the curve
 * here. Whether `(x, y)` actually satisfies the curve equation is the runtime
 * verifier's job at the moment it imports the key (WP-25/WP-27); what this
 * decides is whether the bytes are the ONE representation the platform accepts.
 */
export function decodeCanonicalP256PublicKey(value: string): DeviceP256PublicKeyDecodeResult {
  if (value.includes('=')) return { ok: false, rejection: 'ENCODING_PADDED' };
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) return { ok: false, rejection: 'ENCODING_NOT_BASE64URL' };

  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) return { ok: false, rejection: 'ENCODING_NOT_CANONICAL' };
  // Length is checked before the prefix so a 33-byte compressed point and a DER
  // blob both die here rather than being half-interpreted.
  if (decoded.byteLength !== P256_PUBLIC_KEY_BYTES) return { ok: false, rejection: 'WRONG_LENGTH' };

  const bytes = new Uint8Array(decoded);
  if (bytes[0] !== P256_PUBLIC_KEY_UNCOMPRESSED_PREFIX) return { ok: false, rejection: 'NOT_UNCOMPRESSED_POINT' };

  const x = bytesToBigInt(bytes.subarray(1, 1 + P256_SCALAR_BYTES));
  const y = bytesToBigInt(bytes.subarray(1 + P256_SCALAR_BYTES));
  if (x >= P256_FIELD_PRIME || y >= P256_FIELD_PRIME) return { ok: false, rejection: 'COORDINATE_OUT_OF_RANGE' };
  // The point at infinity has no uncompressed encoding and (0, 0) is not on the
  // curve; refusing it here keeps a degenerate key out of the registry.
  if (x === 0n && y === 0n) return { ok: false, rejection: 'COORDINATE_OUT_OF_RANGE' };

  return { ok: true, point: { x, y, bytes } };
}

/** The public-key wire form, branded so a parsed key provably decoded (C15-01's rule, applied to keys). */
export const DeviceP256PublicKeySchema = z
  .string()
  .superRefine((value, context) => {
    const decoded = decodeCanonicalP256PublicKey(value);
    if (decoded.ok) return;
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: `public key is not a canonical uncompressed P-256 point: ${decoded.rejection}`,
      params: { rejection: decoded.rejection },
    });
  })
  .brand<'CanonicalP256PublicKey'>();

export type CanonicalP256PublicKey = z.infer<typeof DeviceP256PublicKeySchema>;

/**
 * C15-02: THE THUMBPRINT IS COMPUTED, NEVER BELIEVED.
 *
 * SHA-256 hex over the canonical 65 key bytes. An independently supplied digest
 * is not evidence about a key — it is a second, unverified claim, and accepting
 * one would let a device name a key it does not hold. Everywhere a thumbprint
 * arrives alongside a key, the contract recomputes it and refuses on
 * disagreement; that is what `deviceKeyThumbprintMatches` is for.
 */
export function deriveP256PublicKeyThumbprint(publicKey: string): string {
  const decoded = decodeCanonicalP256PublicKey(publicKey);
  if (!decoded.ok) throw new RangeError(`public key is not canonical: ${decoded.rejection}`);
  return createHash('sha256').update(decoded.point.bytes).digest('hex');
}

/** True when `thumbprint` is exactly the digest derived from `publicKey`. */
export function deviceKeyThumbprintMatches(publicKey: string, thumbprint: string): boolean {
  const decoded = decodeCanonicalP256PublicKey(publicKey);
  if (!decoded.ok) return false;
  return deriveP256PublicKeyThumbprint(publicKey) === thumbprint;
}

// ---------------------------------------------------------------------------
// The verification boundary
// ---------------------------------------------------------------------------

export type DeviceSignatureVerification =
  | { readonly outcome: 'VERIFIED' }
  | { readonly outcome: 'REFUSED'; readonly rejection: DeviceSignatureRejection }
  | { readonly outcome: 'INVALID_SIGNATURE' }
  | { readonly outcome: 'PROFILE_NOT_APPROVED' }
  | { readonly outcome: 'PROFILE_CLAIM_MISMATCH' };

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
 * C15-01 adds the profile binding to that ordering. `serverResolvedProfile` is
 * the registry's answer for this key; `claimedProfile` is the device's field.
 * They must be equal before a verifier is reachable, so a client that names a
 * different profile is refused rather than served — and the SERVER's value is
 * the one any canonical statement goes on to bind.
 *
 * The regression that matters here asserts the callback was **not called**.
 */
export function verifyCanonicalDeviceSignature(
  input: { readonly serverResolvedProfile: unknown; readonly claimedProfile: unknown; readonly signature: string },
  verify: (scalars: DeviceSignatureScalars) => boolean,
): DeviceSignatureVerification {
  const binding = bindClaimedSignatureProfile(input.claimedProfile, input.serverResolvedProfile);
  if (!binding.bound) return { outcome: binding.refusal };
  const decoded = decodeCanonicalP256Signature(input.signature);
  if (!decoded.ok) return { outcome: 'REFUSED', rejection: decoded.rejection };
  return verify(decoded.scalars) ? { outcome: 'VERIFIED' } : { outcome: 'INVALID_SIGNATURE' };
}
