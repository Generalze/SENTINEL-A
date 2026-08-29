import { createVerify, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  decodeCanonicalP256Signature,
  DeviceSignatureSchema,
  encodeCanonicalP256Signature,
  isApprovedDeviceSignatureProfile,
  isLowS,
  lowSCanonicaliseForSigning,
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  P256_SIGNATURE_BASE64URL_LENGTH,
  P256_SIGNATURE_BYTES,
  verifyCanonicalDeviceSignature,
  type DeviceSignatureScalars,
} from './index.js';

/** WP-23 / C14-01 Crucible — the physical-device signature profile. */

const R = 0x1234567890abcdefn;
const S = 0x0fedcba098765432n;

function scalarsOf(signature: string): DeviceSignatureScalars {
  const decoded = decodeCanonicalP256Signature(signature);
  if (!decoded.ok) throw new Error(`expected a decodable signature, got ${decoded.rejection}`);
  return decoded.scalars;
}

describe('C14-01 the approved profile is an allowlist and never client-chosen', () => {
  it('admits exactly the hardware-compatible P-256 profile', () => {
    expect(isApprovedDeviceSignatureProfile('P256_ECDSA_SHA256')).toBe(true);
    // Whisper v1's algorithm is not an M3 device profile: v1 stays frozen and
    // is verified by its own path, not reinterpreted through this one.
    for (const forged of ['Ed25519', 'ES256', 'none', 'RS256', 'P256_ECDSA_SHA1', '', null, 7]) {
      expect(isApprovedDeviceSignatureProfile(forged), String(forged)).toBe(false);
    }
  });

  it('an unapproved profile is refused without entering the verifier', () => {
    const verify = vi.fn(() => true);
    expect(verifyCanonicalDeviceSignature({ profile: 'Ed25519', signature: encodeCanonicalP256Signature(R, S) }, verify)).toEqual({
      outcome: 'PROFILE_NOT_APPROVED',
    });
    expect(verify).not.toHaveBeenCalled();
  });
});

describe('C14-01 exactly one canonical wire representation', () => {
  const valid = encodeCanonicalP256Signature(R, S);

  it('round-trips r and s through the raw P1363 form', () => {
    expect(valid).toHaveLength(P256_SIGNATURE_BASE64URL_LENGTH);
    expect(DeviceSignatureSchema.safeParse(valid).success).toBe(true);
    expect(scalarsOf(valid).r).toBe(R);
    expect(scalarsOf(valid).s).toBe(S);
    expect(scalarsOf(valid).bytes).toHaveLength(P256_SIGNATURE_BYTES);
  });

  it('refuses padding, non-base64url alphabets and non-canonical encodings', () => {
    const raw = Buffer.from(scalarsOf(valid).bytes);
    expect(decodeCanonicalP256Signature(`${raw.toString('base64url')}=`)).toEqual({ ok: false, rejection: 'ENCODING_PADDED' });
    // Standard base64's + and / are not in the base64url alphabet. (Asserted
    // directly: for some byte sequences the two encodings coincide, and a test
    // that only sometimes exercises the rule is not a test of the rule.)
    expect(decodeCanonicalP256Signature(`${valid.slice(0, -1)}+`)).toEqual({ ok: false, rejection: 'ENCODING_NOT_BASE64URL' });
    expect(decodeCanonicalP256Signature(`${valid.slice(0, -1)}/`)).toEqual({ ok: false, rejection: 'ENCODING_NOT_BASE64URL' });
    expect(decodeCanonicalP256Signature('!!!!')).toEqual({ ok: false, rejection: 'ENCODING_NOT_BASE64URL' });
    // A trailing character that decodes to the same bytes is NOT canonical:
    // Buffer.from is lenient, the round-trip check is what refuses it.
    const nonCanonical = `${valid.slice(0, -1)}${valid.endsWith('A') ? 'B' : 'A'}`;
    const decodedNonCanonical = decodeCanonicalP256Signature(nonCanonical);
    if (decodedNonCanonical.ok) {
      // If it decoded, it must be because it is a genuinely different signature.
      expect(decodedNonCanonical.scalars.s).not.toBe(S);
    } else {
      expect(decodedNonCanonical.rejection).toBe('ENCODING_NOT_CANONICAL');
    }
  });

  it('refuses anything that is not exactly 64 bytes', () => {
    for (const bytes of [new Uint8Array(63), new Uint8Array(65), new Uint8Array(0), new Uint8Array(32)]) {
      const encoded = Buffer.from(bytes).toString('base64url');
      expect(decodeCanonicalP256Signature(encoded), `${bytes.length} bytes`).toMatchObject({ ok: false });
    }
  });

  it('C14-01: DER is not an alternate accepted input', () => {
    // A real DER ECDSA signature, produced by node, is ~70-72 bytes and starts
    // with 0x30. It must fail on length rather than being unwrapped — DER
    // admits several encodings of one signature, which is exactly the
    // malleability a single representation exists to remove.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const der = cryptoSign('sha256', Buffer.from('device statement'), privateKey);
    expect(der[0]).toBe(0x30);
    expect(decodeCanonicalP256Signature(der.toString('base64url'))).toEqual({ ok: false, rejection: 'WRONG_LENGTH' });
  });
});

describe('C14-01 scalar range and low-S', () => {
  function encodeScalarsUnchecked(r: bigint, s: bigint): string {
    const bytes = new Uint8Array(P256_SIGNATURE_BYTES);
    const write = (value: bigint, offset: number): void => {
      let remaining = value;
      for (let index = 31; index >= 0; index -= 1) {
        bytes[offset + index] = Number(remaining & 0xffn);
        remaining >>= 8n;
      }
    };
    write(r, 0);
    write(s, 32);
    return Buffer.from(bytes).toString('base64url');
  }

  it('refuses zero and out-of-range scalars', () => {
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(0n, S))).toEqual({ ok: false, rejection: 'R_OUT_OF_RANGE' });
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(P256_CURVE_ORDER, S))).toEqual({ ok: false, rejection: 'R_OUT_OF_RANGE' });
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(R, 0n))).toEqual({ ok: false, rejection: 'S_OUT_OF_RANGE' });
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(R, P256_CURVE_ORDER))).toEqual({ ok: false, rejection: 'S_OUT_OF_RANGE' });
  });

  it('accepts s exactly at floor(n/2) and refuses one above it', () => {
    expect(isLowS(P256_HALF_CURVE_ORDER)).toBe(true);
    expect(isLowS(P256_HALF_CURVE_ORDER + 1n)).toBe(false);
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(R, P256_HALF_CURVE_ORDER))).toMatchObject({ ok: true });
    expect(decodeCanonicalP256Signature(encodeScalarsUnchecked(R, P256_HALF_CURVE_ORDER + 1n))).toEqual({
      ok: false,
      rejection: 'S_NOT_LOW',
    });
  });

  it('C14-01: an incoming high-S signature is REFUSED, never silently normalised', () => {
    const high = P256_CURVE_ORDER - S;
    expect(isLowS(high)).toBe(false);
    const encoded = encodeScalarsUnchecked(R, high);
    expect(decodeCanonicalP256Signature(encoded)).toEqual({ ok: false, rejection: 'S_NOT_LOW' });
    // The equivalent low-S form is a DIFFERENT wire value, and only it is
    // admitted — so one signature cannot arrive in two accepted shapes.
    const low = encodeCanonicalP256Signature(R, lowSCanonicaliseForSigning(high));
    expect(low).not.toBe(encoded);
    expect(decodeCanonicalP256Signature(low)).toMatchObject({ ok: true });
  });

  it('low-S canonicalisation is a signer-side operation, and the encoder refuses to do it implicitly', () => {
    const high = P256_CURVE_ORDER - S;
    expect(lowSCanonicaliseForSigning(high)).toBe(S);
    expect(lowSCanonicaliseForSigning(S)).toBe(S);
    // The encoder will not quietly fix a high-S caller: normalising on the way
    // out would hide from a signer that it is producing a non-canonical form.
    expect(() => encodeCanonicalP256Signature(R, high)).toThrow(/low-S/u);
    expect(() => encodeCanonicalP256Signature(0n, S)).toThrow(/range/u);
    expect(() => lowSCanonicaliseForSigning(P256_CURVE_ORDER)).toThrow(/range/u);
  });
});

describe('C14-01 nothing malformed reaches the cryptographic verifier', () => {
  const cases: Array<[string, string]> = [
    ['padded', `${encodeCanonicalP256Signature(R, S)}=`],
    ['non-base64url', '!!!!'],
    ['wrong length', Buffer.alloc(32).toString('base64url')],
    ['zero r', Buffer.concat([Buffer.alloc(32), Buffer.alloc(32, 1)]).toString('base64url')],
    ['high s', Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32, 0xff)]).toString('base64url')],
  ];

  it('refuses every malformed shape without invoking the verifier callback', () => {
    for (const [label, signature] of cases) {
      const verify = vi.fn(() => true);
      const result = verifyCanonicalDeviceSignature({ profile: 'P256_ECDSA_SHA256', signature }, verify);
      expect(result.outcome, label).toBe('REFUSED');
      // The load-bearing assertion: a permissive library must never get the
      // chance to "rescue" a value the contract has already refused.
      expect(verify, label).not.toHaveBeenCalled();
    }
  });

  it('enters the verifier only for a structurally valid signature, and reports its verdict', () => {
    const signature = encodeCanonicalP256Signature(R, S);
    // Typed parameter so the recorded call is inspectable: the point of this
    // assertion is WHAT the verifier was handed, not merely that it ran.
    const accepting = vi.fn((_scalars: DeviceSignatureScalars) => true);
    expect(verifyCanonicalDeviceSignature({ profile: 'P256_ECDSA_SHA256', signature }, accepting)).toEqual({ outcome: 'VERIFIED' });
    expect(accepting).toHaveBeenCalledTimes(1);
    expect(accepting).toHaveBeenCalledWith(expect.objectContaining({ r: R, s: S }));

    const rejecting = vi.fn(() => false);
    expect(verifyCanonicalDeviceSignature({ profile: 'P256_ECDSA_SHA256', signature }, rejecting)).toEqual({ outcome: 'INVALID_SIGNATURE' });
  });
});

describe('C14-01 the profile works against real hardware-compatible P-256 crypto', () => {
  it('a genuine P-256 signature verifies through the gate once canonicalised', () => {
    // Proves the profile is implementable with the algorithm the mobile
    // keystores actually guarantee — the whole reason M3 versions forward
    // instead of inheriting Whisper v1's Ed25519.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const message = Buffer.from('sentinel.device.request-proof.v1 canonical statement', 'utf8');

    const raw = cryptoSign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    expect(raw).toHaveLength(P256_SIGNATURE_BYTES);

    // OpenSSL does not guarantee low-S, so the SIGNER canonicalises — the
    // explicitly named, signer-side-only operation.
    const rHex = raw.subarray(0, 32).toString('hex');
    const sHex = raw.subarray(32).toString('hex');
    const canonical = encodeCanonicalP256Signature(BigInt(`0x${rHex}`), lowSCanonicaliseForSigning(BigInt(`0x${sHex}`)));

    const result = verifyCanonicalDeviceSignature({ profile: 'P256_ECDSA_SHA256', signature: canonical }, (scalars) => {
      const verifier = createVerify('sha256');
      verifier.update(message);
      return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(scalars.bytes));
    });
    expect(result).toEqual({ outcome: 'VERIFIED' });
  });

  it('a signature over different content does not verify', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const raw = cryptoSign('sha256', Buffer.from('statement A'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    const canonical = encodeCanonicalP256Signature(
      BigInt(`0x${raw.subarray(0, 32).toString('hex')}`),
      lowSCanonicaliseForSigning(BigInt(`0x${raw.subarray(32).toString('hex')}`)),
    );
    const result = verifyCanonicalDeviceSignature({ profile: 'P256_ECDSA_SHA256', signature: canonical }, (scalars) => {
      const verifier = createVerify('sha256');
      verifier.update(Buffer.from('statement B'));
      return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(scalars.bytes));
    });
    expect(result).toEqual({ outcome: 'INVALID_SIGNATURE' });
  });
});
