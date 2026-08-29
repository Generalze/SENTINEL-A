import { createVerify, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  bindClaimedSignatureProfile,
  decodeCanonicalP256PublicKey,
  decodeCanonicalP256Signature,
  deriveP256PublicKeyThumbprint,
  DeviceP256PublicKeySchema,
  DeviceSignatureSchema,
  deviceKeyThumbprintMatches,
  encodeCanonicalP256Signature,
  isApprovedDeviceSignatureProfile,
  isLowS,
  lowSCanonicaliseForSigning,
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  P256_PUBLIC_KEY_BASE64URL_LENGTH,
  P256_PUBLIC_KEY_BYTES,
  P256_PUBLIC_KEY_UNCOMPRESSED_PREFIX,
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

  it('an unapproved server profile is refused without entering the verifier', () => {
    const verify = vi.fn(() => true);
    expect(
      verifyCanonicalDeviceSignature(
        { serverResolvedProfile: 'Ed25519', claimedProfile: 'Ed25519', signature: encodeCanonicalP256Signature(R, S) },
        verify,
      ),
    ).toEqual({ outcome: 'PROFILE_NOT_APPROVED' });
    expect(verify).not.toHaveBeenCalled();
  });

  it('C15-01: a client-claimed profile that differs from the server-resolved one refuses BEFORE verification', () => {
    const verify = vi.fn(() => true);
    // The signature is perfectly valid and the server's profile is approved.
    // The only defect is that the CLIENT named something else — and that alone
    // must stop the verifier being reached, because a client that can steer the
    // profile can steer which verifier judges it.
    expect(
      verifyCanonicalDeviceSignature(
        { serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'Ed25519', signature: encodeCanonicalP256Signature(R, S) },
        verify,
      ),
    ).toEqual({ outcome: 'PROFILE_CLAIM_MISMATCH' });
    expect(verify).not.toHaveBeenCalled();
  });

  it('C15-01: bindClaimedSignatureProfile returns the SERVER value, never the claim', () => {
    expect(bindClaimedSignatureProfile('P256_ECDSA_SHA256', 'P256_ECDSA_SHA256')).toEqual({
      bound: true,
      profile: 'P256_ECDSA_SHA256',
    });
    expect(bindClaimedSignatureProfile('Ed25519', 'P256_ECDSA_SHA256')).toEqual({ bound: false, refusal: 'PROFILE_CLAIM_MISMATCH' });
    // An absent claim is not a wildcard.
    for (const claim of [undefined, null, '', 'P256_ECDSA_SHA256 ']) {
      expect(bindClaimedSignatureProfile(claim, 'P256_ECDSA_SHA256'), String(claim)).toEqual({
        bound: false,
        refusal: 'PROFILE_CLAIM_MISMATCH',
      });
    }
    // And the server's own value is still checked against the allowlist.
    expect(bindClaimedSignatureProfile('RS256', 'RS256')).toEqual({ bound: false, refusal: 'PROFILE_NOT_APPROVED' });
  });
});

describe('C15-01 the schema IS the parse boundary', () => {
  function unchecked(r: bigint, s: bigint): string {
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

  it('refuses at the SCHEMA every value the decoder refuses', () => {
    // Before C15-01 each of these parsed: the schema checked only "86 chars of
    // base64url", so a caller who forgot to run the decoder held a value the
    // contract considers invalid.
    const refused: Array<[string, string]> = [
      ['high s', unchecked(R, P256_CURVE_ORDER - S)],
      ['zero r', unchecked(0n, S)],
      ['zero s', unchecked(R, 0n)],
      ['r at the curve order', unchecked(P256_CURVE_ORDER, S)],
      ['s at the curve order', unchecked(R, P256_CURVE_ORDER)],
      ['wrong length', Buffer.alloc(32).toString('base64url')],
      ['padded', `${encodeCanonicalP256Signature(R, S)}=`],
      ['non-base64url alphabet', `${encodeCanonicalP256Signature(R, S).slice(0, -1)}+`],
    ];
    for (const [label, value] of refused) {
      expect(DeviceSignatureSchema.safeParse(value).success, label).toBe(false);
    }
    // 86 characters of valid base64url that is nonetheless not a signature.
    const shapeOnly = 'A'.repeat(P256_SIGNATURE_BASE64URL_LENGTH);
    expect(shapeOnly).toHaveLength(P256_SIGNATURE_BASE64URL_LENGTH);
    expect(/^[A-Za-z0-9_-]+$/u.test(shapeOnly)).toBe(true);
    expect(DeviceSignatureSchema.safeParse(shapeOnly).success).toBe(false);
  });

  it('accepts exactly the canonical form, and s exactly at floor(n/2)', () => {
    expect(DeviceSignatureSchema.safeParse(encodeCanonicalP256Signature(R, S)).success).toBe(true);
    expect(DeviceSignatureSchema.safeParse(unchecked(R, P256_HALF_CURVE_ORDER)).success).toBe(true);
    expect(DeviceSignatureSchema.safeParse(unchecked(R, P256_HALF_CURVE_ORDER + 1n)).success).toBe(false);
  });

  it('names the rejection on the issue for internal audit granularity', () => {
    const parsed = DeviceSignatureSchema.safeParse(unchecked(R, P256_CURVE_ORDER - S));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0]?.message).toMatch(/S_NOT_LOW/u);
    }
  });
});

describe('C15-02 exactly one canonical public-key representation', () => {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const uncompressed = publicKey.export({ type: 'spki', format: 'der' }).subarray(-P256_PUBLIC_KEY_BYTES);
  const canonicalKey = Buffer.from(uncompressed).toString('base64url');

  it('accepts the uncompressed SEC1 point and nothing else', () => {
    expect(uncompressed[0]).toBe(P256_PUBLIC_KEY_UNCOMPRESSED_PREFIX);
    expect(canonicalKey).toHaveLength(P256_PUBLIC_KEY_BASE64URL_LENGTH);
    expect(DeviceP256PublicKeySchema.safeParse(canonicalKey).success).toBe(true);
    expect(decodeCanonicalP256PublicKey(canonicalKey)).toMatchObject({ ok: true });
  });

  it('C15-02: refuses compressed points, DER/SPKI and PEM', () => {
    // A COMPRESSED point names the same key with different bytes. Admitting it
    // would give one key two thumbprints, and a device could then present
    // whichever the registry was not looking for.
    const compressed = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).subarray(-65);
    const compressedPoint = Buffer.concat([Buffer.from([0x02]), compressed.subarray(1, 33)]);
    expect(decodeCanonicalP256PublicKey(compressedPoint.toString('base64url'))).toEqual({ ok: false, rejection: 'WRONG_LENGTH' });

    const der = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));
    expect(decodeCanonicalP256PublicKey(der.toString('base64url'))).toEqual({ ok: false, rejection: 'WRONG_LENGTH' });

    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(decodeCanonicalP256PublicKey(pem)).toMatchObject({ ok: false });
    expect(DeviceP256PublicKeySchema.safeParse(pem).success).toBe(false);
  });

  it('refuses a wrong prefix, an out-of-range coordinate and a degenerate point', () => {
    const wrongPrefix = Buffer.from(uncompressed);
    wrongPrefix[0] = 0x03;
    expect(decodeCanonicalP256PublicKey(wrongPrefix.toString('base64url'))).toEqual({ ok: false, rejection: 'NOT_UNCOMPRESSED_POINT' });

    const outOfRange = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(32, 0xff), Buffer.alloc(32, 1)]);
    expect(decodeCanonicalP256PublicKey(outOfRange.toString('base64url'))).toEqual({ ok: false, rejection: 'COORDINATE_OUT_OF_RANGE' });

    const zeroPoint = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64)]);
    expect(decodeCanonicalP256PublicKey(zeroPoint.toString('base64url'))).toEqual({ ok: false, rejection: 'COORDINATE_OUT_OF_RANGE' });

    expect(decodeCanonicalP256PublicKey(`${canonicalKey}=`)).toEqual({ ok: false, rejection: 'ENCODING_PADDED' });
  });

  it('C15-02: the thumbprint is COMPUTED, and a supplied digest is never believed', () => {
    const derived = deriveP256PublicKeyThumbprint(canonicalKey);
    expect(derived).toMatch(/^[0-9a-f]{64}$/u);
    // Stable: the same key always names itself the same way.
    expect(deriveP256PublicKeyThumbprint(canonicalKey)).toBe(derived);
    expect(deviceKeyThumbprintMatches(canonicalKey, derived)).toBe(true);
    // An independently supplied digest is a second claim, not corroboration.
    expect(deviceKeyThumbprintMatches(canonicalKey, 'a'.repeat(64))).toBe(false);
    // A different key derives a different name.
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    const otherKey = Buffer.from(other.export({ type: 'spki', format: 'der' })).subarray(-P256_PUBLIC_KEY_BYTES).toString('base64url');
    expect(deriveP256PublicKeyThumbprint(otherKey)).not.toBe(derived);
    // And a non-canonical key cannot be named at all.
    expect(() => deriveP256PublicKeyThumbprint('not-a-key')).toThrow(/canonical/u);
    expect(deviceKeyThumbprintMatches('not-a-key', derived)).toBe(false);
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
      const result = verifyCanonicalDeviceSignature({ serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'P256_ECDSA_SHA256', signature }, verify);
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
    expect(verifyCanonicalDeviceSignature({ serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'P256_ECDSA_SHA256', signature }, accepting)).toEqual({ outcome: 'VERIFIED' });
    expect(accepting).toHaveBeenCalledTimes(1);
    expect(accepting).toHaveBeenCalledWith(expect.objectContaining({ r: R, s: S }));

    const rejecting = vi.fn(() => false);
    expect(verifyCanonicalDeviceSignature({ serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'P256_ECDSA_SHA256', signature }, rejecting)).toEqual({ outcome: 'INVALID_SIGNATURE' });
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

    const result = verifyCanonicalDeviceSignature({ serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'P256_ECDSA_SHA256', signature: canonical }, (scalars) => {
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
    const result = verifyCanonicalDeviceSignature({ serverResolvedProfile: 'P256_ECDSA_SHA256', claimedProfile: 'P256_ECDSA_SHA256', signature: canonical }, (scalars) => {
      const verifier = createVerify('sha256');
      verifier.update(Buffer.from('statement B'));
      return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(scalars.bytes));
    });
    expect(result).toEqual({ outcome: 'INVALID_SIGNATURE' });
  });
});
