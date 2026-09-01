import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  P256_HALF_CURVE_ORDER,
  P256_CURVE_ORDER,
  P256_SCALAR_BYTES,
  encodeCanonicalP256Signature,
  decodeCanonicalP256Signature,
  deriveP256PublicKeyThumbprint,
} from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { P256KeyImporter } from './p256-key.importer';
import { generateTestDeviceKeyPair, offCurveP256PublicKey, signCanonicalStatement } from './shield.test-support';

/**
 * WP-24/D24-05 — the runtime cryptographic boundary, tested as a pure unit.
 *
 * No stack, no database, nothing to race. The property under test is the one
 * WP-23 explicitly deferred to runtime: a structurally perfect but OFF-CURVE
 * P-256 point parses at every contract boundary and must be refused HERE,
 * before it can become an active verification credential.
 */

const PROFILE = 'P256_ECDSA_SHA256';

describe('WP-24/D24-05 P256KeyImporter', () => {
  const importer = new P256KeyImporter();

  describe('importPublicKey', () => {
    it('imports a genuine canonical P-256 point as an EC public key on prime256v1', () => {
      const key = importer.importPublicKey(generateTestDeviceKeyPair().publicKey);
      expect(key).not.toBeNull();
      expect(key?.type).toBe('public');
      expect(key?.asymmetricKeyType).toBe('ec');
      expect(key?.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    });

    it('REFUSES a structurally perfect off-curve point — the whole point of D24-05', () => {
      const offCurve = offCurveP256PublicKey();

      // The fixture is only meaningful if the CONTRACT accepts it. If this
      // assertion ever fails the test below has become vacuous: it would be
      // proving that the importer refuses something the parse already refused,
      // which is not the deferral D24-05 exists to pay off.
      expect(deriveP256PublicKeyThumbprint(offCurve)).toMatch(/^[0-9a-f]{64}$/u);

      expect(importer.importPublicKey(offCurve)).toBeNull();
      expect(importer.isRuntimeValidPublicKey(offCurve)).toBe(false);
    });

    it('refuses every non-canonical encoding before the provider is reached', () => {
      const valid = generateTestDeviceKeyPair().publicKey;
      const raw = Buffer.from(valid, 'base64url');
      for (const rejected of [
        '',
        // Standard base64 with padding: a different string for the same bytes.
        raw.toString('base64'),
        // A compressed point names the same key with different bytes, which
        // would give one key two thumbprints (C15-02).
        Buffer.concat([Buffer.from([0x02]), raw.subarray(1, 1 + P256_SCALAR_BYTES)]).toString('base64url'),
        // DER SPKI, which admits several encodings of one key.
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
        // Truncated, and decorated.
        raw.subarray(0, 64).toString('base64url'),
        `${valid} `,
      ]) {
        expect(importer.importPublicKey(rejected), rejected.slice(0, 24)).toBeNull();
      }
    });

    it('refuses a key from a different curve', () => {
      const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({ format: 'der', type: 'spki' });
      expect(importer.importPublicKey(Buffer.from(p384).toString('base64url'))).toBeNull();
    });
  });

  describe('verifySignature', () => {
    const pair = generateTestDeviceKeyPair();
    const message = '{"domain":"sentinel.test","value":1}';

    it('verifies a canonical low-S signature by the registered key', () => {
      expect(
        importer.verifySignature({
          registeredPublicKey: pair.publicKey,
          message,
          signature: signCanonicalStatement(pair.privateKey, message),
          serverResolvedProfile: PROFILE,
          claimedProfile: PROFILE,
        }),
      ).toBe(true);
    });

    it('refuses a signature by a DIFFERENT key over the same message', () => {
      const attacker = generateTestDeviceKeyPair();
      expect(
        importer.verifySignature({
          registeredPublicKey: pair.publicKey,
          message,
          signature: signCanonicalStatement(attacker.privateKey, message),
          serverResolvedProfile: PROFILE,
          claimedProfile: PROFILE,
        }),
      ).toBe(false);
    });

    it('refuses a valid signature over DIFFERENT bytes', () => {
      expect(
        importer.verifySignature({
          registeredPublicKey: pair.publicKey,
          message: `${message} `,
          signature: signCanonicalStatement(pair.privateKey, message),
          serverResolvedProfile: PROFILE,
          claimedProfile: PROFILE,
        }),
      ).toBe(false);
    });

    it('C15-01: refuses when the claimed profile is not the server-resolved one', () => {
      const signature = signCanonicalStatement(pair.privateKey, message);
      expect(
        importer.verifySignature({
          registeredPublicKey: pair.publicKey,
          message,
          signature,
          serverResolvedProfile: PROFILE,
          claimedProfile: 'ED25519',
        }),
      ).toBe(false);
      // And an unapproved SERVER profile is refused too, so a corrupted
      // registry row cannot steer the verifier either.
      expect(
        importer.verifySignature({
          registeredPublicKey: pair.publicKey,
          message,
          signature,
          serverResolvedProfile: 'ED25519',
          claimedProfile: 'ED25519',
        }),
      ).toBe(false);
    });

    it('C14-01: refuses a HIGH-S signature that OpenSSL would otherwise accept', () => {
      // Produce a genuine signature, then present its mathematically
      // equivalent high-S twin. `ieee-p1363` verification accepts it; the
      // contract's canonical decode does not, and the decode runs first.
      const raw = cryptoSign('sha256', Buffer.from(message, 'utf8'), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
      const r = BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`);
      const s = BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`);
      const low = s > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - s : s;
      const high = P256_CURVE_ORDER - low;
      const highSBytes = Buffer.concat([
        raw.subarray(0, P256_SCALAR_BYTES),
        Buffer.from(high.toString(16).padStart(64, '0'), 'hex'),
      ]);
      const highSEncoded = highSBytes.toString('base64url');

      // The fixture must be the malleable twin, not a broken value.
      expect(decodeCanonicalP256Signature(highSEncoded)).toEqual({ ok: false, rejection: 'S_NOT_LOW' });
      expect(importer.verifySignature({
        registeredPublicKey: pair.publicKey,
        message,
        signature: highSEncoded,
        serverResolvedProfile: PROFILE,
        claimedProfile: PROFILE,
      })).toBe(false);

      // ... while its low-S form, over the same message, verifies. Without
      // this half the assertion above would pass for a fixture that was simply
      // not a signature at all.
      expect(importer.verifySignature({
        registeredPublicKey: pair.publicKey,
        message,
        signature: encodeCanonicalP256Signature(r, low),
        serverResolvedProfile: PROFILE,
        claimedProfile: PROFILE,
      })).toBe(true);
    });

    it('refuses when the REGISTERED key is off-curve, however good the signature looks', () => {
      expect(
        importer.verifySignature({
          registeredPublicKey: offCurveP256PublicKey(),
          message,
          signature: signCanonicalStatement(pair.privateKey, message),
          serverResolvedProfile: PROFILE,
          claimedProfile: PROFILE,
        }),
      ).toBe(false);
    });
  });
});
