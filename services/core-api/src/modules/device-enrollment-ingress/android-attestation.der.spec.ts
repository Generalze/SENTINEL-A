import { describe, expect, it } from 'vitest';
import {
  ANDROID_KEY_ATTESTATION_EXTENSION_OID,
  encodeObjectIdentifier,
  findCertificateExtension,
  parseAndroidKeyDescription,
  readDerChildren,
  readDerNode,
  readDerNodeExact,
  readDerUnsignedInteger,
} from './android-attestation.der';
import {
  buildCertificate,
  buildKeyDescription,
  buildSyntheticChain,
  der,
  extension,
  generateEcKeyPair,
} from './android-attestation.test-support';

/**
 * WP-26/D26-04B — the DER reader, on its own, with no stack and no database.
 *
 * This parser decides whether a physical device is granted the first
 * `HARDWARE_BACKED` value in Sentinel's history, so its REFUSALS matter at
 * least as much as its successes. A lenient parser on a signed structure is not
 * a convenience: it is two readers who can disagree about what a certificate
 * says, which is exactly the ambiguity a signature exists to eliminate.
 *
 * Every case below is a REFUSAL that a permissive decoder would have accepted.
 */

describe('WP-26 the OID encoder produces the bytes a reviewer can check', () => {
  it('encodes the Android Key Attestation OID', () => {
    // 1.3.6.1.4.1.11129.2.1.17
    //   first two arcs collapse to 1*40 + 3 = 43 = 0x2b
    //   11129 = 86*128 + 121, so base-128 is [86, 121] and the continuation
    //   bit on the first octet makes it 0xd6 0x79
    expect(encodeObjectIdentifier(ANDROID_KEY_ATTESTATION_EXTENSION_OID)?.toString('hex')).toBe('2b06010401d679020111');
  });

  it('refuses an OID that cannot exist', () => {
    expect(encodeObjectIdentifier('3.1.1')).toBeNull();
    expect(encodeObjectIdentifier('1.40.1')).toBeNull();
    expect(encodeObjectIdentifier('1')).toBeNull();
  });
});

describe('WP-26 the reader refuses BER, non-minimal encodings and trailing bytes', () => {
  it('refuses the INDEFINITE length form', () => {
    // `30 80 ... 00 00` is legal BER and forbidden in DER.
    expect(readDerNode(Buffer.from('30800000', 'hex'))).toBeNull();
  });

  it('refuses a non-minimal long-form length', () => {
    // Length 1 expressed in the long form. A permissive parser accepts it and
    // then two encodings of the same structure exist.
    expect(readDerNode(Buffer.from('81010500'.replace('81', '02'), 'hex'))).not.toBeNull();
    expect(readDerNode(Buffer.from('028101ff', 'hex'))).toBeNull();
  });

  it('refuses a length that overruns the buffer', () => {
    expect(readDerNode(Buffer.from('0410aabb', 'hex'))).toBeNull();
  });

  it('refuses trailing bytes after a complete structure', () => {
    const complete = der.sequence(der.integer(1));
    expect(readDerNodeExact(complete)).not.toBeNull();
    expect(readDerNodeExact(Buffer.concat([complete, Buffer.from([0x00])]))).toBeNull();
  });

  it('refuses children that do not tile their parent exactly', () => {
    const node = readDerNode(Buffer.from('3003020101', 'hex').subarray(0, 5));
    expect(node).not.toBeNull();
    expect(readDerChildren(node as NonNullable<typeof node>)).not.toBeNull();
    // A SEQUENCE claiming 4 content bytes whose single child consumes 3.
    const ragged = readDerNode(Buffer.from('300402010100', 'hex'));
    expect(ragged).not.toBeNull();
    expect(readDerChildren(ragged as NonNullable<typeof ragged>)).toBeNull();
  });

  it('refuses a negative or non-minimal INTEGER, and a bignum', () => {
    const negative = readDerNode(Buffer.from('0201ff', 'hex'));
    expect(readDerUnsignedInteger(negative as NonNullable<typeof negative>)).toBeNull();
    const padded = readDerNode(Buffer.from('02020001', 'hex'));
    expect(readDerUnsignedInteger(padded as NonNullable<typeof padded>)).toBeNull();
    const huge = readDerNode(Buffer.from(`0208${'ff'.repeat(8)}`, 'hex'));
    expect(readDerUnsignedInteger(huge as NonNullable<typeof huge>)).toBeNull();
    const ok = readDerNode(Buffer.from('02020100', 'hex'));
    expect(readDerUnsignedInteger(ok as NonNullable<typeof ok>)).toBe(256);
  });
});

describe('WP-26 the KeyDescription parser', () => {
  const challenge = Buffer.from('a-server-challenge', 'utf8');

  it('reads the fields the verdict depends on', () => {
    const parsed = parseAndroidKeyDescription(buildKeyDescription({ challenge }));
    expect(parsed).not.toBeNull();
    expect(parsed?.attestationSecurityLevel).toBe(2);
    expect(parsed?.keymasterSecurityLevel).toBe(2);
    expect(parsed?.attestationChallenge.equals(challenge)).toBe(true);
    expect(parsed?.teeEnforced.purposes).toEqual([2]);
    expect(parsed?.teeEnforced.algorithm).toBe(3);
    expect(parsed?.teeEnforced.keySize).toBe(256);
    expect(parsed?.teeEnforced.origin).toBe(0);
    expect(parsed?.teeEnforced.noAuthRequired).toBe(true);
    expect(parsed?.teeEnforced.rootOfTrust?.deviceLocked).toBe(true);
    expect(parsed?.teeEnforced.rootOfTrust?.verifiedBootState).toBe(0);
    // `softwareEnforced` is read but is EMPTY in the fixture, and the verifier
    // consults `teeEnforced` only: what the OS asserts is not evidence about
    // hardware.
    expect(parsed?.softwareEnforced.rootOfTrust).toBeNull();
  });

  it('refuses an authorisation list whose tags are not strictly ascending', () => {
    // Hand-built, out of order: [2] before [1]. A parser that tolerated this
    // would accept a structure two readers could disagree about — and a
    // duplicate tag is the same defect with a worse consequence, because "first
    // wins" and "last wins" then differ.
    const outOfOrder = der.sequence(
      der.integer(4),
      der.enumerated(2),
      der.integer(41),
      der.enumerated(2),
      der.octetString(challenge),
      der.octetString(Buffer.alloc(0)),
      der.sequence(),
      der.sequence(der.contextExplicit(2, der.integer(3)), der.contextExplicit(1, der.set(der.integer(2)))),
    );
    expect(parseAndroidKeyDescription(outOfOrder)).toBeNull();

    const duplicated = der.sequence(
      der.integer(4),
      der.enumerated(2),
      der.integer(41),
      der.enumerated(2),
      der.octetString(challenge),
      der.octetString(Buffer.alloc(0)),
      der.sequence(),
      der.sequence(der.contextExplicit(1, der.set(der.integer(2))), der.contextExplicit(1, der.set(der.integer(3)))),
    );
    expect(parseAndroidKeyDescription(duplicated)).toBeNull();
  });

  it('refuses a [503] noAuthRequired that is not NULL', () => {
    const malformed = der.sequence(
      der.integer(4),
      der.enumerated(2),
      der.integer(41),
      der.enumerated(2),
      der.octetString(challenge),
      der.octetString(Buffer.alloc(0)),
      der.sequence(),
      der.sequence(der.contextExplicit(503, der.integer(1))),
    );
    expect(parseAndroidKeyDescription(malformed)).toBeNull();
  });

  it('refuses a KeyDescription with the wrong number of fields', () => {
    const truncated = der.sequence(der.integer(4), der.enumerated(2), der.integer(41));
    expect(parseAndroidKeyDescription(truncated)).toBeNull();
  });
});

describe('WP-26 the certificate extension walk', () => {
  it('finds the attestation extension on a real leaf', () => {
    const chain = buildSyntheticChain({ challenge: Buffer.from('challenge', 'utf8') });
    const leaf = Buffer.from(chain.chainBase64[0] as string, 'base64');
    const value = findCertificateExtension(leaf, ANDROID_KEY_ATTESTATION_EXTENSION_OID);
    expect(value).not.toBeNull();
    expect(parseAndroidKeyDescription(value as Buffer)).not.toBeNull();
  });

  it('returns null when the certificate does not carry it', () => {
    const chain = buildSyntheticChain({ challenge: Buffer.alloc(8), omitAttestationExtension: true });
    const leaf = Buffer.from(chain.chainBase64[0] as string, 'base64');
    expect(findCertificateExtension(leaf, ANDROID_KEY_ATTESTATION_EXTENSION_OID)).toBeNull();
  });

  it('REFUSES a certificate carrying the same extension OID twice', () => {
    // X.509 forbids it, and "the first one wins" versus "the last one wins" is
    // precisely the disagreement a signed object must not admit. A device that
    // could ship two KeyDescriptions could ship one for each reader.
    const keyPair = generateEcKeyPair();
    const honest = buildKeyDescription({ challenge: Buffer.from('honest', 'utf8') });
    const forged = buildKeyDescription({ challenge: Buffer.from('forged', 'utf8') });
    const chain = buildSyntheticChain({
      challenge: Buffer.from('honest', 'utf8'),
      leafKeyPair: keyPair,
    });
    // Rebuild a leaf with BOTH extensions present.
    const doubled = buildLeafWithExtensions(chain, [
      extension(ANDROID_KEY_ATTESTATION_EXTENSION_OID, honest),
      extension(ANDROID_KEY_ATTESTATION_EXTENSION_OID, forged),
    ]);
    expect(findCertificateExtension(doubled, ANDROID_KEY_ATTESTATION_EXTENSION_OID)).toBeNull();
  });
});

/**
 * Builds a leaf carrying arbitrary extensions, reusing the suite's own chain
 * fixture for its keys and names. It exists only for the duplicate-OID case, so
 * it is local to this spec rather than in the shared builder.
 */
function buildLeafWithExtensions(chain: ReturnType<typeof buildSyntheticChain>, extensions: Buffer[]): Buffer {
  const intermediateKeyPair = generateEcKeyPair();
  const now = new Date();
  return buildCertificate({
    subjectCommonName: 'WP-26 Test Attested Key',
    issuerCommonName: 'WP-26 Test Attestation Intermediate',
    subjectPublicKey: chain.leafKeyPair.publicKey,
    issuerPrivateKey: intermediateKeyPair.privateKey,
    serial: 99,
    notBefore: new Date(now.getTime() - 1000),
    notAfter: new Date(now.getTime() + 86_400_000),
    isCertificateAuthority: false,
    extraExtensions: extensions,
  }).der;
}
