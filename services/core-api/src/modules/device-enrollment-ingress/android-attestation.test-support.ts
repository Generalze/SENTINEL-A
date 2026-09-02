import { X509Certificate, createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import {
  ANDROID_EC_CURVE_P256,
  ANDROID_KEY_ALGORITHM_EC,
  ANDROID_KEY_ORIGIN_GENERATED,
  ANDROID_KEY_PURPOSE_SIGN,
  ANDROID_KEY_SIZE_P256,
  ANDROID_SECURITY_LEVEL_STRONGBOX,
  ANDROID_VERIFIED_BOOT_STATE_VERIFIED,
} from './device-enrollment-ingress.constants';
import { ANDROID_KEY_ATTESTATION_EXTENSION_OID, encodeObjectIdentifier } from './android-attestation.der';

/**
 * ============================================================================
 * WP-26 SYNTHETIC ANDROID KEY ATTESTATION CHAINS — TEST SUPPORT ONLY.
 *
 * A SYNTHETIC CHAIN IS NOT A PHYSICAL DEVICE, AND THIS IS NOT PROOF C.
 *
 * Everything this file builds is a certificate chain THIS PROCESS generated,
 * rooted in a test CA THIS PROCESS generated, carrying a `KeyDescription` THIS
 * PROCESS encoded. There is no StrongBox anywhere near it, no TEE, no
 * non-exportable key and no Google root. What a passing test built on this
 * proves is that the VERIFIER's logic is correct — that it refuses a chain whose
 * challenge is wrong, whose leaf key is not the submitted key, whose root is not
 * pinned, whose security level is TEE rather than StrongBox, and so on.
 *
 * It proves NOTHING about hardware. D26-10 is explicit that an emulator is not a
 * hardware test, and a certificate builder is one step further from hardware
 * than an emulator. Physical-device acceptance — genuine supported Android
 * hardware, StrongBox available, a server-issued challenge, a key that attests
 * as StrongBox, a private key that is non-exportable — is required to close
 * WP-26, and is STILL NOT Proof C.
 *
 * THIS FILE IS NOT A PRODUCTION PATH. It is the only DER *encoder* in the
 * module; the production reader (`android-attestation.der.ts`) decodes and never
 * encodes, and nothing in `src` outside a spec imports this file. The boundary
 * guard asserts that.
 *
 * It lives beside the module, following the `shield.test-support.ts` and
 * `patrol-sweep.scheduler.test-support.ts` precedent, so every spec builds a
 * chain the same way. A builder duplicated per spec is a builder that drifts,
 * and a spec whose fixture drifts from the parser it feeds stops testing the
 * thing it claims to.
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// A minimal DER ENCODER. Mirror image of the production reader, and test-only.
// ---------------------------------------------------------------------------

function derLength(length: number): Buffer {
  if (length < 128) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTlv(identifier: Buffer, content: Buffer): Buffer {
  return Buffer.concat([identifier, derLength(content.length), content]);
}

/** A context-specific `[tagNumber]` identifier, constructed, in the correct tag form. */
function contextIdentifier(tagNumber: number): Buffer {
  if (tagNumber < 0x1f) return Buffer.from([0xa0 | tagNumber]);
  const base128: number[] = [];
  let remaining = tagNumber;
  do {
    base128.unshift(remaining % 128);
    remaining = Math.floor(remaining / 128);
  } while (remaining > 0);
  const bytes = base128.map((value, index) => (index < base128.length - 1 ? value | 0x80 : value));
  return Buffer.from([0xbf, ...bytes]);
}

export const der = {
  sequence: (...children: Buffer[]): Buffer => derTlv(Buffer.from([0x30]), Buffer.concat(children)),
  set: (...children: Buffer[]): Buffer => derTlv(Buffer.from([0x31]), Buffer.concat(children)),
  integer: (value: number): Buffer => derTlv(Buffer.from([0x02]), unsignedIntegerBytes(value)),
  enumerated: (value: number): Buffer => derTlv(Buffer.from([0x0a]), unsignedIntegerBytes(value)),
  octetString: (value: Buffer): Buffer => derTlv(Buffer.from([0x04]), value),
  boolean: (value: boolean): Buffer => derTlv(Buffer.from([0x01]), Buffer.from([value ? 0xff : 0x00])),
  null: (): Buffer => Buffer.from([0x05, 0x00]),
  bitString: (value: Buffer): Buffer => derTlv(Buffer.from([0x03]), Buffer.concat([Buffer.from([0x00]), value])),
  oid: (dotted: string): Buffer => {
    const encoded = encodeObjectIdentifier(dotted);
    if (encoded === null) throw new Error(`unencodable OID: ${dotted}`);
    return derTlv(Buffer.from([0x06]), encoded);
  },
  utf8String: (value: string): Buffer => derTlv(Buffer.from([0x0c]), Buffer.from(value, 'utf8')),
  utcTime: (at: Date): Buffer => {
    const pad = (value: number): string => String(value).padStart(2, '0');
    const text =
      pad(at.getUTCFullYear() % 100) +
      pad(at.getUTCMonth() + 1) +
      pad(at.getUTCDate()) +
      pad(at.getUTCHours()) +
      pad(at.getUTCMinutes()) +
      pad(at.getUTCSeconds()) +
      'Z';
    return derTlv(Buffer.from([0x17]), Buffer.from(text, 'ascii'));
  },
  /** `[tagNumber] EXPLICIT`, the form an AuthorizationList entry uses. */
  contextExplicit: (tagNumber: number, content: Buffer): Buffer => derTlv(contextIdentifier(tagNumber), content),
  raw: (bytes: Buffer): Buffer => bytes,
};

function unsignedIntegerBytes(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`unsupported integer: ${value}`);
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.unshift(remaining % 256);
    remaining = Math.floor(remaining / 256);
  } while (remaining > 0);
  // Clear the sign bit so the value stays positive, exactly as DER requires.
  if ((bytes[0] as number) & 0x80) bytes.unshift(0x00);
  return Buffer.from(bytes);
}

// ---------------------------------------------------------------------------
// The KeyDescription
// ---------------------------------------------------------------------------

export interface KeyDescriptionOptions {
  attestationVersion?: number;
  attestationSecurityLevel?: number;
  keymasterVersion?: number;
  keymasterSecurityLevel?: number;
  /** The bytes placed in `attestationChallenge`. */
  challenge: Buffer;
  purposes?: readonly number[];
  algorithm?: number;
  keySize?: number;
  ecCurve?: number;
  origin?: number;
  includeNoAuthRequired?: boolean;
  includeRootOfTrust?: boolean;
  deviceLocked?: boolean;
  verifiedBootState?: number;
  includeApplicationId?: boolean;
  packageName?: string;
  /** Raw digest bytes; the verifier compares their lowercase hex. */
  signingDigest?: Buffer;
}

export const TEST_PACKAGE_NAME = 'com.sentinel.field';
export const TEST_SIGNING_DIGEST = createHash('sha256').update('wp26-test-signing-identity').digest();

export function buildKeyDescription(options: KeyDescriptionOptions): Buffer {
  const attestationApplicationId = der.sequence(
    der.set(der.sequence(der.octetString(Buffer.from(options.packageName ?? TEST_PACKAGE_NAME, 'utf8')), der.integer(1))),
    der.set(der.octetString(options.signingDigest ?? TEST_SIGNING_DIGEST)),
  );

  // The AuthorizationList's members are strictly ASCENDING by tag — the
  // production reader refuses anything else, and a real list is emitted that way.
  const teeEntries: Buffer[] = [];
  teeEntries.push(der.contextExplicit(1, der.set(...(options.purposes ?? [ANDROID_KEY_PURPOSE_SIGN]).map((p) => der.integer(p)))));
  teeEntries.push(der.contextExplicit(2, der.integer(options.algorithm ?? ANDROID_KEY_ALGORITHM_EC)));
  teeEntries.push(der.contextExplicit(3, der.integer(options.keySize ?? ANDROID_KEY_SIZE_P256)));
  teeEntries.push(der.contextExplicit(10, der.integer(options.ecCurve ?? ANDROID_EC_CURVE_P256)));
  if (options.includeNoAuthRequired ?? true) teeEntries.push(der.contextExplicit(503, der.null()));
  teeEntries.push(der.contextExplicit(702, der.integer(options.origin ?? ANDROID_KEY_ORIGIN_GENERATED)));
  if (options.includeRootOfTrust ?? true) {
    teeEntries.push(
      der.contextExplicit(
        704,
        der.sequence(
          der.octetString(Buffer.alloc(32, 0x11)),
          der.boolean(options.deviceLocked ?? true),
          der.enumerated(options.verifiedBootState ?? ANDROID_VERIFIED_BOOT_STATE_VERIFIED),
          der.octetString(Buffer.alloc(32, 0x22)),
        ),
      ),
    );
  }
  if (options.includeApplicationId ?? true) {
    teeEntries.push(der.contextExplicit(709, der.octetString(attestationApplicationId)));
  }

  return der.sequence(
    der.integer(options.attestationVersion ?? 4),
    der.enumerated(options.attestationSecurityLevel ?? ANDROID_SECURITY_LEVEL_STRONGBOX),
    der.integer(options.keymasterVersion ?? 41),
    der.enumerated(options.keymasterSecurityLevel ?? ANDROID_SECURITY_LEVEL_STRONGBOX),
    der.octetString(options.challenge),
    der.octetString(Buffer.alloc(0)),
    // softwareEnforced: deliberately EMPTY. The verifier reads `teeEnforced`
    // only, and a fixture that populated the software list would make it easy to
    // write a test that passes for the wrong reason.
    der.sequence(),
    der.sequence(...teeEntries),
  );
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/** `ecdsa-with-SHA256`. The one signature algorithm these fixtures use. */
const ECDSA_WITH_SHA256_OID = '1.2.840.10045.4.3.2';
/** `id-at-commonName`. */
const COMMON_NAME_OID = '2.5.4.3';
/** `id-ce-basicConstraints`. */
const BASIC_CONSTRAINTS_OID = '2.5.29.19';

export interface TestKeyPair {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

export function generateEcKeyPair(): TestKeyPair {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

function name(commonName: string): Buffer {
  return der.sequence(der.set(der.sequence(der.oid(COMMON_NAME_OID), der.utf8String(commonName))));
}

export interface CertificateOptions {
  subjectCommonName: string;
  issuerCommonName: string;
  subjectPublicKey: KeyObject;
  issuerPrivateKey: KeyObject;
  serial: number;
  notBefore: Date;
  notAfter: Date;
  isCertificateAuthority: boolean;
  /** Fully-encoded `Extension` structures to append, e.g. the attestation one. */
  extraExtensions?: readonly Buffer[];
}

/** One `Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }`. */
export function extension(oid: string, value: Buffer, critical = false): Buffer {
  return critical
    ? der.sequence(der.oid(oid), der.boolean(true), der.octetString(value))
    : der.sequence(der.oid(oid), der.octetString(value));
}

/** The Android Key Attestation extension, ready to place on a leaf certificate. */
export function attestationExtension(keyDescription: Buffer): Buffer {
  return extension(ANDROID_KEY_ATTESTATION_EXTENSION_OID, keyDescription);
}

export function buildCertificate(options: CertificateOptions): { der: Buffer; base64: string; certificate: X509Certificate } {
  const algorithm = der.sequence(der.oid(ECDSA_WITH_SHA256_OID));
  const extensions: Buffer[] = [
    extension(BASIC_CONSTRAINTS_OID, der.sequence(...(options.isCertificateAuthority ? [der.boolean(true)] : [])), true),
    ...(options.extraExtensions ?? []),
  ];

  const tbs = der.sequence(
    // [0] EXPLICIT version, v3.
    der.contextExplicit(0, der.integer(2)),
    der.integer(options.serial),
    algorithm,
    name(options.issuerCommonName),
    der.sequence(der.utcTime(options.notBefore), der.utcTime(options.notAfter)),
    name(options.subjectCommonName),
    Buffer.from(options.subjectPublicKey.export({ format: 'der', type: 'spki' })),
    der.contextExplicit(3, der.sequence(...extensions)),
  );

  // DER-encoded ECDSA, which is what an X.509 signature carries. `crypto.sign`
  // emits that form by default for EC keys.
  const signature = cryptoSign('sha256', tbs, options.issuerPrivateKey);
  const certificateDer = der.sequence(tbs, algorithm, der.bitString(signature));
  return {
    der: certificateDer,
    base64: certificateDer.toString('base64'),
    certificate: new X509Certificate(certificateDer),
  };
}

// ---------------------------------------------------------------------------
// A whole chain
// ---------------------------------------------------------------------------

export interface SyntheticChainOptions {
  /** The device key the leaf attests to. Defaults to a fresh pair. */
  leafKeyPair?: TestKeyPair;
  /** The bytes to place inside `attestationChallenge`. */
  challenge: Buffer;
  /** Override the KeyDescription the leaf carries. */
  keyDescription?: Partial<KeyDescriptionOptions>;
  /** Omit the attestation extension entirely. */
  omitAttestationExtension?: boolean;
  /** The instant the certificates are dated around. */
  now?: Date;
  /** Move the whole chain's validity window, e.g. to build an expired chain. */
  notBefore?: Date;
  notAfter?: Date;
  /** Serial numbers, so a revocation snapshot can name one. */
  rootSerial?: number;
  intermediateSerial?: number;
  leafSerial?: number;
  /** Use a caller-supplied root, e.g. to build a chain to an UNPINNED root. */
  rootKeyPair?: TestKeyPair;
  rootCommonName?: string;
}

export interface SyntheticChain {
  /** Base64 DER, LEAF FIRST — the order the ingress accepts. */
  readonly chainBase64: string[];
  readonly leafKeyPair: TestKeyPair;
  readonly rootKeyPair: TestKeyPair;
  /** The root as an `X509Certificate`, ready to be PINNED as a trust anchor. */
  readonly root: X509Certificate;
  readonly leafSerial: number;
  readonly intermediateSerial: number;
}

/**
 * Builds root -> intermediate -> leaf, with the leaf carrying a crafted
 * `KeyDescription`.
 *
 * Three certificates rather than two because a real Android chain has an
 * intermediate, and a verifier tested only against a two-certificate chain would
 * not exercise the link-by-link walk at all.
 */
export function buildSyntheticChain(options: SyntheticChainOptions): SyntheticChain {
  const now = options.now ?? new Date();
  const notBefore = options.notBefore ?? new Date(now.getTime() - 86_400_000);
  const notAfter = options.notAfter ?? new Date(now.getTime() + 86_400_000);

  const rootKeyPair = options.rootKeyPair ?? generateEcKeyPair();
  const intermediateKeyPair = generateEcKeyPair();
  const leafKeyPair = options.leafKeyPair ?? generateEcKeyPair();

  const rootCommonName = options.rootCommonName ?? 'WP-26 Test Attestation Root';
  const intermediateCommonName = 'WP-26 Test Attestation Intermediate';

  const rootSerial = options.rootSerial ?? 1;
  const intermediateSerial = options.intermediateSerial ?? 2;
  const leafSerial = options.leafSerial ?? 3;

  const root = buildCertificate({
    subjectCommonName: rootCommonName,
    issuerCommonName: rootCommonName,
    subjectPublicKey: rootKeyPair.publicKey,
    issuerPrivateKey: rootKeyPair.privateKey,
    serial: rootSerial,
    notBefore,
    notAfter,
    isCertificateAuthority: true,
  });

  const intermediate = buildCertificate({
    subjectCommonName: intermediateCommonName,
    issuerCommonName: rootCommonName,
    subjectPublicKey: intermediateKeyPair.publicKey,
    issuerPrivateKey: rootKeyPair.privateKey,
    serial: intermediateSerial,
    notBefore,
    notAfter,
    isCertificateAuthority: true,
  });

  const keyDescription = buildKeyDescription({ challenge: options.challenge, ...options.keyDescription });
  const leaf = buildCertificate({
    subjectCommonName: 'WP-26 Test Attested Key',
    issuerCommonName: intermediateCommonName,
    subjectPublicKey: leafKeyPair.publicKey,
    issuerPrivateKey: intermediateKeyPair.privateKey,
    serial: leafSerial,
    notBefore,
    notAfter,
    isCertificateAuthority: false,
    extraExtensions: options.omitAttestationExtension === true ? [] : [attestationExtension(keyDescription)],
  });

  return {
    // LEAF FIRST, then the intermediate. The ROOT is deliberately NOT included
    // by default: a verifier must anchor on SERVER configuration, and a chain
    // that carries its own root is exactly the shape that tempts an
    // implementation to trust one.
    chainBase64: [leaf.base64, intermediate.base64],
    leafKeyPair,
    rootKeyPair,
    root: root.certificate,
    leafSerial,
    intermediateSerial,
  };
}

/**
 * The canonical unpadded base64url SEC1 point for a test key — the ONE
 * representation WP-23 accepts.
 *
 * Node emits a 91-byte SPKI for P-256; the last 65 bytes are the uncompressed
 * point. Slicing rather than re-encoding keeps this helper free of ASN.1 of its
 * own, exactly as `shield.test-support.ts` does for the same value.
 */
const P256_SPKI_HEADER_BYTES = 26;

export function canonicalPublicKeyOf(keyPair: TestKeyPair): string {
  const spki = keyPair.publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(spki.subarray(P256_SPKI_HEADER_BYTES)).toString('base64url');
}
