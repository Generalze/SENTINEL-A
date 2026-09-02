/**
 * ============================================================================
 * WP-26/D26-04B — A SMALL, FOCUSED DER READER FOR ANDROID KEY ATTESTATION.
 *
 * WHY THIS FILE EXISTS INSTEAD OF AN ASN.1 DEPENDENCY
 * ---------------------------------------------------
 * This is a security-critical path: the bytes read here decide whether a
 * physical device is granted the first `HARDWARE_BACKED` value in Sentinel's
 * history. This project already hand-verified base64url canonicalisation for
 * exactly that reason (`device-signature.ts`), and `p256-key.importer.ts`
 * hand-wrote a fixed SPKI header rather than assemble one at runtime. A
 * general-purpose ASN.1 library on this path would be a large, transitively
 * dependent, mostly unused decoder that every future auditor would have to take
 * on trust; what is needed is the ~200 lines that read ONE extension.
 *
 * WHAT THIS READER DELIBERATELY DOES NOT DO
 * -----------------------------------------
 *   * It does NOT verify signatures. `node:crypto`'s `X509Certificate.verify()`
 *     does that, using OpenSSL, for the same reason `p256-key.importer.ts`
 *     refuses to implement curve arithmetic: the platform already does it
 *     correctly and a second implementation is a second thing to be wrong.
 *   * It does NOT accept BER. Indefinite lengths, non-minimal lengths and
 *     trailing bytes are all REFUSED. A certificate is a signed object; if two
 *     parsers can disagree about what it says, the signature stops meaning
 *     anything. Strictness here is not fastidiousness, it is the property.
 *   * It has NO error channel, for the `P256KeyImporter` reason: every failure
 *     returns `null`. A caller able to distinguish "not a SEQUENCE" from "tag
 *     number too large" from "length overruns the buffer" holds a parser
 *     oracle, and the only safe action for all of them is identical.
 *
 * EVERYTHING BELOW IS PURE. No I/O, no clock, no injected state, no throwing.
 * ============================================================================
 */

/** DER tag classes, as the two high bits of an identifier octet encode them. */
const TAG_CLASS_UNIVERSAL = 0x00;
const TAG_CLASS_CONTEXT = 0x02;

/** The universal tag numbers this reader understands. */
const UNIVERSAL_BOOLEAN = 0x01;
const UNIVERSAL_INTEGER = 0x02;
const UNIVERSAL_OCTET_STRING = 0x04;
const UNIVERSAL_OBJECT_IDENTIFIER = 0x06;
const UNIVERSAL_ENUMERATED = 0x0a;
const UNIVERSAL_SEQUENCE = 0x10;
const UNIVERSAL_SET = 0x11;

/**
 * The largest integer this reader will return.
 *
 * Every integer the KeyDescription actually carries — a version, a security
 * level, a key size, an origin — is small. Refusing anything that does not fit
 * in 6 bytes means a hostile certificate cannot hand us a bignum that silently
 * loses precision when it becomes a JavaScript number, which would be a
 * comparison quietly passing on a value nobody read.
 */
const MAX_INTEGER_BYTES = 6;

/** A parsed TLV. `content` is a VIEW into the source buffer, never a copy. */
export interface DerNode {
  readonly tagClass: number;
  readonly constructed: boolean;
  readonly tagNumber: number;
  readonly content: Buffer;
  /** Identifier + length + content, so a caller can walk a sequence. */
  readonly totalLength: number;
}

/**
 * Reads ONE TLV at `offset`, or returns `null`.
 *
 * The three refusals that matter are all here: the indefinite length form
 * (BER-only, and the classic way to make two parsers disagree), a non-minimal
 * long-form length, and a length that overruns the buffer.
 */
export function readDerNode(buffer: Buffer, offset = 0): DerNode | null {
  if (offset < 0 || offset >= buffer.length) return null;
  const identifier = buffer[offset] as number;
  const tagClass = (identifier & 0xc0) >> 6;
  const constructed = (identifier & 0x20) !== 0;
  let cursor = offset + 1;

  let tagNumber = identifier & 0x1f;
  if (tagNumber === 0x1f) {
    // High-tag-number form. The KeyDescription's authorisation list uses it for
    // every tag above 30 — `noAuthRequired` is [503], `origin` is [702] — so it
    // is not an exotic case here, it is the common one.
    tagNumber = 0;
    let shifted = 0;
    for (;;) {
      if (cursor >= buffer.length) return null;
      const octet = buffer[cursor] as number;
      cursor += 1;
      // A leading 0x80 is the non-minimal encoding of a tag number, refused for
      // the same reason a non-minimal length is.
      if (shifted === 0 && octet === 0x80) return null;
      tagNumber = tagNumber * 128 + (octet & 0x7f);
      shifted += 1;
      if (shifted > 4) return null;
      if ((octet & 0x80) === 0) break;
    }
  }

  if (cursor >= buffer.length) return null;
  const firstLengthOctet = buffer[cursor] as number;
  cursor += 1;
  let length: number;
  if ((firstLengthOctet & 0x80) === 0) {
    length = firstLengthOctet;
  } else {
    const lengthOctets = firstLengthOctet & 0x7f;
    // 0x80 is the INDEFINITE length form: legal in BER, forbidden in DER.
    if (lengthOctets === 0) return null;
    if (lengthOctets > 4) return null;
    if (cursor + lengthOctets > buffer.length) return null;
    length = 0;
    for (let index = 0; index < lengthOctets; index += 1) {
      length = length * 256 + (buffer[cursor + index] as number);
    }
    cursor += lengthOctets;
    // Minimality: a value below 128 must have used the short form, and a
    // leading zero octet is padding DER does not permit.
    if (length < 128) return null;
    if ((buffer[cursor - lengthOctets] as number) === 0x00) return null;
  }

  if (cursor + length > buffer.length) return null;
  return {
    tagClass,
    constructed,
    tagNumber,
    content: buffer.subarray(cursor, cursor + length),
    totalLength: cursor + length - offset,
  };
}

/**
 * Reads a TLV that must occupy the WHOLE buffer.
 *
 * Trailing bytes after a complete structure are refused rather than ignored:
 * an appended TLV that one parser drops and another reads is precisely the
 * ambiguity a signature is supposed to eliminate.
 */
export function readDerNodeExact(buffer: Buffer): DerNode | null {
  const node = readDerNode(buffer, 0);
  if (node === null) return null;
  return node.totalLength === buffer.length ? node : null;
}

/** Every child TLV of a constructed node, or `null` if the contents do not tile exactly. */
export function readDerChildren(node: DerNode): DerNode[] | null {
  if (!node.constructed) return null;
  const children: DerNode[] = [];
  let offset = 0;
  while (offset < node.content.length) {
    const child = readDerNode(node.content, offset);
    if (child === null) return null;
    children.push(child);
    offset += child.totalLength;
    // Guards against a zero-length step turning a malformed structure into an
    // infinite loop. `totalLength` is always >= 2, but the loop must not depend
    // on a fact established elsewhere in the file.
    if (child.totalLength <= 0) return null;
  }
  return offset === node.content.length ? children : null;
}

/** True when `node` is the universal SEQUENCE tag. */
export function isSequence(node: DerNode): boolean {
  return node.tagClass === TAG_CLASS_UNIVERSAL && node.constructed && node.tagNumber === UNIVERSAL_SEQUENCE;
}

/** True when `node` is the universal SET tag. */
export function isSet(node: DerNode): boolean {
  return node.tagClass === TAG_CLASS_UNIVERSAL && node.constructed && node.tagNumber === UNIVERSAL_SET;
}

/** True when `node` is a context-specific `[tagNumber]`. */
export function isContext(node: DerNode, tagNumber: number): boolean {
  return node.tagClass === TAG_CLASS_CONTEXT && node.tagNumber === tagNumber;
}

/**
 * A non-negative DER INTEGER or ENUMERATED as a JavaScript number.
 *
 * Negative values, non-minimal encodings and anything wider than
 * `MAX_INTEGER_BYTES` are refused. Nothing in a KeyDescription is negative or
 * large, so a value that is either is not a value to interpret leniently.
 */
export function readDerUnsignedInteger(node: DerNode): number | null {
  const universal = node.tagClass === TAG_CLASS_UNIVERSAL && !node.constructed;
  if (!universal) return null;
  if (node.tagNumber !== UNIVERSAL_INTEGER && node.tagNumber !== UNIVERSAL_ENUMERATED) return null;
  const bytes = node.content;
  if (bytes.length === 0) return null;
  if (bytes.length > MAX_INTEGER_BYTES) return null;
  const first = bytes[0] as number;
  // The sign bit. A DER INTEGER is two's complement, so a leading byte >= 0x80
  // is negative — and this reader has no use for a negative value.
  if ((first & 0x80) !== 0) return null;
  // Minimality: 0x00 padding is only legal to clear a sign bit.
  if (bytes.length > 1 && first === 0x00 && ((bytes[1] as number) & 0x80) === 0) return null;
  let value = 0;
  for (const byte of bytes) value = value * 256 + byte;
  return value;
}

/** A DER BOOLEAN. DER fixes TRUE as exactly `0xFF`; anything else is refused. */
export function readDerBoolean(node: DerNode): boolean | null {
  if (node.tagClass !== TAG_CLASS_UNIVERSAL || node.constructed || node.tagNumber !== UNIVERSAL_BOOLEAN) return null;
  if (node.content.length !== 1) return null;
  const byte = node.content[0] as number;
  if (byte === 0x00) return false;
  if (byte === 0xff) return true;
  return null;
}

/** The contents of a primitive OCTET STRING. */
export function readDerOctetString(node: DerNode): Buffer | null {
  if (node.tagClass !== TAG_CLASS_UNIVERSAL || node.constructed || node.tagNumber !== UNIVERSAL_OCTET_STRING) return null;
  return node.content;
}

/**
 * Encodes a dotted OID into its DER content octets.
 *
 * A function rather than a hard-coded constant so the one OID this module cares
 * about — `1.3.6.1.4.1.11129.2.1.17` — can be spelled in the form a reviewer
 * can check against the Android documentation, and so the encoding itself is
 * exercised by test rather than asserted by comment.
 */
export function encodeObjectIdentifier(oid: string): Buffer | null {
  const parts = oid.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length < 2) return null;
  if (parts.some((part) => !Number.isSafeInteger(part) || part < 0)) return null;
  const first = parts[0] as number;
  const second = parts[1] as number;
  if (first > 2) return null;
  if (first < 2 && second >= 40) return null;
  const bytes: number[] = [];
  const emit = (value: number): void => {
    const base128: number[] = [];
    let remaining = value;
    do {
      base128.unshift(remaining % 128);
      remaining = Math.floor(remaining / 128);
    } while (remaining > 0);
    for (let index = 0; index < base128.length - 1; index += 1) {
      bytes.push((base128[index] as number) | 0x80);
    }
    bytes.push(base128[base128.length - 1] as number);
  };
  emit(first * 40 + second);
  for (const part of parts.slice(2)) emit(part);
  return Buffer.from(bytes);
}

/**
 * The extension value for `oid` inside a DER X.509 certificate, or `null`.
 *
 * The walk is Certificate -> TBSCertificate -> [3] EXPLICIT Extensions ->
 * SEQUENCE OF Extension, and it reads the OCTET STRING `extnValue` rather than
 * its contents, because the caller decides what the contents are supposed to
 * be. `node:crypto`'s `X509Certificate` exposes a fixed handful of extensions
 * and not this one, which is the entire reason this walk exists.
 *
 * A certificate carrying the SAME extension OID twice is REFUSED. X.509 forbids
 * it, and "the first one wins" versus "the last one wins" is exactly the kind of
 * disagreement a signed object must not admit.
 */
export function findCertificateExtension(certificateDer: Buffer, oid: string): Buffer | null {
  const wantedOid = encodeObjectIdentifier(oid);
  if (wantedOid === null) return null;

  const certificate = readDerNodeExact(certificateDer);
  if (certificate === null || !isSequence(certificate)) return null;
  const certificateChildren = readDerChildren(certificate);
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  if (certificateChildren === null || certificateChildren.length !== 3) return null;
  const tbs = certificateChildren[0] as DerNode;
  if (!isSequence(tbs)) return null;
  const tbsChildren = readDerChildren(tbs);
  if (tbsChildren === null) return null;

  // TBSCertificate's extensions are `[3] EXPLICIT Extensions OPTIONAL`, always
  // last when present. Searching for the tag rather than counting fields keeps
  // this walk indifferent to the optional `[1]`/`[2]` unique identifiers.
  const extensionsHolder = tbsChildren.find((child) => isContext(child, 3) && child.constructed);
  if (extensionsHolder === undefined) return null;
  const holderChildren = readDerChildren(extensionsHolder);
  if (holderChildren === null || holderChildren.length !== 1) return null;
  const extensions = holderChildren[0] as DerNode;
  if (!isSequence(extensions)) return null;
  const extensionNodes = readDerChildren(extensions);
  if (extensionNodes === null) return null;

  let found: Buffer | null = null;
  for (const extension of extensionNodes) {
    if (!isSequence(extension)) return null;
    const fields = readDerChildren(extension);
    // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }
    if (fields === null || fields.length < 2 || fields.length > 3) return null;
    const extnId = fields[0] as DerNode;
    if (extnId.tagClass !== TAG_CLASS_UNIVERSAL || extnId.constructed || extnId.tagNumber !== UNIVERSAL_OBJECT_IDENTIFIER) {
      return null;
    }
    const extnValue = readDerOctetString(fields[fields.length - 1] as DerNode);
    if (extnValue === null) return null;
    if (!extnId.content.equals(wantedOid)) continue;
    // A duplicate OID is a refusal, not a preference. See this function's header.
    if (found !== null) return null;
    found = extnValue;
  }
  return found;
}

// ---------------------------------------------------------------------------
// The KeyDescription itself
// ---------------------------------------------------------------------------

/**
 * The Android Key Attestation extension OID.
 *
 * `1.3.6.1.4.1.11129.2.1.17` — Google's arc (11129), attestation (2.1.17). Its
 * `extnValue` is the DER encoding of `KeyDescription`.
 */
export const ANDROID_KEY_ATTESTATION_EXTENSION_OID = '1.3.6.1.4.1.11129.2.1.17';

/**
 * The AuthorizationList tags this reader understands.
 *
 * Every tag in the schema that WP-26 does not read is simply skipped: an
 * authorisation list is an extensible structure and a reader that refused
 * unknown tags would break on the next Keymaster version, which is a different
 * failure from the one this code is protecting against. What is NOT skipped is
 * a malformed tag — a `[503]` whose contents are not NULL is a refusal, because
 * that is a structure disagreeing with itself.
 */
const TAG_PURPOSE = 1;
const TAG_ALGORITHM = 2;
const TAG_KEY_SIZE = 3;
const TAG_EC_CURVE = 10;
const TAG_NO_AUTH_REQUIRED = 503;
const TAG_ORIGIN = 702;
const TAG_ROOT_OF_TRUST = 704;
const TAG_ATTESTATION_APPLICATION_ID = 709;

/** The AttestationApplicationId, as the extension carries it. */
export interface AndroidAttestationApplicationId {
  /** The package names claimed, in the order recorded. */
  readonly packageNames: readonly string[];
  /** Lowercase hex SHA-256 signing-certificate digests, sorted ascending. */
  readonly signatureDigests: readonly string[];
}

/** The `teeEnforced` / `softwareEnforced` fields WP-26 actually reads. */
export interface AndroidAuthorizationList {
  /** KeyPurpose values, sorted ascending. Empty when the tag is absent. */
  readonly purposes: readonly number[];
  readonly algorithm: number | null;
  readonly keySize: number | null;
  readonly ecCurve: number | null;
  readonly origin: number | null;
  readonly noAuthRequired: boolean;
  readonly rootOfTrust: AndroidRootOfTrust | null;
  readonly attestationApplicationId: AndroidAttestationApplicationId | null;
}

export interface AndroidRootOfTrust {
  readonly deviceLocked: boolean;
  /** 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed. */
  readonly verifiedBootState: number;
}

/** The parsed `KeyDescription`. */
export interface AndroidKeyDescription {
  readonly attestationVersion: number;
  /** 0 Software, 1 TrustedEnvironment, 2 StrongBox. */
  readonly attestationSecurityLevel: number;
  readonly keymasterVersion: number;
  readonly keymasterSecurityLevel: number;
  /** The exact bytes the key was generated against. Compared, never trusted. */
  readonly attestationChallenge: Buffer;
  readonly softwareEnforced: AndroidAuthorizationList;
  readonly teeEnforced: AndroidAuthorizationList;
}

/**
 * Parses `KeyDescription` from an extension value, or returns `null`.
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion         INTEGER,
 *     attestationSecurityLevel   SecurityLevel,
 *     keymasterVersion           INTEGER,
 *     keymasterSecurityLevel     SecurityLevel,
 *     attestationChallenge       OCTET_STRING,
 *     uniqueId                   OCTET_STRING,
 *     softwareEnforced           AuthorizationList,
 *     teeEnforced                AuthorizationList }
 *
 * `uniqueId` is read to prove the structure is the shape it claims and is then
 * DISCARDED. It is a device-scoped identifier Sentinel has no use for and no
 * business retaining, and the schema is positional, so it cannot simply be
 * skipped.
 */
export function parseAndroidKeyDescription(extensionValue: Buffer): AndroidKeyDescription | null {
  const root = readDerNodeExact(extensionValue);
  if (root === null || !isSequence(root)) return null;
  const fields = readDerChildren(root);
  if (fields === null || fields.length !== 8) return null;

  const attestationVersion = readDerUnsignedInteger(fields[0] as DerNode);
  const attestationSecurityLevel = readDerUnsignedInteger(fields[1] as DerNode);
  const keymasterVersion = readDerUnsignedInteger(fields[2] as DerNode);
  const keymasterSecurityLevel = readDerUnsignedInteger(fields[3] as DerNode);
  const attestationChallenge = readDerOctetString(fields[4] as DerNode);
  const uniqueId = readDerOctetString(fields[5] as DerNode);
  if (
    attestationVersion === null ||
    attestationSecurityLevel === null ||
    keymasterVersion === null ||
    keymasterSecurityLevel === null ||
    attestationChallenge === null ||
    uniqueId === null
  ) {
    return null;
  }

  const softwareEnforced = parseAuthorizationList(fields[6] as DerNode);
  const teeEnforced = parseAuthorizationList(fields[7] as DerNode);
  if (softwareEnforced === null || teeEnforced === null) return null;

  return {
    attestationVersion,
    attestationSecurityLevel,
    keymasterVersion,
    keymasterSecurityLevel,
    // Copied out of the source buffer: the caller compares these bytes against
    // a server challenge and must not hold a view whose backing store it does
    // not own.
    attestationChallenge: Buffer.from(attestationChallenge),
    softwareEnforced,
    teeEnforced,
  };
}

function parseAuthorizationList(node: DerNode): AndroidAuthorizationList | null {
  if (!isSequence(node)) return null;
  const entries = readDerChildren(node);
  if (entries === null) return null;

  let purposes: number[] = [];
  let algorithm: number | null = null;
  let keySize: number | null = null;
  let ecCurve: number | null = null;
  let origin: number | null = null;
  let noAuthRequired = false;
  let rootOfTrust: AndroidRootOfTrust | null = null;
  let attestationApplicationId: AndroidAttestationApplicationId | null = null;

  let previousTag = -1;
  for (const entry of entries) {
    if (entry.tagClass !== TAG_CLASS_CONTEXT || !entry.constructed) return null;
    // The list is DER SEQUENCE-tagged and its members are strictly ascending. A
    // repeated or out-of-order tag is a structure two readers could disagree
    // about, so it is refused rather than tolerated.
    if (entry.tagNumber <= previousTag) return null;
    previousTag = entry.tagNumber;

    const inner = readDerChildren(entry);
    if (inner === null || inner.length !== 1) return null;
    const value = inner[0] as DerNode;

    switch (entry.tagNumber) {
      case TAG_PURPOSE: {
        if (!isSet(value)) return null;
        const members = readDerChildren(value);
        if (members === null) return null;
        const parsed: number[] = [];
        for (const member of members) {
          const purpose = readDerUnsignedInteger(member);
          if (purpose === null) return null;
          parsed.push(purpose);
        }
        purposes = [...parsed].sort((left, right) => left - right);
        break;
      }
      case TAG_ALGORITHM:
        algorithm = readDerUnsignedInteger(value);
        if (algorithm === null) return null;
        break;
      case TAG_KEY_SIZE:
        keySize = readDerUnsignedInteger(value);
        if (keySize === null) return null;
        break;
      case TAG_EC_CURVE:
        ecCurve = readDerUnsignedInteger(value);
        if (ecCurve === null) return null;
        break;
      case TAG_NO_AUTH_REQUIRED:
        // `noAuthRequired ::= NULL` — its PRESENCE is the value. A `[503]`
        // carrying anything else is a malformed list.
        if (value.tagClass !== TAG_CLASS_UNIVERSAL || value.constructed || value.tagNumber !== 0x05) return null;
        if (value.content.length !== 0) return null;
        noAuthRequired = true;
        break;
      case TAG_ORIGIN:
        origin = readDerUnsignedInteger(value);
        if (origin === null) return null;
        break;
      case TAG_ROOT_OF_TRUST:
        rootOfTrust = parseRootOfTrust(value);
        if (rootOfTrust === null) return null;
        break;
      case TAG_ATTESTATION_APPLICATION_ID: {
        const wrapped = readDerOctetString(value);
        if (wrapped === null) return null;
        attestationApplicationId = parseAttestationApplicationId(wrapped);
        if (attestationApplicationId === null) return null;
        break;
      }
      default:
        // An authorisation tag WP-26 does not read. Skipped deliberately — see
        // the tag block's header.
        break;
    }
  }

  return { purposes, algorithm, keySize, ecCurve, origin, noAuthRequired, rootOfTrust, attestationApplicationId };
}

/**
 *   RootOfTrust ::= SEQUENCE {
 *     verifiedBootKey    OCTET_STRING,
 *     deviceLocked       BOOLEAN,
 *     verifiedBootState  VerifiedBootState,
 *     verifiedBootHash   OCTET_STRING }
 *
 * `verifiedBootHash` was added in attestation version 3, so a three-field
 * structure is accepted from an older device. `verifiedBootKey` and
 * `verifiedBootHash` are read for structural validity and discarded: they are
 * device-identifying material Sentinel does not need in order to answer the one
 * question it is asking, which is whether the boot state is acceptable.
 */
function parseRootOfTrust(node: DerNode): AndroidRootOfTrust | null {
  if (!isSequence(node)) return null;
  const fields = readDerChildren(node);
  if (fields === null || fields.length < 3 || fields.length > 4) return null;
  if (readDerOctetString(fields[0] as DerNode) === null) return null;
  const deviceLocked = readDerBoolean(fields[1] as DerNode);
  const verifiedBootState = readDerUnsignedInteger(fields[2] as DerNode);
  if (deviceLocked === null || verifiedBootState === null) return null;
  if (fields.length === 4 && readDerOctetString(fields[3] as DerNode) === null) return null;
  return { deviceLocked, verifiedBootState };
}

/**
 *   AttestationApplicationId ::= SEQUENCE {
 *     packageInfos      SET OF AttestationPackageInfo,
 *     signatureDigests  SET OF OCTET_STRING }
 *   AttestationPackageInfo ::= SEQUENCE {
 *     packageName  OCTET_STRING,
 *     version      INTEGER }
 *
 * The package name is decoded as UTF-8 and refused if it does not round-trip.
 * A name that is not valid UTF-8 cannot be compared against a configured
 * expectation without the comparison silently becoming a comparison of
 * replacement characters.
 */
function parseAttestationApplicationId(value: Buffer): AndroidAttestationApplicationId | null {
  const root = readDerNodeExact(value);
  if (root === null || !isSequence(root)) return null;
  const fields = readDerChildren(root);
  if (fields === null || fields.length !== 2) return null;

  const packageSet = fields[0] as DerNode;
  const digestSet = fields[1] as DerNode;
  if (!isSet(packageSet) || !isSet(digestSet)) return null;

  const packageEntries = readDerChildren(packageSet);
  if (packageEntries === null) return null;
  const packageNames: string[] = [];
  for (const entry of packageEntries) {
    if (!isSequence(entry)) return null;
    const parts = readDerChildren(entry);
    if (parts === null || parts.length !== 2) return null;
    const nameBytes = readDerOctetString(parts[0] as DerNode);
    if (nameBytes === null) return null;
    if (readDerUnsignedInteger(parts[1] as DerNode) === null) return null;
    const name = nameBytes.toString('utf8');
    if (!Buffer.from(name, 'utf8').equals(nameBytes)) return null;
    packageNames.push(name);
  }

  const digestEntries = readDerChildren(digestSet);
  if (digestEntries === null) return null;
  const signatureDigests: string[] = [];
  for (const entry of digestEntries) {
    const digest = readDerOctetString(entry);
    if (digest === null) return null;
    signatureDigests.push(digest.toString('hex'));
  }

  return { packageNames, signatureDigests: [...signatureDigests].sort() };
}
