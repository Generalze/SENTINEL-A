import { Injectable } from '@nestjs/common';
import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import {
  decodeCanonicalP256PublicKey,
  decodeCanonicalP256Signature,
  bindClaimedSignatureProfile,
  P256_PUBLIC_KEY_BYTES,
} from '@sentinel/contracts';

/**
 * WP-24/D24-05 — THE RUNTIME CRYPTOGRAPHIC BOUNDARY.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `device-signature.ts` says, in its own words, that it performs no curve
 * arithmetic: it fixes the ONE accepted representation of a P-256 public key
 * (uncompressed SEC1 `0x04 || X || Y`, 65 bytes, canonical unpadded base64url)
 * and refuses everything else STRUCTURALLY. It explicitly defers one question:
 *
 *     "Whether (x, y) actually satisfies the curve equation is the runtime
 *      verifier's job at the moment it imports the key."
 *
 * This is that moment. A structurally perfect but OFF-CURVE point parses
 * cleanly at every contract boundary in WP-23 — that is the documented limit
 * of a contracts package, not a defect in it — and must be stopped here,
 * before it can be registered as an active verification credential.
 *
 * NO ELLIPTIC-CURVE ARITHMETIC IS IMPLEMENTED IN THIS FILE, and none is
 * implemented anywhere in WP-24 (D24-05). The curve check is performed by the
 * platform provider: the point is wrapped in a DER SubjectPublicKeyInfo naming
 * `prime256v1` and handed to `crypto.createPublicKey`, and OpenSSL's own point
 * decoder rejects a point that is not on the curve. Hand-rolling the check
 * would mean shipping a second, unreviewed implementation of the exact
 * arithmetic the platform already does correctly.
 *
 * NO ERROR CHANNEL, FOR THE `WhisperSignatureVerifier` REASON
 * ----------------------------------------------------------
 * Every failure returns `null` or `false`. A caller able to distinguish "that
 * point is not on the curve" from "that key is not registered" from "the
 * signature did not verify" holds an oracle over the registry and over the
 * curve check, and the only safe action for all three is identical: refuse.
 * The refusal REASON is available to internal audit through the contract's own
 * `DeviceP256PublicKeyRejection` / `DeviceSignatureRejection` vocabularies at
 * the parse boundary; it is deliberately not surfaced from here.
 */

/**
 * The fixed DER SubjectPublicKeyInfo prefix for an uncompressed P-256 point.
 *
 * It is a CONSTANT, not something assembled at runtime, because every byte of
 * it is fixed by the standard and an assembled version would be a small ASN.1
 * encoder nobody asked for:
 *
 *   30 59                      SEQUENCE, 89 bytes
 *     30 13                    SEQUENCE, 19 bytes  (AlgorithmIdentifier)
 *       06 07 2A8648CE3D0201     OID 1.2.840.10045.2.1   id-ecPublicKey
 *       06 08 2A8648CE3D030107   OID 1.2.840.10045.3.1.7 prime256v1
 *     03 42 00                 BIT STRING, 66 bytes, 0 unused bits
 *                              ... followed by the 65 point bytes
 *
 * 26 + 65 = 91 bytes, which is exactly what Node itself emits for a P-256
 * public key exported as DER SPKI. The named curve in the header is the second
 * half of the D24-05 check: it is what makes an import fail for a point from
 * any other curve rather than succeed as some other key.
 */
const P256_SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

/** What `asymmetricKeyType` must be. Anything else is refused, never interpreted. */
const EC_KEY_TYPE = 'ec';

/** What `asymmetricKeyDetails.namedCurve` must be. OpenSSL's name for P-256. */
const P256_NAMED_CURVE = 'prime256v1';

/**
 * The digest the M3 signature profile fixes. `P256_ECDSA_SHA256` names it in
 * the profile string itself; it is repeated here because `crypto.verify` needs
 * it as an argument, and it is never read from anything a client sent.
 */
const P256_DIGEST_ALGORITHM = 'sha256';

/**
 * IEEE P1363 raw `r || s`. This is not a preference — `decodeCanonicalP256Signature`
 * accepts exactly this form and refuses DER, so telling the verifier anything
 * else would mean verifying bytes the contract never validated.
 */
const P256_SIGNATURE_ENCODING = 'ieee-p1363';

export interface P256SignatureVerificationInput {
  /** The canonical base64url uncompressed point, from the SERVER registry. */
  readonly registeredPublicKey: string;
  /** The exact canonical statement bytes the signature must cover. */
  readonly message: string;
  /** The canonical base64url IEEE-P1363 signature, as submitted. */
  readonly signature: string;
  /** C15-01: the profile the SERVER resolved from its own registry record. */
  readonly serverResolvedProfile: unknown;
  /** C15-01: the profile the CLIENT claimed. Equality-bound, never consulted. */
  readonly claimedProfile: unknown;
}

/**
 * D24-05's runtime seam, as an injectable collaborator.
 *
 * It is a class rather than two free functions for the reason
 * `WhisperSignatureVerifier` is: the services that depend on it declare that
 * dependency, so the crypto boundary is visible in the module graph instead of
 * being an import somebody can add anywhere.
 */
@Injectable()
export class P256KeyImporter {
  /**
   * Imports a canonical P-256 public key, or returns `null`.
   *
   * The order is the D24-05 order and it matters. The contract's structural
   * decode runs FIRST, so a padded, non-canonical, compressed, DER, wrong
   * length or out-of-field-range value never reaches the provider at all — a
   * hostile client cannot steer OpenSSL's parser. Only bytes that are already
   * the one accepted representation are wrapped and imported, and the import
   * is where an off-curve point dies.
   *
   * The three post-import assertions are the `WhisperSignatureVerifier.resolveKey`
   * discipline applied to a different algorithm: a key is re-checked for what
   * it actually IS rather than trusted to be what the header asked for. They
   * cannot fail while the header above is correct, and that is precisely why
   * they are here — they are what a future edit to that header runs into.
   */
  importPublicKey(canonicalPublicKey: string): KeyObject | null {
    const decoded = decodeCanonicalP256PublicKey(canonicalPublicKey);
    if (!decoded.ok) return null;
    // Defence in depth on the decoder's own guarantee. The SPKI header declares
    // a 66-byte BIT STRING, so a point of any other length would produce a
    // structurally invalid DER blob rather than a refusal we chose.
    if (decoded.point.bytes.byteLength !== P256_PUBLIC_KEY_BYTES) return null;

    const spki = Buffer.concat([P256_SPKI_HEADER, Buffer.from(decoded.point.bytes)]);

    let key: KeyObject;
    try {
      key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch {
      // THIS is where an off-curve point is refused (D24-05). OpenSSL raises
      // rather than returning, and a raised error is a refusal — never an
      // exception this module lets escape into a caller's control flow.
      return null;
    }

    if (key.type !== 'public') return null;
    if (key.asymmetricKeyType !== EC_KEY_TYPE) return null;
    if (key.asymmetricKeyDetails?.namedCurve !== P256_NAMED_CURVE) return null;
    return key;
  }

  /** True when the runtime provider accepts this key. The D24-05 gate, as a predicate. */
  isRuntimeValidPublicKey(canonicalPublicKey: string): boolean {
    return this.importPublicKey(canonicalPublicKey) !== null;
  }

  /**
   * True when `signature` is a valid P-256/SHA-256 signature by
   * `registeredPublicKey` over exactly `message`.
   *
   * THREE GATES RUN BEFORE ANY CRYPTO CALL, and their order is the contract's:
   *
   *  1. C15-01's profile binding. The server's resolved profile must be an
   *     approved one and the client's claim must EQUAL it. A client that names
   *     a different profile is refused rather than served, so no client can
   *     steer the verifier.
   *  2. `decodeCanonicalP256Signature`. Padding, non-canonical base64url, DER,
   *     wrong length, zero or out-of-range scalars and — critically — HIGH-S
   *     are all refused here. Node's `ieee-p1363` verifier would happily accept
   *     a high-S signature, so a malleable second encoding of a valid signature
   *     would verify if this gate were skipped or reordered after the call.
   *  3. The key import above, which is where an off-curve registry entry dies.
   *
   * Only then is `crypto.verify` reached, and any error it raises is a refusal.
   * The bytes handed to the verifier are the DECODER's, not the caller's
   * string re-decoded, so there is exactly one decode and no second chance for
   * a lenient one to disagree with it.
   */
  verifySignature(input: P256SignatureVerificationInput): boolean {
    const binding = bindClaimedSignatureProfile(input.claimedProfile, input.serverResolvedProfile);
    if (!binding.bound) return false;

    const decodedSignature = decodeCanonicalP256Signature(input.signature);
    if (!decodedSignature.ok) return false;

    const key = this.importPublicKey(input.registeredPublicKey);
    if (key === null) return false;

    try {
      return cryptoVerify(
        P256_DIGEST_ALGORITHM,
        Buffer.from(input.message, 'utf8'),
        { key, dsaEncoding: P256_SIGNATURE_ENCODING },
        Buffer.from(decodedSignature.scalars.bytes),
      );
    } catch {
      // A crypto-layer fault is not evidence of a valid signature.
      return false;
    }
  }
}
