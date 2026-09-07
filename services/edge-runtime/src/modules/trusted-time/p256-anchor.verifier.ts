import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { P256_PUBLIC_KEY_BYTES, decodeCanonicalP256PublicKey, decodeCanonicalP256Signature } from '@sentinel/contracts';

/**
 * WP-29B — EDGE'S RUNTIME CRYPTOGRAPHIC BOUNDARY, AND IT ADDS NOTHING NEW.
 *
 * This is `services/core-api/src/modules/shield/p256-key.importer.ts`, verify
 * half only, with the same constant header, the same three gates in the same
 * order, and the same no-error-channel discipline. Every line of the recipe is
 * Sentinel's existing one.
 *
 * WHY IT IS MIRRORED RATHER THAN IMPORTED
 * ---------------------------------------
 * Edge is a separate deployable that runs on a customer LAN with the WAN down.
 * Importing from `@sentinel/core-api` would make the Edge binary depend on the
 * whole central service — Prisma, NATS, Redis, S3, every controller — and would
 * couple two artifacts whose entire design point is that one keeps working when
 * it cannot reach the other. Moving the recipe into `@sentinel/contracts`
 * instead is the other obvious answer, and it is refused for a reason the
 * contracts package states about itself: `device-signature.ts` performs NO
 * curve arithmetic and `device-identity.ts` says "no cryptography here". Both
 * deliberately stop at the structural boundary and defer the curve check to
 * "the runtime verifier's job at the moment it imports the key". This is that
 * moment, on this side.
 *
 * So there are two copies of one recipe. That is a real cost, and it is the
 * smaller one: the alternative is either a cross-service dependency that breaks
 * the offline property or cryptography in a package that documents itself as
 * having none.
 *
 * WHAT IT VERIFIES, AND WHAT IT DELIBERATELY CANNOT DO
 * ---------------------------------------------------
 * There is no signing half here. Edge holds no private key for this domain and
 * has no way to author an anchor — it can only check one central produced. An
 * Edge that could sign its own anchor could choose what time it believed it
 * was, which is precisely the attack the FW2-11 ruling closes.
 */

/**
 * The fixed DER SubjectPublicKeyInfo prefix for an uncompressed P-256 point.
 *
 *   30 59                      SEQUENCE, 89 bytes
 *     30 13                    SEQUENCE, 19 bytes  (AlgorithmIdentifier)
 *       06 07 2A8648CE3D0201     OID 1.2.840.10045.2.1   id-ecPublicKey
 *       06 08 2A8648CE3D030107   OID 1.2.840.10045.3.1.7 prime256v1
 *     03 42 00                 BIT STRING, 66 bytes, 0 unused bits
 *                              ... followed by the 65 point bytes
 *
 * A CONSTANT rather than something assembled, because every byte is fixed by
 * the standard and assembling it would be a small ASN.1 encoder nobody asked
 * for. The named curve inside it is half the check: it is what makes an import
 * FAIL for a point from another curve rather than succeed as some other key.
 */
const P256_SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

const EC_KEY_TYPE = 'ec';
const P256_NAMED_CURVE = 'prime256v1';

/** Fixed by the `.v1` in the anchor domain separator. Never read from anything received. */
const P256_DIGEST_ALGORITHM = 'sha256';

/**
 * IEEE P1363 raw `r || s`. Not a preference — `decodeCanonicalP256Signature`
 * accepts exactly this form and refuses DER, so telling the verifier anything
 * else would mean verifying bytes the contract never validated.
 */
const P256_SIGNATURE_ENCODING = 'ieee-p1363';

@Injectable()
export class P256AnchorSignatureVerifier {
  /**
   * Imports a canonical P-256 public key, or returns `null`.
   *
   * The contract's structural decode runs FIRST, so a padded, non-canonical,
   * compressed, DER, wrong-length or out-of-field-range value never reaches the
   * platform decoder at all. Only bytes that are already the one accepted
   * representation are wrapped and imported, and THE IMPORT IS WHERE AN
   * OFF-CURVE POINT DIES — OpenSSL's own point decoder refuses it. No elliptic
   * curve arithmetic is implemented here or anywhere in the Edge runtime.
   *
   * The three post-import assertions are the `WhisperSignatureVerifier.resolveKey`
   * discipline: a key is re-checked for what it IS rather than trusted to be
   * what the header asked for. They cannot fail while the header above is
   * correct, which is exactly why they are here — they are what a future edit
   * to that header runs into.
   */
  importPublicKey(canonicalPublicKey: string): KeyObject | null {
    const decoded = decodeCanonicalP256PublicKey(canonicalPublicKey);
    if (!decoded.ok) return null;
    if (decoded.point.bytes.byteLength !== P256_PUBLIC_KEY_BYTES) return null;

    const spki = Buffer.concat([P256_SPKI_HEADER, Buffer.from(decoded.point.bytes)]);

    let key: KeyObject;
    try {
      key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch {
      // An off-curve point. A raised error is a refusal, never an exception
      // this module lets escape into a caller's control flow.
      return null;
    }

    if (key.type !== 'public') return null;
    if (key.asymmetricKeyType !== EC_KEY_TYPE) return null;
    if (key.asymmetricKeyDetails?.namedCurve !== P256_NAMED_CURVE) return null;
    return key;
  }

  /** True when the runtime provider accepts this key. Used when the keyring is loaded. */
  isRuntimeValidPublicKey(canonicalPublicKey: string): boolean {
    return this.importPublicKey(canonicalPublicKey) !== null;
  }

  /**
   * True when `signature` is a valid P-256/SHA-256 signature by `publicKey`
   * over exactly `message`.
   *
   * TWO GATES RUN BEFORE ANY CRYPTO CALL, in the contract's order:
   *
   *  1. `decodeCanonicalP256Signature`. Padding, non-canonical base64url, DER,
   *     wrong length, zero or out-of-range scalars and — critically — HIGH-S
   *     are refused here. Node's `ieee-p1363` verifier would happily accept a
   *     high-S signature, so a malleable second encoding of a valid anchor
   *     signature would verify if this gate were skipped or reordered after the
   *     call. It matters more for an anchor than for most statements, because a
   *     persisted anchor is a file an attacker can rewrite: two distinct byte
   *     sequences that both verify would be two anchors that both look genuine.
   *  2. The key import above, where an off-curve keyring entry dies.
   *
   * There is deliberately no signature-profile binding gate here, unlike
   * `P256KeyImporter.verifySignature`. The anchor statement carries no claimed
   * profile to bind: the domain separator's version fixes the algorithm, so
   * there is nothing for a caller to claim and nothing to be steered by.
   *
   * The bytes handed to the verifier are the DECODER'S, not the caller's string
   * re-decoded, so there is exactly one decode and no second chance for a
   * lenient one to disagree with it. Any error the crypto layer raises is a
   * refusal.
   */
  verifyAnchorSignature(input: { readonly publicKey: string; readonly message: string; readonly signature: string }): boolean {
    const decodedSignature = decodeCanonicalP256Signature(input.signature);
    if (!decodedSignature.ok) return false;

    const key = this.importPublicKey(input.publicKey);
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
