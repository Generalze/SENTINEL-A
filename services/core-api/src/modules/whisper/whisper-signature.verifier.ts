import { Inject, Injectable } from '@nestjs/common';
import { verify as cryptoVerify, type KeyObject } from 'node:crypto';
import {
  canonicalWhisperSignedStatement,
  WHISPER_SIGNATURE_ALGORITHM,
  type AuthenticatedWhisperDeviceContext,
  type DeviceActionWhisperResult,
} from '@sentinel/contracts';
import { WHISPER_ED25519_KEY_TYPE, WHISPER_ED25519_SIGNATURE_BYTES } from './whisper.constants';
import { WHISPER_DEVICE_KEY_RESOLVER, type WhisperDeviceKeyResolver } from './whisper-key.resolver';

/**
 * B11-09: canonical unpadded base64url, decoded to an exact byte length.
 *
 * `Buffer.from(value, 'base64url')` is LENIENT — it silently skips characters
 * it does not recognise and tolerates truncated trailing groups — so calling
 * it is not a validation. Three gates run instead, and all of them run BEFORE
 * any crypto call:
 *
 *  1. the alphabet is checked against the raw string, so a padded, standard
 *     base64, whitespace-bearing or otherwise decorated encoding is refused
 *     rather than quietly cleaned up;
 *  2. the decoded length must be exactly the algorithm's signature size, so a
 *     truncated or padded signature never reaches the verifier; and
 *  3. the decoded bytes are RE-ENCODED and required to equal the input, which
 *     is what rules out non-canonical encodings — two different strings that
 *     decode to the same bytes (a trailing group whose unused bits are not
 *     zero, for instance). Malleable encodings matter here because the
 *     signature string is part of what a future cache, log or comparison might
 *     treat as an identity.
 *
 * Refusing malformed input before the crypto call also keeps a hostile client
 * from steering the verifier into library error paths at all.
 */
function decodeCanonicalBase64UrlSignature(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.byteLength !== WHISPER_ED25519_SIGNATURE_BYTES) return null;
  if (decoded.toString('base64url') !== value) return null;
  return decoded;
}

/**
 * B11-09/W21-06: verifies that a TRUSTED DEVICE produced this exact statement.
 *
 * The message is `canonicalWhisperSignedStatement(...)` and nothing else — a
 * domain-tagged canonical JSON object whose field names and escaping mean no
 * two distinct identities can share a preimage. What the statement covers, and
 * what it deliberately does not, is the contract's ruling, not this class's:
 * `confidence` is signed because it can flip a refusal into an acceptance,
 * while `device_trust`, `context` and `freshness_ms` are absent because none
 * of them is the device's to assert.
 *
 * TWO PROPERTIES THIS CLASS EXISTS TO GUARANTEE:
 *
 *  - THE KEY COMES ONLY FROM THE RESOLVER. Nothing in the submitted result is
 *    read as key material, and there is no parameter through which a caller
 *    could pass one. The key is selected by
 *    `context.verification_key_id` — a SERVER-ESTABLISHED value on the
 *    authenticated device context (W21-05) — inside the context's own
 *    organisation.
 *  - `signature_algorithm` SELECTS NOTHING. C11-04 pinned the field to a
 *    literal at the contract boundary precisely so a client-supplied algorithm
 *    name could never choose the verifier and downgrade the check to something
 *    forgeable. The equality assertion below is defence in depth on an
 *    already-pinned field; it is a REFUSAL, never a lookup. The algorithm is
 *    fixed by this module and re-confirmed against the resolved key's own
 *    type, so a registry entry of the wrong type is refused rather than
 *    verified with whatever scheme that type implies.
 */
@Injectable()
export class WhisperSignatureVerifier {
  constructor(@Inject(WHISPER_DEVICE_KEY_RESOLVER) private readonly keys: WhisperDeviceKeyResolver) {}

  /**
   * True only when the resolved registry key verifies the canonical signed
   * statement. EVERY other path returns false: an unregistered key, a key of
   * the wrong type, a private key where a public one was expected, a
   * malformed or non-canonical signature encoding, a wrong-length signature,
   * and any error the crypto layer raises.
   *
   * There is no error channel on purpose. A caller that could distinguish
   * "no key registered for this device" from "signature did not verify" would
   * have an oracle over the key registry, and the only safe action for either
   * is identical: refuse with SIGNATURE_INVALID and consume no replay
   * identity (B11-12).
   */
  async verify(context: AuthenticatedWhisperDeviceContext, result: DeviceActionWhisperResult): Promise<boolean> {
    if (result.signature_algorithm !== WHISPER_SIGNATURE_ALGORITHM) return false;

    const signature = decodeCanonicalBase64UrlSignature(result.signature);
    if (signature === null) return false;

    const key = await this.resolveKey(context);
    if (key === null) return false;

    const message = Buffer.from(canonicalWhisperSignedStatement(result), 'utf8');
    try {
      // Ed25519 takes no digest algorithm: the scheme fixes its own hashing,
      // so `null` here is the correct and only argument, not an omission.
      return cryptoVerify(null, message, key, signature);
    } catch {
      // A crypto-layer fault is not evidence of a valid signature. Anything
      // this throws — an unsupported key, an internal error — is a refusal.
      return false;
    }
  }

  /**
   * Resolves and then RE-CHECKS the registry key.
   *
   * A registry is data, and data drifts. Confirming the key is an Ed25519
   * PUBLIC key here means a registry entry that somehow holds a private key,
   * or a key of another type, is refused rather than handed to `verify` to be
   * interpreted under whatever scheme that type implies — which would be the
   * algorithm-selection hole C11-04 closed, re-opened from the other side.
   */
  private async resolveKey(context: AuthenticatedWhisperDeviceContext): Promise<KeyObject | null> {
    let key: KeyObject | null;
    try {
      key = await this.keys.resolveVerificationKey(context.organisationId, context.verificationKeyId);
    } catch {
      // A resolver that throws has not resolved a key. Fail closed rather than
      // let an unavailable registry become an unverified signature.
      return null;
    }
    if (key === null) return null;
    if (key.type !== 'public') return null;
    if (key.asymmetricKeyType !== WHISPER_ED25519_KEY_TYPE) return null;
    return key;
  }
}
