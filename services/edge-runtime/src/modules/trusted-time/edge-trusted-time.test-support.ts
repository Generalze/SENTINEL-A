import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import {
  P256_SCALAR_BYTES,
  canonicalEdgeTrustedTimeAnchorStatement,
  encodeCanonicalP256Signature,
  lowSCanonicaliseForSigning,
  type EdgeTrustedTimeAnchorStatement,
} from '@sentinel/contracts';

/**
 * WP-29B Edge trusted-time test support.
 *
 * It lives in `src` beside the module, following the
 * `shield.test-support.ts` / `patrol-sweep.scheduler.test-support.ts`
 * precedent, so every spec builds a signer the same way. A key helper
 * duplicated per spec is a key helper that drifts.
 *
 * NOTHING HERE IS A PRODUCTION PATH. Edge holds no anchor-signing key and must
 * never be able to: an Edge that could author its own anchor could choose what
 * time it believed it was, which is the exact attack the FW2-11 ruling closes.
 * These helpers stand in for CENTRAL, so that Edge's verifier can be exercised
 * without one. The presence of a signer in this file is why it is named
 * `.test-support.ts` — vitest does not collect it and `tsconfig.json` does not
 * exclude it, so a production import of it would be visible in a diff as an
 * import of a file with this header on it.
 */

const P256_SPKI_HEADER_BYTES = 26;

export interface TestAnchorSigner {
  /** Canonical unpadded base64url of the uncompressed SEC1 point. */
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

export function generateTestAnchorSigner(): TestAnchorSigner {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: Buffer.from(spki.subarray(P256_SPKI_HEADER_BYTES)).toString('base64url'),
    privateKey: pair.privateKey,
  };
}

/**
 * Signs a canonical statement the way central does.
 *
 * `lowSCanonicaliseForSigning` is the contract's SIGNER-side helper, used for
 * the reason the contract gives: Node can emit a high-S signature, which
 * `decodeCanonicalP256Signature` refuses — so without this the fixture would
 * intermittently produce a value the verifier rejects, and the test would look
 * flaky rather than wrong.
 */
export function signTestStatement(privateKey: KeyObject, message: string): string {
  const raw = cryptoSign('sha256', Buffer.from(message, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`);
  const s = BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`);
  return encodeCanonicalP256Signature(r, lowSCanonicaliseForSigning(s));
}

/** Signs an anchor statement over exactly the bytes the verifier will re-derive. */
export function signTestAnchor(privateKey: KeyObject, statement: EdgeTrustedTimeAnchorStatement): string {
  return signTestStatement(privateKey, canonicalEdgeTrustedTimeAnchorStatement(statement));
}
