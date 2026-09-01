import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import {
  encodeCanonicalP256Signature,
  lowSCanonicaliseForSigning,
  P256_SCALAR_BYTES,
  type DeviceAttestationEvidence,
  type DeviceAttestationOutcome,
} from '@sentinel/contracts';
import type { DeviceAttestationEvaluationInput, DeviceAttestationEvaluator } from './attestation.evaluator';

/**
 * WP-24 Shield test support.
 *
 * It lives in `src` beside the module, following the
 * `patrol-sweep.scheduler.test-support.ts` precedent, so the unit specs, the
 * live acceptance suite and any future work package all build a device key the
 * same way. A key helper duplicated per spec is a key helper that drifts, and
 * a spec whose fixture drifts from the contract's canonical encoding stops
 * testing the thing it claims to.
 *
 * NOTHING HERE IS A PRODUCTION PATH. There is no device-side signer in
 * Sentinel and there will not be one: D23-03 has the device generate its own
 * keypair in hardware-backed storage and Sentinel receive only the public key.
 * These helpers exist to stand in for hardware that does not exist yet, which
 * is exactly why a passing enrollment test is not Proof C (D24-15).
 */

/** A P-256 keypair in the ONE canonical representation WP-23 accepts. */
export interface TestDeviceKeyPair {
  /** Canonical unpadded base64url of the uncompressed SEC1 point (C15-02). */
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

/**
 * The 26-byte DER SPKI prefix a P-256 public key is exported with.
 *
 * Node emits a 91-byte SPKI for P-256; the last 65 bytes are the uncompressed
 * point the contract defines as the wire form. Slicing rather than re-encoding
 * keeps this helper free of any ASN.1 of its own — the same argument
 * `p256-key.importer.ts` makes for its constant header, from the other
 * direction.
 */
const P256_SPKI_HEADER_BYTES = 26;

export function generateTestDeviceKeyPair(): TestDeviceKeyPair {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: Buffer.from(spki.subarray(P256_SPKI_HEADER_BYTES)).toString('base64url'),
    privateKey: pair.privateKey,
  };
}

/**
 * Signs a canonical statement the way a conforming device would.
 *
 * `lowSCanonicaliseForSigning` is the SIGNER-side helper the contract provides
 * and it is used here rather than on the verifier for the reason the contract
 * gives: a signer holds the key and is choosing which of two equivalent forms
 * to send, while a verifier doing the same thing would be accepting a value
 * the contract refuses. Node can emit a high-S signature, so without this the
 * fixture would intermittently produce a value `decodeCanonicalP256Signature`
 * rejects — and the test would look flaky rather than wrong.
 */
export function signCanonicalStatement(privateKey: KeyObject, message: string): string {
  const raw = cryptoSign('sha256', Buffer.from(message, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`);
  const s = BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`);
  return encodeCanonicalP256Signature(r, lowSCanonicaliseForSigning(s));
}

/**
 * A STRUCTURALLY PERFECT point that is not on the P-256 curve.
 *
 * This is the exact value D24-05 exists for. It passes every check
 * `device-signature.ts` performs — canonical unpadded base64url, 65 bytes,
 * `0x04` prefix, both coordinates inside the field prime, not (0, 0) — and it
 * satisfies no curve equation, so only the runtime import can refuse it.
 *
 * Built by flipping the low bit of Y on a genuine key. `p` ends in `...FFFF`,
 * so `y ^ 1` stays below the field prime, and exactly one of `y` and `y ^ 1`
 * can satisfy `y^2 = x^3 - 3x + b` for a given x — the curve's two valid
 * y-values for an x are `y` and `p - y`, which differ in far more than one bit.
 */
export function offCurveP256PublicKey(): string {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const point = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(P256_SPKI_HEADER_BYTES));
  const lastByteIndex = point.length - 1;
  point[lastByteIndex] = (point[lastByteIndex] as number) ^ 0x01;
  return point.toString('base64url');
}

/**
 * A settable stand-in for the D24-07 attestation seam.
 *
 * It exists so a spec can supply VERIFIED or NEGATIVE evidence and observe what
 * the REGISTRY concludes — never so a spec can reach into the trust rules
 * themselves, which stay in the frozen contracts where no test can touch them.
 * That is the whole reason the evaluator is an injected collaborator behind a
 * token (`WhisperDeviceKeyResolver`'s argument, applied to attestation).
 */
export class SettableDeviceAttestationEvaluator implements DeviceAttestationEvaluator {
  outcome: DeviceAttestationOutcome = 'UNAVAILABLE';
  reference: string | null = null;

  async evaluate(input: DeviceAttestationEvaluationInput): Promise<DeviceAttestationEvidence> {
    return { outcome: this.outcome, evaluated_at: input.now, attestation_reference: this.reference };
  }
}
