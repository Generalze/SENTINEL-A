import { canonicalDeviceJson, deviceCanonicalDigest, deviceOfflineOperationFingerprint, DeviceOfflineOperationEnvelopeSchema } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { DEVICE_GATEWAY_OPERATION_ENVELOPE_DOMAIN } from './device-gateway.constants';
import { deviceGatewayEnvelopeDigest } from './device-gateway.envelope';

/**
 * WP-29A — THE ANDROID/SERVER INTEROP VECTORS, PINNED ON BOTH SIDES.
 *
 * A signature scheme spanning two implementations fails in exactly one way: the
 * two canonicalisers agree on every example anybody tried, and disagree on the
 * one nobody did. The failure then arrives as an invalid signature, which is
 * the least diagnosable refusal there is — it names the signature and says
 * nothing about the byte that differed.
 *
 * So the same three vectors are pinned twice, in two languages, by two
 * independent canonicalisers:
 *
 *   here                                        apps/field-mobile-android
 *   ----                                        -------------------------
 *   canonicalDeviceJson + SHA-256               CanonicalJson + SHA-256
 *   (packages/contracts)                        (OfflineEnvelopeTest)
 *
 * The constants below are BYTE-IDENTICAL to the ones in
 * `OfflineEnvelopeTest.kt`. If either side's ordering, number formatting or
 * field set drifts, one of the two suites goes red and names which. If only one
 * side pinned them, a drift would be invisible until a device in the field
 * produced a signature the server could not reconstruct.
 *
 * WHY THE NESTING MATTERS MOST. The gateway digest covers a submission whose
 * `semantic_payload` contains the WHOLE signed offline envelope and its
 * payload. That is the only place in this system where canonical ordering must
 * hold RECURSIVELY through two levels of nested object. A canonicaliser that
 * sorts the top level and preserves insertion order below would pass every
 * other test in this repository and fail only here.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT. It proves the SHAPE of the signed
 * bytes on both sides. It proves nothing about the signature itself, which is
 * made in StrongBox and can only be established on physical hardware —
 * `signature` below is a marker string, not a real P-256 signature.
 */

const OPERATION_ID = '11111111-1111-4111-8111-111111111111';
const MESSAGE_ID = '22222222-2222-4222-8222-222222222222';
const NONCE = 'nonce-0123456789abcdef';
const CREATED_AT = '2026-09-05T10:00:00Z';

/** SHA-256 over the canonical acknowledgement payload. */
const PAYLOAD_DIGEST = '032c6ac159c32198b4287477cae0eea2dbef37e41cf9ffec2b39c4a9a9ab5a5a';
/** The QUEUED STATEMENT's identity — what the envelope's own signature covers. */
const STATEMENT_FINGERPRINT = 'e240927cd731c8ded1c6315c333b288092f00cd751954c5babeb8badf360a027';
/** THIS REQUEST's identity — what the fresh WP-25 proof's `payload_digest` covers. */
const GATEWAY_DIGEST = 'a8c13f873fdb83b02e3f27c512bfa3b12d209adb1b9eebebdcef406daff7d855';
/** The exact canonical statement length, which the client's test signer encodes. */
const STATEMENT_LENGTH = 608;

const payload = { message_id: MESSAGE_ID };

const envelope = {
  schema_version: 1 as const,
  offline_operation_id: OPERATION_ID,
  organisation_id: 'org-1',
  site_id: 'site-1',
  actor_user_id: 'user-1',
  device_id: 'device-1',
  key_id: 'key-1',
  key_version: 3,
  operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' as const,
  device_sequence: 7,
  idempotency_key: OPERATION_ID,
  payload_digest: PAYLOAD_DIGEST,
  policy_lease_id: 'lease-1',
  nonce: NONCE,
  created_at: CREATED_AT,
  claimed_signature_profile: 'P256_ECDSA_SHA256' as const,
  signature: `signature-of-${STATEMENT_LENGTH}`,
};

describe('WP-29A Android interop vectors', () => {
  it('the payload digest is the one the client computes', () => {
    expect(deviceCanonicalDigest(payload)).toBe(PAYLOAD_DIGEST);
  });

  it('the queued statement fingerprint is the one the client signs', () => {
    // Built through the contract's own statement input, so the SERVER's
    // resolved profile goes into the signed bytes rather than the client's
    // claim — the C15-01 substitution, exercised on a real vector.
    const fingerprint = deviceOfflineOperationFingerprint({
      schema_version: envelope.schema_version,
      offline_operation_id: envelope.offline_operation_id,
      organisation_id: envelope.organisation_id,
      site_id: envelope.site_id,
      actor_user_id: envelope.actor_user_id,
      device_id: envelope.device_id,
      key_id: envelope.key_id,
      key_version: envelope.key_version,
      operation_kind: envelope.operation_kind,
      device_sequence: envelope.device_sequence,
      idempotency_key: envelope.idempotency_key,
      payload_digest: envelope.payload_digest,
      policy_lease_id: envelope.policy_lease_id,
      nonce: envelope.nonce,
      created_at: envelope.created_at,
      signature_profile: 'P256_ECDSA_SHA256',
    });
    expect(fingerprint).toBe(STATEMENT_FINGERPRINT);
  });

  it('the gateway envelope digest is the one the client puts in its fresh proof', () => {
    // THE RECURSIVE CASE. `semantic_payload` nests the whole signed envelope
    // and its payload, so this vector is what proves both canonicalisers sort
    // all the way down rather than only at the top.
    const digest = deviceGatewayEnvelopeDigest({
      schema_version: 1,
      operation_kind: 'OFFLINE_QUEUE_SUBMIT',
      organisation_id: 'org-1',
      site_id: 'site-1',
      actor_user_id: 'user-1',
      device_id: 'device-1',
      target_type: 'FIELD_OFFLINE_OPERATION',
      target_id: OPERATION_ID,
      semantic_payload: { envelope, payload },
    });
    expect(digest).toBe(GATEWAY_DIGEST);
  });

  it('the two digests are DIFFERENT, so one can never stand in for the other', () => {
    // Two signatures, two preimages. A client that put the statement
    // fingerprint into its proof — the mistake the client's first revision
    // made — must be refused rather than quietly accepted.
    expect(GATEWAY_DIGEST).not.toBe(STATEMENT_FINGERPRINT);
  });

  it('the pinned envelope is one the frozen contract actually accepts', () => {
    // Guards against a vector that both sides agree on and the contract would
    // reject anyway — a fixture proving only that two implementations share a
    // misunderstanding. C18-02 was exactly that failure, in the attestation
    // parser, where a synthetic fixture and the parser proved each other
    // correct against a shape Android never emits.
    //
    // The marker signature is not a real P-256 value, so the full schema (which
    // decodes the signature) cannot accept it. Every OTHER field is checked
    // against the frozen shape.
    const withoutSignature = DeviceOfflineOperationEnvelopeSchema.safeParse(envelope);
    expect(withoutSignature.success).toBe(false);
    const issues = withoutSignature.success ? [] : withoutSignature.error.issues.map((issue) => issue.path.join('.'));
    expect(issues).toEqual(['signature']);
  });

  it('the canonical statement is the exact length the client encodes', () => {
    // The client's test signer returns `signature-of-<length>`, so this number
    // is load-bearing for the gateway vector above: a canonicaliser that
    // emitted one byte more or fewer would change the signature string and
    // therefore the digest, and this names that cause directly.
    const statement = canonicalDeviceJson({
      domain: 'sentinel.device.offline-operation.v1',
      schema_version: envelope.schema_version,
      offline_operation_id: envelope.offline_operation_id,
      organisation_id: envelope.organisation_id,
      site_id: envelope.site_id,
      actor_user_id: envelope.actor_user_id,
      device_id: envelope.device_id,
      key_id: envelope.key_id,
      key_version: envelope.key_version,
      operation_kind: envelope.operation_kind,
      device_sequence: envelope.device_sequence,
      idempotency_key: envelope.idempotency_key,
      payload_digest: envelope.payload_digest,
      policy_lease_id: envelope.policy_lease_id,
      nonce: envelope.nonce,
      created_at: envelope.created_at,
      signature_profile: 'P256_ECDSA_SHA256',
    });
    expect(statement.length).toBe(STATEMENT_LENGTH);
  });

  it('the gateway domain separator is the one both sides name', () => {
    expect(DEVICE_GATEWAY_OPERATION_ENVELOPE_DOMAIN).toBe('sentinel.wp25.device-gateway.operation-envelope.v1');
  });
});
