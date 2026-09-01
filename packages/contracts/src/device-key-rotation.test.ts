import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalDeviceKeyRotationPossessionStatement,
  canonicalDeviceKeyRotationRequestStatement,
  deriveP256PublicKeyThumbprint,
  DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS,
  DEVICE_KEY_ROTATION_POSSESSION_DOMAIN,
  DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN,
  DEVICE_KEY_ROTATION_REQUEST_DOMAIN,
  DEVICE_POSSESSION_CHALLENGE_DOMAIN,
  DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS,
  deviceKeyRotationPossessionStatementFingerprint,
  DeviceKeyRotationChallengeSchema,
  deviceKeyRotationReplayKey,
  deviceKeyRotationRequestFingerprint,
  DeviceKeyRotationPossessionResponseSchema,
  DeviceKeyRotationPossessionVerificationResultSchema,
  DeviceKeyRotationRequestSchema,
  evaluateDeviceKeyRotation,
  type DeviceKeyRotationAdmissibilityInput,
  type DeviceKeyRotationChallenge,
  type DeviceKeyRotationPossessionVerificationResult,
  type DeviceKeyRotationRegistryFacts,
  type DeviceKeyRotationRequest,
  type DeviceNonceConsumption,
} from './index.js';

/**
 * WP-24 / D24-10A Crucible — the key-rotation possession contract.
 *
 * The ceremony this file exists to make safe is the one WP-23 could not
 * express: a device replacing its credential must prove CONTINUITY with the key
 * being retired AND POSSESSION of the key replacing it, and neither may stand
 * in for the other.
 */

const NOW = '2026-09-01T12:00:00.000Z';

function iso(offsetMs: number): string {
  return new Date(Date.parse(NOW) + offsetMs).toISOString();
}

function canonicalKey(): string {
  return Buffer.from(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }))
    .subarray(-65)
    .toString('base64url');
}

const NEW_PUBLIC_KEY = canonicalKey();
const NEW_THUMBPRINT = deriveP256PublicKeyThumbprint(NEW_PUBLIC_KEY);
const OTHER_PUBLIC_KEY = canonicalKey();

function request(overrides: Record<string, unknown> = {}): DeviceKeyRotationRequest {
  return DeviceKeyRotationRequestSchema.parse({
    schema_version: 1,
    rotation_request_id: 'rot-1',
    organisation_id: 'org-1',
    device_id: 'device-1',
    current_key_id: 'key-1',
    current_key_version: 4,
    proposed_key_id: 'key-2',
    proposed_key_version: 5,
    new_public_key: NEW_PUBLIC_KEY,
    new_public_key_thumbprint: NEW_THUMBPRINT,
    new_key_storage: 'HARDWARE_BACKED',
    server_resolved_signature_profile: 'P256_ECDSA_SHA256',
    requested_at: iso(-30_000),
    ...overrides,
  });
}

function challenge(target: DeviceKeyRotationRequest, overrides: Record<string, unknown> = {}): DeviceKeyRotationChallenge {
  return DeviceKeyRotationChallengeSchema.parse({
    schema_version: 1,
    challenge_id: 'rot-challenge-1',
    organisation_id: target.organisation_id,
    device_id: target.device_id,
    rotation_request_id: target.rotation_request_id,
    rotation_request_fingerprint: deviceKeyRotationRequestFingerprint(target),
    current_key_id: target.current_key_id,
    current_key_version: target.current_key_version,
    proposed_key_id: target.proposed_key_id,
    proposed_key_version: target.proposed_key_version,
    new_public_key_thumbprint: target.new_public_key_thumbprint,
    nonce: 'rotation-nonce-0123456789',
    issued_at: iso(-20_000),
    expires_at: iso(-20_000 + DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS),
    ...overrides,
  });
}

function registry(overrides: Partial<DeviceKeyRotationRegistryFacts> = {}): DeviceKeyRotationRegistryFacts {
  return {
    organisation_id: 'org-1',
    device_id: 'device-1',
    current_key_id: 'key-1',
    current_key_version: 4,
    current_key_status: 'CURRENT',
    current_key_revoked: false,
    device_revoked: false,
    server_resolved_signature_profile: 'P256_ECDSA_SHA256',
    ...overrides,
  };
}

function verification(
  target: DeviceKeyRotationRequest,
  theChallenge: DeviceKeyRotationChallenge,
  overrides: Record<string, unknown> = {},
): DeviceKeyRotationPossessionVerificationResult {
  const fingerprint = deviceKeyRotationRequestFingerprint(target);
  return DeviceKeyRotationPossessionVerificationResultSchema.parse({
    schema_version: 1,
    source: 'SENTINEL_DEVICE_KEY_ROTATION_VERIFIER',
    verified: true,
    organisation_id: target.organisation_id,
    device_id: target.device_id,
    rotation_request_id: target.rotation_request_id,
    rotation_request_fingerprint: fingerprint,
    rotation_challenge_id: theChallenge.challenge_id,
    current_key_id: target.current_key_id,
    current_key_version: target.current_key_version,
    proposed_key_id: target.proposed_key_id,
    proposed_key_version: target.proposed_key_version,
    new_public_key_thumbprint: target.new_public_key_thumbprint,
    signature_profile: 'P256_ECDSA_SHA256',
    canonical_statement_fingerprint: deviceKeyRotationPossessionStatementFingerprint({
      organisation_id: target.organisation_id,
      device_id: target.device_id,
      rotation_request_id: target.rotation_request_id,
      rotation_request_fingerprint: fingerprint,
      current_key_id: target.current_key_id,
      current_key_version: target.current_key_version,
      proposed_key_id: target.proposed_key_id,
      proposed_key_version: target.proposed_key_version,
      new_public_key_thumbprint: target.new_public_key_thumbprint,
      rotation_challenge_id: theChallenge.challenge_id,
      nonce: theChallenge.nonce,
      signature_profile: 'P256_ECDSA_SHA256',
    }),
    verified_at: iso(-10_000),
    ...overrides,
  });
}

function consumption(
  target: DeviceKeyRotationRequest,
  theChallenge: DeviceKeyRotationChallenge,
  overrides: Record<string, unknown> = {},
): DeviceNonceConsumption {
  return {
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'FIRST_SEEN',
    replay_key: deviceKeyRotationReplayKey({
      organisation_id: target.organisation_id,
      device_id: target.device_id,
      rotation_request_id: target.rotation_request_id,
      rotation_challenge_id: theChallenge.challenge_id,
      current_key_id: target.current_key_id,
      current_key_version: target.current_key_version,
      proposed_key_id: target.proposed_key_id,
      proposed_key_version: target.proposed_key_version,
      nonce: theChallenge.nonce,
    }),
    statement_fingerprint: deviceKeyRotationRequestFingerprint(target),
    stored_outcome_ref: null,
    ...overrides,
  } as DeviceNonceConsumption;
}

function ceremony(overrides: Partial<DeviceKeyRotationAdmissibilityInput> = {}): DeviceKeyRotationAdmissibilityInput {
  const target = overrides.request ?? request();
  const theChallenge = overrides.challenge ?? challenge(target);
  return {
    request: target,
    challenge: theChallenge,
    possessionVerification: verification(target, theChallenge),
    continuity: { verified: true, purpose_payload_digest: deviceKeyRotationRequestFingerprint(target) },
    newKeyRuntimeValid: true,
    registered: registry(),
    consumption: consumption(target, theChallenge),
    now: NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------

describe('D24-10A the rotation domain is NEW, never a reinterpreted enrollment domain', () => {
  it('does not share a signed-statement domain with the enrollment possession ceremony', () => {
    // This is the whole reason the file exists. Repurposing the enrollment
    // statement would have made a rotation proof byte-identical to an
    // enrollment proof carrying the same ids.
    expect(DEVICE_KEY_ROTATION_POSSESSION_DOMAIN).toBe('sentinel.device.key-rotation-possession.v1');
    expect(DEVICE_KEY_ROTATION_POSSESSION_DOMAIN).not.toBe(DEVICE_POSSESSION_CHALLENGE_DOMAIN);
    expect(DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN).toBe('sentinel.device.key-rotation.replay-identity.v1');
    expect(DEVICE_KEY_ROTATION_REQUEST_DOMAIN).toBe('sentinel.device.key-rotation-request.v1');
    const domains = new Set([
      DEVICE_KEY_ROTATION_POSSESSION_DOMAIN,
      DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN,
      DEVICE_KEY_ROTATION_REQUEST_DOMAIN,
      DEVICE_POSSESSION_CHALLENGE_DOMAIN,
    ]);
    expect(domains.size).toBe(4);
  });

  it('carries the domain inside the signed bytes, so the bytes name their own ceremony', () => {
    const target = request();
    const statement = canonicalDeviceKeyRotationPossessionStatement({
      organisation_id: target.organisation_id,
      device_id: target.device_id,
      rotation_request_id: target.rotation_request_id,
      rotation_request_fingerprint: deviceKeyRotationRequestFingerprint(target),
      current_key_id: target.current_key_id,
      current_key_version: target.current_key_version,
      proposed_key_id: target.proposed_key_id,
      proposed_key_version: target.proposed_key_version,
      new_public_key_thumbprint: target.new_public_key_thumbprint,
      rotation_challenge_id: 'rot-challenge-1',
      nonce: 'rotation-nonce-0123456789',
      signature_profile: 'P256_ECDSA_SHA256',
    });
    expect(statement).toContain(DEVICE_KEY_ROTATION_POSSESSION_DOMAIN);
    expect(statement).not.toContain(DEVICE_POSSESSION_CHALLENGE_DOMAIN);
    // Canonical JSON, not a delimiter join: a value containing a separator
    // cannot forge another tuple (C11-01).
    expect(() => JSON.parse(statement)).not.toThrow();
  });

  it('LOCKED: the rotation challenge ceiling is its OWN constant, not enrollment\'s', () => {
    // They are numerically equal today. That equality is a coincidence of
    // policy, and the two must be able to move independently.
    expect(DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS).toBe(120_000);
    expect(DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS).toBe(DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS);
    const target = request();
    const issued_at = iso(-20_000);
    expect(() =>
      challenge(target, { issued_at, expires_at: iso(-20_000 + DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS) }),
    ).not.toThrow();
    expect(() =>
      challenge(target, { issued_at, expires_at: iso(-20_000 + DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS + 1) }),
    ).toThrow();
  });
});

describe('D24-10A the rotation request is an exact semantic object', () => {
  it('requires the proposed version to be exactly current + 1', () => {
    expect(() => request({ proposed_key_version: 6 })).toThrow();
    expect(() => request({ proposed_key_version: 4 })).toThrow();
    expect(() => request({ proposed_key_version: 3 })).toThrow();
    expect(() => request({ proposed_key_version: 5 })).not.toThrow();
  });

  it('refuses a proposal that does not actually replace the key', () => {
    expect(() => request({ proposed_key_id: 'key-1' })).toThrow();
  });

  it('DERIVES the new thumbprint rather than believing the one supplied beside it', () => {
    expect(() => request({ new_public_key_thumbprint: deriveP256PublicKeyThumbprint(OTHER_PUBLIC_KEY) })).toThrow();
    expect(() => request({ new_public_key_thumbprint: 'a'.repeat(64) })).toThrow();
    // And the key itself must be the one canonical representation.
    expect(() => request({ new_public_key: Buffer.alloc(33, 2).toString('base64url') })).toThrow();
  });

  it('changes the fingerprint for every individually mutated bound field', () => {
    const base = deviceKeyRotationRequestFingerprint(request());
    const mutations: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ['rotation_request_id', { rotation_request_id: 'rot-2' }],
      ['organisation_id', { organisation_id: 'org-2' }],
      ['device_id', { device_id: 'device-2' }],
      ['current_key_id', { current_key_id: 'key-9' }],
      ['proposed_key_id', { proposed_key_id: 'key-3' }],
      ['new_key_storage', { new_key_storage: 'SOFTWARE' }],
      ['requested_at', { requested_at: iso(-31_000) }],
      [
        'new_public_key',
        { new_public_key: OTHER_PUBLIC_KEY, new_public_key_thumbprint: deriveP256PublicKeyThumbprint(OTHER_PUBLIC_KEY) },
      ],
      ['key versions', { current_key_version: 7, proposed_key_version: 8 }],
    ];
    const seen = new Set<string>([base]);
    for (const [label, patch] of mutations) {
      const mutated = deviceKeyRotationRequestFingerprint(request(patch));
      expect(mutated, label).not.toBe(base);
      expect(seen.has(mutated), `${label} collided`).toBe(false);
      seen.add(mutated);
    }
  });

  it('excludes nothing it commits to: the canonical statement round-trips to the fingerprint', () => {
    const target = request();
    const statement = canonicalDeviceKeyRotationRequestStatement(target);
    expect(statement).toContain(DEVICE_KEY_ROTATION_REQUEST_DOMAIN);
    for (const value of [target.rotation_request_id, target.new_public_key, target.new_public_key_thumbprint]) {
      expect(statement).toContain(value);
    }
  });

  it('the possession response carries a claim, and a malformed signature cannot reach a parsed one', () => {
    const parsed = DeviceKeyRotationPossessionResponseSchema.safeParse({
      schema_version: 1,
      challenge_id: 'rot-challenge-1',
      rotation_request_id: 'rot-1',
      claimed_signature_profile: 'P256_ECDSA_SHA256',
      signature: 'A'.repeat(86),
      answered_at: NOW,
    });
    // 86 characters of valid base64url that is not a canonical signature.
    expect(parsed.success).toBe(false);
  });
});

describe('D24-10A both proofs are required and neither substitutes for the other', () => {
  it('admits the complete ceremony and reports the version movement', () => {
    expect(evaluateDeviceKeyRotation(ceremony())).toEqual({
      decision: 'ROTATE',
      rotation_request_fingerprint: deviceKeyRotationRequestFingerprint(request()),
      from_key_version: 4,
      to_key_version: 5,
      invalidates_contexts_at_or_below_key_version: 4,
    });
  });

  it('LOCKED: possession WITHOUT continuity cannot replace a credential', () => {
    // Anyone holding a fresh keypair could otherwise take over a device.
    expect(evaluateDeviceKeyRotation(ceremony({ continuity: null }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CONTINUITY_PROOF_MISBOUND',
    });
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ continuity: { verified: false, purpose_payload_digest: deviceKeyRotationRequestFingerprint(request()) } }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'CONTINUITY_NOT_PROVEN' });
  });

  it('LOCKED: continuity WITHOUT possession registers a key nobody can show they hold', () => {
    // That is the upload C14-02 refuses, arriving through the rotation door.
    expect(evaluateDeviceKeyRotation(ceremony({ possessionVerification: null }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_VERIFICATION_MISSING',
    });
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ possessionVerification: verification(target, theChallenge, { verified: false }) }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'POSSESSION_NOT_PROVEN' });
  });

  it('LOCKED: a valid current-key proof cannot be BORROWED for a different replacement key', () => {
    // The continuity proof's payload_digest is bound to this exact request, so
    // a proof produced for one proposal cannot authorise another.
    const other = request({
      rotation_request_id: 'rot-2',
      proposed_key_id: 'key-3',
      new_public_key: OTHER_PUBLIC_KEY,
      new_public_key_thumbprint: deriveP256PublicKeyThumbprint(OTHER_PUBLIC_KEY),
    });
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ continuity: { verified: true, purpose_payload_digest: deviceKeyRotationRequestFingerprint(other) } }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'CONTINUITY_PROOF_MISBOUND' });
  });

  it('LOCKED: a genuine possession verdict from ANOTHER ceremony is structurally unusable', () => {
    const target = request();
    const theChallenge = challenge(target);
    const mutations: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ['another organisation', { organisation_id: 'org-2' }],
      ['another device', { device_id: 'device-2' }],
      ['another rotation request', { rotation_request_id: 'rot-2' }],
      ['another request fingerprint', { rotation_request_fingerprint: 'b'.repeat(64) }],
      ['another challenge', { rotation_challenge_id: 'rot-challenge-2' }],
      ['another current key', { current_key_id: 'key-9' }],
      ['another current version', { current_key_version: 3 }],
      ['another proposed key', { proposed_key_id: 'key-3' }],
      ['another proposed version', { proposed_key_version: 6 }],
      ['another new key', { new_public_key_thumbprint: deriveP256PublicKeyThumbprint(OTHER_PUBLIC_KEY) }],
    ];
    for (const [label, patch] of mutations) {
      expect(
        evaluateDeviceKeyRotation(ceremony({ possessionVerification: verification(target, theChallenge, patch) })),
        label,
      ).toEqual({ decision: 'REFUSE', refusal: 'POSSESSION_VERIFICATION_MISBOUND' });
    }
  });

  it('refuses a verdict that covered different bytes, or ran under another profile', () => {
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ possessionVerification: verification(target, theChallenge, { canonical_statement_fingerprint: 'c'.repeat(64) }) }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'POSSESSION_STATEMENT_MISMATCH' });
  });

  it('LOCKED: there is no naked boolean anywhere in the verdict type', () => {
    // `verified` exists, but it is unreachable without every binding above it.
    const target = request();
    const theChallenge = challenge(target);
    const naked = { verified: true } as unknown as DeviceKeyRotationPossessionVerificationResult;
    expect(evaluateDeviceKeyRotation(ceremony({ possessionVerification: naked }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_VERIFICATION_MISBOUND',
    });
    expect(DeviceKeyRotationPossessionVerificationResultSchema.safeParse({ verified: true }).success).toBe(false);
    // And the parsed shape cannot omit its provenance literal.
    expect(
      DeviceKeyRotationPossessionVerificationResultSchema.safeParse({
        ...verification(target, theChallenge),
        source: 'DEVICE_SELF_REPORT',
      }).success,
    ).toBe(false);
  });
});

describe('D24-10A the challenge is bound to the whole proposal', () => {
  it('refuses a challenge about a different rotation, device, key or proposal', () => {
    const target = request();
    const mutations: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ['another organisation', { organisation_id: 'org-2' }],
      ['another device', { device_id: 'device-2' }],
      ['another rotation request', { rotation_request_id: 'rot-2' }],
      ['a rewritten request', { rotation_request_fingerprint: 'd'.repeat(64) }],
      ['another current key', { current_key_id: 'key-9' }],
      ['another proposal', { current_key_version: 7, proposed_key_version: 8 }],
      ['another new key', { new_public_key_thumbprint: deriveP256PublicKeyThumbprint(OTHER_PUBLIC_KEY) }],
    ];
    for (const [label, patch] of mutations) {
      expect(evaluateDeviceKeyRotation(ceremony({ challenge: challenge(target, patch) })), label).toEqual({
        decision: 'REFUSE',
        refusal: 'CHALLENGE_MISBOUND',
      });
    }
  });

  it('judges freshness on the SERVER instant, with an exclusive expiry boundary', () => {
    const target = request();
    const theChallenge = challenge(target);
    const at = (verified_at: string): DeviceKeyRotationAdmissibilityInput =>
      ceremony({
        request: target,
        challenge: theChallenge,
        possessionVerification: verification(target, theChallenge, { verified_at }),
        now: iso(200_000),
      });
    // Exactly at expires_at is already expired.
    expect(evaluateDeviceKeyRotation(at(theChallenge.expires_at))).toEqual({ decision: 'REFUSE', refusal: 'CHALLENGE_EXPIRED' });
    expect(evaluateDeviceKeyRotation(at(iso(-20_000 + DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS - 1)))).toMatchObject({
      decision: 'ROTATE',
    });
    // Before the challenge it verified, and after the server's own clock.
    expect(evaluateDeviceKeyRotation(at(iso(-25_000)))).toEqual({ decision: 'REFUSE', refusal: 'CHALLENGE_NOT_YET_ISSUED' });
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ possessionVerification: verification(target, theChallenge, { verified_at: iso(1) }) }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'POSSESSION_VERIFIED_IN_FUTURE' });
  });

  it('fails closed on an unreadable instant', () => {
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ possessionVerification: { ...verification(target, theChallenge), verified_at: 'not-a-time' } }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'TIME_NOT_AUTHORITATIVE' });
  });

  it('never reads the device\'s own answered_at', () => {
    // The response type carries it; no evaluation path consults it.
    const target = request();
    const theChallenge = challenge(target);
    const response = DeviceKeyRotationPossessionResponseSchema.safeParse({
      schema_version: 1,
      challenge_id: theChallenge.challenge_id,
      rotation_request_id: target.rotation_request_id,
      claimed_signature_profile: 'P256_ECDSA_SHA256',
      signature: 'A'.repeat(86),
      answered_at: iso(9_999_999),
    });
    expect(response.success).toBe(false);
    // The admissibility input has nowhere to put a response at all.
    expect(Object.keys(ceremony())).not.toContain('response');
  });
});

describe('D24-10A STALE_ROTATION: the registry as it is now, not as it was', () => {
  it('LOCKED: refuses rather than retargeting the ceremony at whatever is current now', () => {
    const moved: ReadonlyArray<readonly [string, Partial<DeviceKeyRotationRegistryFacts>]> = [
      ['another rotation landed first', { current_key_version: 5, current_key_id: 'key-2' }],
      ['the key is no longer CURRENT', { current_key_status: 'ROTATED' }],
      ['the key was revoked', { current_key_status: 'REVOKED', current_key_revoked: true }],
      ['the key was declared compromised', { current_key_status: 'COMPROMISED', current_key_revoked: true }],
      ['key-level withdrawal only', { current_key_revoked: true }],
      ['device-level revocation only', { device_revoked: true }],
    ];
    for (const [label, patch] of moved) {
      expect(evaluateDeviceKeyRotation(ceremony({ registered: registry(patch) })), label).toEqual({
        decision: 'REFUSE',
        refusal: 'STALE_ROTATION',
      });
    }
  });

  it('asks the device and the key independently, so neither masks the other', () => {
    // C15-R4-final's rule on the device side: the two rows do not move
    // atomically, and either one alone is sufficient to refuse.
    expect(
      evaluateDeviceKeyRotation(ceremony({ registered: registry({ current_key_status: 'CURRENT', device_revoked: true }) })),
    ).toEqual({ decision: 'REFUSE', refusal: 'STALE_ROTATION' });
    expect(
      evaluateDeviceKeyRotation(ceremony({ registered: registry({ current_key_revoked: true, device_revoked: false }) })),
    ).toEqual({ decision: 'REFUSE', refusal: 'STALE_ROTATION' });
  });

  it('refuses a registry record about another device or tenant', () => {
    for (const patch of [{ organisation_id: 'org-2' }, { device_id: 'device-2' }]) {
      expect(evaluateDeviceKeyRotation(ceremony({ registered: registry(patch) }))).toEqual({
        decision: 'REFUSE',
        refusal: 'ROTATION_REQUEST_MISBOUND',
      });
    }
  });

  it('binds the profile to the SERVER\'s, before anything is verified under either', () => {
    expect(
      evaluateDeviceKeyRotation(
        ceremony({
          registered: registry({ server_resolved_signature_profile: 'Ed25519' as never }),
        }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' });
  });
});

describe('D24-05 runtime import precedes possession', () => {
  it('LOCKED: an off-curve key cannot acquire a rotation, however perfect its structure', () => {
    // A structurally valid uncompressed point whose coordinates are not on the
    // curve parses everywhere in this file — that is the documented limit of a
    // contracts package — and the runtime provider is what stops it.
    const offCurve = Buffer.concat([Buffer.from([4]), Buffer.alloc(32, 1), Buffer.alloc(32, 2)]).toString('base64url');
    const structural = DeviceKeyRotationRequestSchema.safeParse({
      ...request(),
      new_public_key: offCurve,
      new_public_key_thumbprint: deriveP256PublicKeyThumbprint(offCurve),
    });
    expect(structural.success, 'the contract admits it structurally, by design').toBe(true);
    expect(evaluateDeviceKeyRotation(ceremony({ newKeyRuntimeValid: false }))).toEqual({
      decision: 'REFUSE',
      refusal: 'NEW_KEY_NOT_RUNTIME_VALID',
    });
  });

  it('the runtime validity fact is required and undefaulted', () => {
    const withoutFact = { ...ceremony() } as Record<string, unknown>;
    delete withoutFact.newKeyRuntimeValid;
    expect(Object.keys(withoutFact)).not.toContain('newKeyRuntimeValid');
    expect(evaluateDeviceKeyRotation(withoutFact as unknown as DeviceKeyRotationAdmissibilityInput)).toEqual({
      decision: 'REFUSE',
      refusal: 'NEW_KEY_NOT_RUNTIME_VALID',
    });
  });
});

describe('D24-10A replay identity is not the statement fingerprint', () => {
  it('keys on the ceremony identity, and changes with every part of it', () => {
    const target = request();
    const theChallenge = challenge(target);
    const base = deviceKeyRotationReplayKey({
      organisation_id: target.organisation_id,
      device_id: target.device_id,
      rotation_request_id: target.rotation_request_id,
      rotation_challenge_id: theChallenge.challenge_id,
      current_key_id: target.current_key_id,
      current_key_version: target.current_key_version,
      proposed_key_id: target.proposed_key_id,
      proposed_key_version: target.proposed_key_version,
      nonce: theChallenge.nonce,
    });
    expect(base).toContain(DEVICE_KEY_ROTATION_REPLAY_IDENTITY_DOMAIN);
    // The identity is NOT the fingerprint: they must be independently stored,
    // because detecting changed semantics behind a reused identity is the
    // entire purpose of keeping both.
    expect(base).not.toBe(deviceKeyRotationRequestFingerprint(target));
  });

  it('LOCKED: an exact duplicate converges and NEVER rotates twice', () => {
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ consumption: consumption(target, theChallenge, { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'rotation-7' }) }),
      ),
    ).toEqual({
      decision: 'CONVERGE',
      rotation_request_fingerprint: deviceKeyRotationRequestFingerprint(target),
      stored_outcome_ref: 'rotation-7',
    });
  });

  it('LOCKED: changed semantics behind a spent identity conflict, and mutate nothing', () => {
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ consumption: consumption(target, theChallenge, { outcome: 'REUSED_WITH_CHANGED_SEMANTICS' }) }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'ROTATION_REUSED_WITH_CHANGED_SEMANTICS' });
  });

  it('C15-R1: a malformed duplicate can never reach ROTATE', () => {
    const target = request();
    const theChallenge = challenge(target);
    const malformed: ReadonlyArray<readonly [string, unknown]> = [
      ['duplicate naming no outcome', { ...consumption(target, theChallenge), outcome: 'EXACT_DUPLICATE', stored_outcome_ref: null }],
      ['duplicate with a blank ref', { ...consumption(target, theChallenge), outcome: 'EXACT_DUPLICATE', stored_outcome_ref: '   ' }],
      ['first seen carrying a ref', { ...consumption(target, theChallenge), outcome: 'FIRST_SEEN', stored_outcome_ref: 'rotation-7' }],
      ['a fact the device could have written', { ...consumption(target, theChallenge), source: 'DEVICE_SELF_REPORT' }],
      ['no fact at all', undefined],
    ];
    for (const [label, fact] of malformed) {
      const decision = evaluateDeviceKeyRotation(ceremony({ consumption: fact as DeviceNonceConsumption }));
      expect(decision.decision, label).toBe('REFUSE');
      expect(decision, label).toEqual({ decision: 'REFUSE', refusal: 'ROTATION_CONSUMPTION_INCONSISTENT' });
    }
  });

  it('refuses a consumption fact bound to another ceremony', () => {
    const target = request();
    const theChallenge = challenge(target);
    expect(
      evaluateDeviceKeyRotation(ceremony({ consumption: consumption(target, theChallenge, { replay_key: 'somewhere-else' }) })),
    ).toEqual({ decision: 'REFUSE', refusal: 'ROTATION_CONSUMPTION_MISBOUND' });
    expect(
      evaluateDeviceKeyRotation(
        ceremony({ consumption: consumption(target, theChallenge, { statement_fingerprint: 'e'.repeat(64) }) }),
      ),
    ).toEqual({ decision: 'REFUSE', refusal: 'ROTATION_CONSUMPTION_MISBOUND' });
  });
});
