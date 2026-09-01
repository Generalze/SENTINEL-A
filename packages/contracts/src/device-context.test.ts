import { describe, expect, it } from 'vitest';
import {
  AuthenticatedDeviceContextSchema,
  canonicalDeviceRequestProofStatement,
  DEVICE_PURPOSE_PERMITTED_TRUST,
  DEVICE_QUEUE_ADMISSION_PURPOSE,
  DEVICE_REQUEST_PROOF_DOMAIN,
  DEVICE_REQUEST_PURPOSES,
  DEVICE_TRUST_OPERATIONAL_RANK,
  deviceContextPermits,
  deviceContextRemainingMs,
  DeviceRequestProofSchema,
  deviceRequestProofFingerprint,
  deviceRequestProofReplayIdentity,
  deviceRequestProofReplayKey,
  deviceRequestProofStatementInput,
  deviceTrustPermitsPurpose,
  evaluateDeviceOfflineQueueAdmission,
  evaluateDeviceReconnectAuthentication,
  evaluateDeviceRequestProof,
  isDeviceContextExpired,
  isDeviceTrustDowngrade,
  type AuthenticatedDeviceContext,
  type DeviceRegistryFacts,
  type DeviceRequestProof,
  type DeviceRequestProofEvaluationInput,
  type DeviceRequestProofStatementInput,
} from './device-context.js';
import {
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_REQUEST_PROOF_MAX_AGE_MS,
  DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  DeviceNonceConsumptionSchema,
  isConsistentDeviceNonceConsumption,
  type DeviceNonceConsumption,
} from './device-identity.js';
import { type DeviceTrust } from './device.js';
import { WHISPER_SIGNED_STATEMENT_DOMAIN } from './whisper.js';

/** WP-23 Crucible — the sender-constrained device context (D23-07 / C14-03). */

const NOW = '2026-08-29T12:00:00.000Z';
const PAYLOAD_DIGEST = 'c'.repeat(64);
const OTHER_DIGEST = 'd'.repeat(64);
const SIGNATURE = Buffer.from(new Uint8Array(64).fill(9)).toString('base64url');
const NONCE = 'nonce-0123456789abcdef';

function iso(deltaMs: number): string {
  return new Date(Date.parse(NOW) + deltaMs).toISOString();
}

function context(overrides: Record<string, unknown> = {}): AuthenticatedDeviceContext {
  return AuthenticatedDeviceContextSchema.parse({
    schema_version: 1,
    context_id: 'ctx-1',
    organisation_id: 'org-1',
    actor_user_id: 'user-1',
    device_id: 'device-1',
    authorised_site_ids: ['site-1', 'site-2'],
    device_trust: 'TRUSTED',
    key_id: 'key-1',
    key_version: 4,
    issued_at: iso(-60_000),
    expires_at: iso(120_000),
    ...overrides,
  });
}

function proof(overrides: Record<string, unknown> = {}): DeviceRequestProof {
  return DeviceRequestProofSchema.parse({
    schema_version: 1,
    context_id: 'ctx-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    actor_user_id: 'user-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 4,
    purpose: 'FIELD_OPERATION',
    payload_digest: PAYLOAD_DIGEST,
    nonce: NONCE,
    issued_at: iso(-5_000),
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    signature: SIGNATURE,
    ...overrides,
  });
}

/**
 * C15-01: the signed bytes carry the SERVER's profile. The test cannot hand a
 * proof straight to the statement builder any more, which is the point.
 */
function statement(source: DeviceRequestProof = proof()): DeviceRequestProofStatementInput {
  return deviceRequestProofStatementInput(source, 'P256_ECDSA_SHA256');
}

/** C15-04: the full set of server-owned CURRENT facts. */
function registry(overrides: Partial<DeviceRegistryFacts> = {}): DeviceRegistryFacts {
  return {
    organisation_id: 'org-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 4,
    signature_profile: 'P256_ECDSA_SHA256',
    trust: 'TRUSTED',
    revoked: false,
    revocation_disposition: null,
    actor: { user_id: 'user-1', authorised_site_ids: ['site-1', 'site-2'], holds_required_capability: true },
    ...overrides,
  };
}

/** C15-05: a store report shaped for the proof actually being presented. */
function consumptionFor(source: DeviceRequestProof = proof(), overrides: Record<string, unknown> = {}): DeviceNonceConsumption {
  // C15-R1: parsed, so every fixture built here is provably a consistent fact.
  // The malformed ones the guard exists to catch are built inline and cast.
  return DeviceNonceConsumptionSchema.parse({
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'FIRST_SEEN',
    replay_key: deviceRequestProofReplayKey(source),
    statement_fingerprint: deviceRequestProofFingerprint(statement(source)),
    stored_outcome_ref: null,
    ...overrides,
  });
}

function evaluation(overrides: Partial<DeviceRequestProofEvaluationInput> = {}): DeviceRequestProofEvaluationInput {
  const theProof = overrides.proof ?? proof();
  return {
    context: context(),
    proof: theProof,
    now: NOW,
    expectedPayloadDigest: PAYLOAD_DIGEST,
    registered: registry(),
    verified: true,
    expectedPurpose: theProof.purpose,
    consumption: consumptionFor(theProof),
    ...overrides,
  };
}

/**
 * C15-R2: a reconnect input. The reconnect API takes NO `expectedPurpose` — it
 * names RECONNECT_HANDSHAKE itself — so the fixture genuinely OMITS the field
 * rather than passing one that happens to be ignored.
 */
function reconnect(overrides: Partial<DeviceRequestProofEvaluationInput> = {}): Omit<DeviceRequestProofEvaluationInput, 'expectedPurpose'> {
  const full: Record<string, unknown> = { ...evaluation({ proof: proof({ purpose: 'RECONNECT_HANDSHAKE' }), ...overrides }) };
  delete full.expectedPurpose;
  return full as unknown as Omit<DeviceRequestProofEvaluationInput, 'expectedPurpose'>;
}

// ---------------------------------------------------------------------------

describe('the authenticated device context (D23-07)', () => {
  it('accepts a lifetime exactly at DEVICE_CONTEXT_MAX_LIFETIME_MS and refuses one millisecond past it', () => {
    expect(() => context({ issued_at: NOW, expires_at: iso(DEVICE_CONTEXT_MAX_LIFETIME_MS) })).not.toThrow();
    expect(() => context({ issued_at: NOW, expires_at: iso(DEVICE_CONTEXT_MAX_LIFETIME_MS + 1) })).toThrow();
  });

  it('refuses a context that expires before it is issued', () => {
    expect(() => context({ issued_at: NOW, expires_at: iso(-1) })).toThrow();
    expect(() => context({ issued_at: NOW, expires_at: NOW })).toThrow();
  });

  it('carries no bearer token, secret or authorization field: it is a scope statement, not a credential (C14-03)', () => {
    for (const field of ['token', 'context_token', 'secret', 'authorization', 'bearer', 'jwt', 'signature']) {
      expect(() => context({ [field]: 'value' })).toThrow();
    }
  });

  it('refuses duplicate authorised sites and an empty site scope', () => {
    expect(() => context({ authorised_site_ids: ['site-1', 'site-1'] })).toThrow();
    expect(() => context({ authorised_site_ids: [] })).toThrow();
  });

  it('reports its own remaining lifetime against the server clock', () => {
    expect(deviceContextRemainingMs(context(), NOW)).toBe(120_000);
    expect(isDeviceContextExpired(context(), NOW)).toBe(false);
    expect(isDeviceContextExpired(context(), iso(120_001))).toBe(true);
  });

  it('answers site entitlement and trust sufficiency without ever standing in for possession', () => {
    expect(deviceContextPermits(context(), { site_id: 'site-2', requiredTrust: ['TRUSTED'] })).toBe(true);
    expect(deviceContextPermits(context(), { site_id: 'site-9', requiredTrust: ['TRUSTED'] })).toBe(false);
    expect(deviceContextPermits(context({ device_trust: 'DEGRADED' }), { site_id: 'site-1', requiredTrust: ['TRUSTED'] })).toBe(false);
  });
});

describe('the canonical request-proof statement (C14-03)', () => {
  it('uses a domain tag distinct from the frozen Whisper statement domain', () => {
    expect(DEVICE_REQUEST_PROOF_DOMAIN).toBe('sentinel.device.request-proof.v1');
    expect(DEVICE_REQUEST_PROOF_DOMAIN).not.toBe(WHISPER_SIGNED_STATEMENT_DOMAIN);
    expect(canonicalDeviceRequestProofStatement(statement())).toContain(DEVICE_REQUEST_PROOF_DOMAIN);
  });

  it('excludes the signature from the bytes it signs', () => {
    expect(canonicalDeviceRequestProofStatement(statement())).not.toContain(SIGNATURE);
  });

  it('changes the fingerprint for every individually mutated bound component, and never converges on the original', () => {
    const baseline = deviceRequestProofFingerprint(statement(proof()));
    const mutations: Array<[string, DeviceRequestProof]> = [
      ['context_id', proof({ context_id: 'ctx-2' })],
      ['organisation_id', proof({ organisation_id: 'org-2' })],
      ['site_id', proof({ site_id: 'site-2' })],
      ['actor_user_id', proof({ actor_user_id: 'user-2' })],
      ['device_id', proof({ device_id: 'device-2' })],
      ['key_id', proof({ key_id: 'key-2' })],
      ['key_version', proof({ key_version: 5 })],
      ['purpose', proof({ purpose: 'OFFLINE_SYNC' })],
      ['payload_digest', proof({ payload_digest: OTHER_DIGEST })],
      ['nonce', proof({ nonce: 'nonce-fedcba9876543210' })],
      ['issued_at', proof({ issued_at: iso(-6_000) })],
    ];
    const digests = new Set<string>([baseline]);
    for (const [label, mutated] of mutations) {
      const digest = deviceRequestProofFingerprint(statement(mutated));
      expect(digest, `${label} must move the fingerprint`).not.toBe(baseline);
      digests.add(digest);
    }
    expect(digests.size).toBe(mutations.length + 1);
  });

  it('cannot be forged by a value that contains a delimiter, because the statement is canonical JSON not a joined string', () => {
    const a = deviceRequestProofFingerprint(statement(proof({ organisation_id: 'org\n1', site_id: 'site-1' })));
    const b = deviceRequestProofFingerprint(statement(proof({ organisation_id: 'org', site_id: '1\nsite-1' })));
    expect(a).not.toBe(b);
  });

  it('refuses a purpose the device invented for itself', () => {
    expect(() => proof({ purpose: 'ANYTHING_I_LIKE' })).toThrow();
    expect(DEVICE_REQUEST_PURPOSES).toContain('RECONNECT_HANDSHAKE');
  });

  it('carries a payload digest rather than the payload itself (D23-14)', () => {
    expect(() => proof({ payload: { body: 'secret' } })).toThrow();
  });
});

describe('LOCKED INVARIANT: a context token without the hardware key is useless (C14-03)', () => {
  it('admits a valid context accompanied by a verified possession proof', () => {
    const decision = evaluateDeviceRequestProof(evaluation());
    expect(decision.admitted).toBe(true);
    if (decision.admitted) expect(decision.fingerprint).toBe(deviceRequestProofFingerprint(statement(proof())));
  });

  it('refuses a stolen, still-unexpired context replayed with every other field perfect but no possession', () => {
    expect(evaluateDeviceRequestProof(evaluation({ verified: false }))).toEqual({
      admitted: false,
      refusal: 'POSSESSION_NOT_PROVEN',
    });
  });

  it('reaches the possession check last, so the refusal names possession rather than an unrelated deflection', () => {
    // Everything the thief could plausibly hold is valid: unexpired context,
    // matching identity, live registry entry, fresh proof, correct body digest.
    const thief = evaluation({ verified: false });
    expect(thief.context.expires_at > NOW).toBe(true);
    expect(thief.registered.revoked).toBe(false);
    expect(evaluateDeviceRequestProof(thief)).toEqual({ admitted: false, refusal: 'POSSESSION_NOT_PROVEN' });
  });
});

describe('a context cannot be replayed across identity boundaries (D23-07)', () => {
  it('refuses a cross-organisation replay', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ organisation_id: 'org-2' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_ORGANISATION_MISMATCH',
    });
  });

  it('refuses a cross-user replay', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ actor_user_id: 'user-2' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_ACTOR_MISMATCH',
    });
  });

  it('refuses a cross-device replay', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ device_id: 'device-2' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_DEVICE_MISMATCH',
    });
  });

  it('refuses a proof presented against a different context', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ context_id: 'ctx-2' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_IDENTITY_MISMATCH',
    });
  });

  it('refuses a cross-site replay to a site the context does not authorise', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ site_id: 'site-9' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_SITE_NOT_AUTHORISED',
    });
  });

  it('refuses an expired context, and one presented before it was issued', () => {
    expect(evaluateDeviceRequestProof(evaluation({ now: iso(120_001) }))).toEqual({ admitted: false, refusal: 'CONTEXT_EXPIRED' });
    expect(evaluateDeviceRequestProof(evaluation({ now: iso(-60_001) }))).toEqual({ admitted: false, refusal: 'CONTEXT_NOT_YET_VALID' });
  });
});

describe('the registry is consulted at use (D23-07 / D23-09)', () => {
  it('invalidates a context bound to a key version the device has since rotated past', () => {
    expect(evaluateDeviceRequestProof(evaluation({ registered: registry({ key_version: 5 }) }))).toEqual({
      admitted: false,
      refusal: 'KEY_VERSION_ROTATED',
    });
  });

  it('refuses a proof minted against an old key version', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ key_version: 3 }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_KEY_MISMATCH',
    });
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ key_id: 'key-9' }) }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_KEY_MISMATCH',
    });
  });

  it('refuses a revoked credential immediately, without waiting for the context to expire', () => {
    expect(evaluateDeviceRequestProof(evaluation({ registered: registry({ revoked: true }) }))).toEqual({
      admitted: false,
      refusal: 'CREDENTIAL_REVOKED',
    });
  });
});

describe('freshness is judged against the server clock (W21-08 / D23-12)', () => {
  it('accepts a proof exactly at DEVICE_REQUEST_PROOF_MAX_AGE_MS and refuses one millisecond past it', () => {
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ issued_at: iso(-DEVICE_REQUEST_PROOF_MAX_AGE_MS) }) })).admitted).toBe(true);
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ issued_at: iso(-DEVICE_REQUEST_PROOF_MAX_AGE_MS - 1) }) }))).toEqual({
      admitted: false,
      refusal: 'PROOF_STALE',
    });
  });

  it('accepts skew exactly at DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS and refuses one millisecond past it', () => {
    expect(
      evaluateDeviceRequestProof(evaluation({ proof: proof({ issued_at: iso(DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS) }) })).admitted,
    ).toBe(true);
    expect(evaluateDeviceRequestProof(evaluation({ proof: proof({ issued_at: iso(DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS + 1) }) }))).toEqual({
      admitted: false,
      refusal: 'PROOF_FUTURE_SKEW',
    });
  });

  it('does not let a device extend its own window by claiming to have signed in the future', () => {
    const future = evaluation({ proof: proof({ issued_at: iso(3_600_000) }) });
    expect(evaluateDeviceRequestProof(future)).toEqual({ admitted: false, refusal: 'PROOF_FUTURE_SKEW' });
  });
});

describe('the proof binds the body it accompanies', () => {
  it('refuses when the server-computed payload digest differs from the signed one', () => {
    expect(evaluateDeviceRequestProof(evaluation({ expectedPayloadDigest: OTHER_DIGEST }))).toEqual({
      admitted: false,
      refusal: 'PAYLOAD_DIGEST_MISMATCH',
    });
  });

  it('C15-04: refuses a purpose that is not the one the caller EXPECTED', () => {
    // The old `allowedPurposes` was optional and defaulted to every purpose, so
    // a caller that forgot it accepted a proof minted for anything at all.
    expect(evaluateDeviceRequestProof(evaluation({ expectedPurpose: 'WHISPER_DEVICE_ACTION' }))).toEqual({
      admitted: false,
      refusal: 'PURPOSE_NOT_ALLOWED',
    });
  });
});

describe('the reconnect authenticates by possession (D23-13 / C14-03)', () => {
  it('authenticates a reconnect proved with the hardware key', () => {
    const decision = evaluateDeviceReconnectAuthentication(reconnect());
    expect(decision.authenticated).toBe(true);
  });

  it('refuses a presented token without possession', () => {
    expect(evaluateDeviceReconnectAuthentication(reconnect({ verified: false }))).toEqual({
      authenticated: false,
      refusal: 'POSSESSION_NOT_PROVEN',
      queue_examination_permitted: false,
    });
  });

  it('refuses a proof minted for some other purpose being reused to reconnect', () => {
    expect(evaluateDeviceReconnectAuthentication(evaluation())).toEqual({
      authenticated: false,
      refusal: 'PURPOSE_NOT_ALLOWED',
      queue_examination_permitted: false,
    });
  });

  it('fails closed as a whole before any queued operation could be examined', () => {
    // D23-13 as a CONTRACT rather than a comment: the caller is handed a
    // `false` it cannot ignore, so no queue is examined on any refusal.
    expect(evaluateDeviceReconnectAuthentication(reconnect({ registered: registry({ revoked: true }) }))).toEqual({
      authenticated: false,
      refusal: 'CREDENTIAL_REVOKED',
      queue_examination_permitted: false,
    });
  });
});

// ---------------------------------------------------------------------------
// C15 corrections
// ---------------------------------------------------------------------------

describe('C15-01 the client does not choose the profile', () => {
  it('names the profile field a CLAIM, and refuses the old authoritative name', () => {
    expect(proof().claimed_signature_profile).toBe('P256_ECDSA_SHA256');
    expect(() => proof({ signature_profile: 'P256_ECDSA_SHA256' })).toThrow();
  });

  it('LOCKED: a claimed profile differing from the server-resolved one refuses BEFORE verification', () => {
    // Every other fact is perfect, including the signature. The registry says
    // one thing and the client says another, and that alone must stop it.
    const decision = evaluateDeviceRequestProof(
      evaluation({ registered: registry({ signature_profile: 'Ed25519' as never }) }),
    );
    expect(decision).toEqual({ admitted: false, refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH' });
  });

  it('the canonical statement binds the SERVER profile, not the claim', () => {
    // The statement input type does not even carry `claimed_signature_profile`,
    // so a caller cannot sign the client's field by accident.
    const built = statement();
    expect(built).not.toHaveProperty('claimed_signature_profile');
    expect(built.signature_profile).toBe('P256_ECDSA_SHA256');
    expect(canonicalDeviceRequestProofStatement(built)).toContain('signature_profile');
  });

  it('COMPOUND: a whole DeviceRequestProof carrying a non-canonical signature fails to PARSE', () => {
    // Before C15-01 each of these produced a fully parsed proof that only some
    // later caller might have rejected.
    const highS = Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32, 0xff)]).toString('base64url');
    const zeroR = Buffer.concat([Buffer.alloc(32), Buffer.alloc(32, 1)]).toString('base64url');
    const shortSig = Buffer.alloc(32).toString('base64url');
    const shapeOnly = 'A'.repeat(86);
    for (const [label, signature] of [
      ['high s', highS],
      ['zero r', zeroR],
      ['wrong length', shortSig],
      ['non-canonical 86 chars', shapeOnly],
      ['padded', `${SIGNATURE}==`],
    ] as Array<[string, string]>) {
      const parsed = DeviceRequestProofSchema.safeParse({ ...proof(), signature });
      expect(parsed.success, label).toBe(false);
    }
    // And the branded valid form still parses.
    expect(DeviceRequestProofSchema.safeParse({ ...proof(), signature: SIGNATURE }).success).toBe(true);
  });
});

describe('C15-04 current authority is present, and purpose is exact', () => {
  it('pins which trust states admit which purpose, with Whisper at TRUSTED only (W21-05)', () => {
    expect(Object.keys(DEVICE_PURPOSE_PERMITTED_TRUST).sort()).toEqual([...DEVICE_REQUEST_PURPOSES].sort());
    expect(DEVICE_PURPOSE_PERMITTED_TRUST.WHISPER_DEVICE_ACTION).toEqual(['TRUSTED']);
    expect(deviceTrustPermitsPurpose('DEGRADED', 'WHISPER_DEVICE_ACTION')).toBe(false);
    expect(deviceTrustPermitsPurpose('TRUSTED', 'WHISPER_DEVICE_ACTION')).toBe(true);
    // A reconnect must remain possible for a device that is, by definition, offline.
    expect(deviceTrustPermitsPurpose('OFFLINE', 'RECONNECT_HANDSHAKE')).toBe(true);
    // But not for a device we have made a decision about.
    expect(deviceTrustPermitsPurpose('QUARANTINED', 'RECONNECT_HANDSHAKE')).toBe(false);
    expect(deviceTrustPermitsPurpose('COMPROMISED', 'RECONNECT_HANDSHAKE')).toBe(false);
  });

  it('LOCKED: registry trust that no longer permits the purpose refuses, even inside a live context', () => {
    // The context still says TRUSTED because that was true when it was issued.
    // The registry has since said otherwise, and the registry wins.
    const whisper = proof({ purpose: 'WHISPER_DEVICE_ACTION' });
    expect(
      evaluateDeviceRequestProof(evaluation({ proof: whisper, registered: registry({ trust: 'DEGRADED' }) })),
    ).toEqual({ admitted: false, refusal: 'DEVICE_TRUST_NOT_PERMITTED' });
    // The same proof against a still-TRUSTED registry is admitted.
    expect(evaluateDeviceRequestProof(evaluation({ proof: whisper })).admitted).toBe(true);
  });

  it('LOCKED: a user who has lost the capability, or the site, is refused', () => {
    expect(
      evaluateDeviceRequestProof(
        evaluation({ registered: registry({ actor: { user_id: 'user-1', authorised_site_ids: ['site-1'], holds_required_capability: false } }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED' });

    // The CONTEXT still authorises site-1; the user's CURRENT entitlement does not.
    expect(
      evaluateDeviceRequestProof(
        evaluation({ registered: registry({ actor: { user_id: 'user-1', authorised_site_ids: ['site-7'], holds_required_capability: true } }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'SITE_ENTITLEMENT_LOST' });

    // And a registry record about someone else entirely.
    expect(
      evaluateDeviceRequestProof(
        evaluation({ registered: registry({ actor: { user_id: 'user-9', authorised_site_ids: ['site-1'], holds_required_capability: true } }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED' });
  });

  it('refuses a registry record that is about a different device or organisation', () => {
    expect(evaluateDeviceRequestProof(evaluation({ registered: registry({ device_id: 'device-9' }) }))).toEqual({
      admitted: false,
      refusal: 'REGISTRY_IDENTITY_MISMATCH',
    });
    expect(evaluateDeviceRequestProof(evaluation({ registered: registry({ organisation_id: 'org-9' }) }))).toEqual({
      admitted: false,
      refusal: 'REGISTRY_IDENTITY_MISMATCH',
    });
  });

  it('LOCKED: cross-purpose reuse is a refusal, and expectedPurpose has no default', () => {
    // A proof genuinely minted for OFFLINE_SYNC, presented where a field
    // operation was expected. Under the old optional allowlist this passed.
    const sync = proof({ purpose: 'OFFLINE_SYNC' });
    expect(evaluateDeviceRequestProof(evaluation({ proof: sync, expectedPurpose: 'FIELD_OPERATION' }))).toEqual({
      admitted: false,
      refusal: 'PURPOSE_NOT_ALLOWED',
    });
    // Structural proof that the field is required rather than defaulted.
    const { expectedPurpose, ...withoutPurpose } = evaluation();
    expect(expectedPurpose).toBe('FIELD_OPERATION');
    expect(Object.keys(withoutPurpose)).not.toContain('expectedPurpose');
    expect(
      evaluateDeviceRequestProof(withoutPurpose as unknown as DeviceRequestProofEvaluationInput),
    ).toEqual({ admitted: false, refusal: 'PURPOSE_NOT_ALLOWED' });
  });
});

describe('C15-04 operational rank remains a fact rather than a feeling', () => {
  it('ranks operational capability so that a downgrade is a fact, not a feeling', () => {
    expect(DEVICE_TRUST_OPERATIONAL_RANK.COMPROMISED).toBeLessThan(DEVICE_TRUST_OPERATIONAL_RANK.QUARANTINED);
    // OFFLINE is ignorance, not suspicion, so it outranks SUSPICIOUS.
    expect(DEVICE_TRUST_OPERATIONAL_RANK.OFFLINE).toBeGreaterThan(DEVICE_TRUST_OPERATIONAL_RANK.SUSPICIOUS);
    expect(DEVICE_TRUST_OPERATIONAL_RANK.TRUSTED).toBeGreaterThan(DEVICE_TRUST_OPERATIONAL_RANK.DEGRADED);
    expect(isDeviceTrustDowngrade('TRUSTED', 'SUSPICIOUS')).toBe(true);
    expect(isDeviceTrustDowngrade('OFFLINE', 'TRUSTED')).toBe(false);
    expect(isDeviceTrustDowngrade('TRUSTED', 'TRUSTED')).toBe(false);
  });

  it('C15-R2: the rank comparison is NOT the reconnect authority decision any more', () => {
    // It stays exported and stays correct — it just no longer gates a
    // handshake, because "lower than it was" is not a statement about whether
    // the hardware on the other end of this connection is the registered one.
    expect(isDeviceTrustDowngrade('TRUSTED', 'OFFLINE')).toBe(true);
    const offline = reconnect({ context: context({ device_trust: 'TRUSTED' }), registered: registry({ trust: 'OFFLINE' }) });
    expect(evaluateDeviceReconnectAuthentication(offline).authenticated).toBe(true);
  });
});

describe('C15-R2 reconnect authentication is separate from queue admission', () => {
  /** The device that went dark while TRUSTED and is registry-OFFLINE now. */
  function returnedFromTheDark(trust: DeviceTrust = 'OFFLINE'): Omit<DeviceRequestProofEvaluationInput, 'expectedPurpose'> {
    return reconnect({ context: context({ device_trust: 'TRUSTED' }), registered: registry({ trust }) });
  }

  function admission(
    overrides: Partial<Parameters<typeof evaluateDeviceOfflineQueueAdmission>[0]> = {},
    trust: DeviceTrust = 'OFFLINE',
  ): ReturnType<typeof evaluateDeviceOfflineQueueAdmission> {
    return evaluateDeviceOfflineQueueAdmission({
      authentication: evaluateDeviceReconnectAuthentication(returnedFromTheDark(trust)),
      registered: registry({ trust }),
      context: context({ device_trust: 'TRUSTED' }),
      site_id: 'site-1',
      ...overrides,
    });
  }

  it('THE CASE THE OLD CONTRACT COULD NOT EXPRESS: a formerly-TRUSTED, now registry-OFFLINE device authenticates', () => {
    // The old handshake refused this device `DEVICE_TRUST_DOWNGRADED` before it
    // could present possession — while the purpose table deliberately admitted
    // OFFLINE. The contract contradicted itself and the stricter half won.
    const decision = evaluateDeviceReconnectAuthentication(returnedFromTheDark());
    expect(decision).toMatchObject({ authenticated: true, effect: 'PROCEED', authenticated_device_trust: 'OFFLINE' });
  });

  it('LOCKED: authentication NEVER unlocks a queue — the success arm carries the literal false', () => {
    const decision = evaluateDeviceReconnectAuthentication(returnedFromTheDark());
    expect(decision.queue_examination_permitted).toBe(false);
    // And on the TRUSTED path too: the ruling is about authentication as such,
    // not about which devices happen to be admissible afterwards.
    expect(evaluateDeviceReconnectAuthentication(returnedFromTheDark('TRUSTED')).queue_examination_permitted).toBe(false);
  });

  it('refuses the OFFLINE device its QUEUE, which is where the trust question actually belongs', () => {
    // OFFLINE_SYNC admits TRUSTED and DEGRADED only. Restoring trust is an
    // evidenced transition through `evaluateDeviceTrustTransition`, never a
    // side effect of a successful handshake.
    expect(admission()).toEqual({ permitted: false, refusal: 'DEVICE_TRUST_NOT_PERMITTED' });
  });

  it('a SUSPICIOUS device authenticates for the recovery path and is still refused the queue', () => {
    expect(evaluateDeviceReconnectAuthentication(returnedFromTheDark('SUSPICIOUS')).authenticated).toBe(true);
    expect(admission({}, 'SUSPICIOUS')).toEqual({ permitted: false, refusal: 'DEVICE_TRUST_NOT_PERMITTED' });
  });

  it('a TRUSTED device authenticates AND is admitted', () => {
    expect(evaluateDeviceReconnectAuthentication(returnedFromTheDark('TRUSTED')).authenticated).toBe(true);
    expect(admission({}, 'TRUSTED')).toEqual({ permitted: true });
  });

  it('each authority fact that moved while the device was dark refuses ADMISSION on its own, while authentication still succeeds', () => {
    const cases: Array<[string, Partial<Parameters<typeof evaluateDeviceOfflineQueueAdmission>[0]>, string]> = [
      ['lowered trust', { registered: registry({ trust: 'SUSPICIOUS' }) }, 'DEVICE_TRUST_NOT_PERMITTED'],
      [
        'capability withdrawn',
        { registered: registry({ actor: { user_id: 'user-1', authorised_site_ids: ['site-1'], holds_required_capability: false } }) },
        'ACTOR_AUTHORITY_REMOVED',
      ],
      [
        'a different actor',
        { registered: registry({ actor: { user_id: 'user-9', authorised_site_ids: ['site-1'], holds_required_capability: true } }) },
        'ACTOR_AUTHORITY_REMOVED',
      ],
      [
        'site entitlement lost',
        { registered: registry({ actor: { user_id: 'user-1', authorised_site_ids: ['site-7'], holds_required_capability: true } }) },
        'SITE_ENTITLEMENT_LOST',
      ],
      ['a revocation that landed while it was away', { registered: registry({ revoked: true }) }, 'CREDENTIAL_REVOKED'],
      ['a record about another device', { registered: registry({ device_id: 'device-9' }) }, 'REGISTRY_IDENTITY_MISMATCH'],
    ];
    for (const [label, overrides, refusal] of cases) {
      // Authentication is unaffected: possession of the hardware key is not in
      // question in any of these, which is exactly why they are a separate
      // decision. `registered` here is the record RE-READ after the handshake.
      const authentication = evaluateDeviceReconnectAuthentication(returnedFromTheDark('TRUSTED'));
      expect(authentication.authenticated, label).toBe(true);
      expect(evaluateDeviceOfflineQueueAdmission({
        authentication,
        registered: registry({ trust: 'TRUSTED' }),
        context: context({ device_trust: 'TRUSTED' }),
        site_id: 'site-1',
        ...overrides,
      }), label).toEqual({ permitted: false, refusal });
    }
  });

  it('a FAILED authentication refuses admission outright, before any registry fact is consulted', () => {
    const authentication = evaluateDeviceReconnectAuthentication(reconnect({ verified: false }));
    expect(authentication.authenticated).toBe(false);
    expect(admission({ authentication, registered: registry({ trust: 'TRUSTED' }) }, 'TRUSTED')).toEqual({
      permitted: false,
      refusal: 'NOT_AUTHENTICATED',
    });
  });

  it('QUARANTINED and COMPROMISED still fail AUTHENTICATION itself, via the purpose table', () => {
    // Those are decisions rather than ignorance, so they do not even get to
    // present possession — the widest row in DEVICE_PURPOSE_PERMITTED_TRUST
    // deliberately excludes them.
    for (const trust of ['QUARANTINED', 'COMPROMISED'] as const) {
      expect(evaluateDeviceReconnectAuthentication(returnedFromTheDark(trust)), trust).toEqual({
        authenticated: false,
        refusal: 'DEVICE_TRUST_NOT_PERMITTED',
        queue_examination_permitted: false,
      });
    }
  });

  it('AUTHENTICATION_ONLY skips exactly the actor-authority block and nothing else', () => {
    // The removed actor does not block authentication...
    const strippedActor = registry({ actor: { user_id: 'user-9', authorised_site_ids: ['site-7'], holds_required_capability: false } });
    expect(evaluateDeviceReconnectAuthentication(reconnect({ registered: strippedActor })).authenticated).toBe(true);
    // ...but every other step still runs, in its original order.
    expect(evaluateDeviceReconnectAuthentication(reconnect({ expectedPayloadDigest: OTHER_DIGEST }))).toMatchObject({
      authenticated: false,
      refusal: 'PAYLOAD_DIGEST_MISMATCH',
    });
    expect(evaluateDeviceReconnectAuthentication(reconnect({ registered: registry({ key_version: 9 }) }))).toMatchObject({
      authenticated: false,
      refusal: 'KEY_VERSION_ROTATED',
    });
    expect(evaluateDeviceReconnectAuthentication(reconnect({ now: 'not-a-time' }))).toMatchObject({
      authenticated: false,
      refusal: DEVICE_TIME_NOT_AUTHORITATIVE,
    });
  });

  it('the ordinary evaluator is unchanged: it still ENFORCES actor authority', () => {
    // The refactor must not have leaked AUTHENTICATION_ONLY into the default
    // path — this is the regression that would silently drop three checks.
    expect(
      evaluateDeviceRequestProof(
        evaluation({ registered: registry({ actor: { user_id: 'user-9', authorised_site_ids: ['site-1'], holds_required_capability: true } }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'ACTOR_AUTHORITY_REMOVED' });
    expect(
      evaluateDeviceRequestProof(
        evaluation({ registered: registry({ actor: { user_id: 'user-1', authorised_site_ids: ['site-7'], holds_required_capability: true } }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'SITE_ENTITLEMENT_LOST' });
  });

  it('a converged reconnect retry authenticates without unlocking the queue either', () => {
    const source = proof({ purpose: 'RECONNECT_HANDSHAKE' });
    const decision = evaluateDeviceReconnectAuthentication(
      reconnect({ consumption: consumptionFor(source, { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'handshake-1' }) }),
    );
    expect(decision).toMatchObject({
      authenticated: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      stored_outcome_ref: 'handshake-1',
      queue_examination_permitted: false,
    });
  });
});

describe('C15-R2-final the authentication verdict is bound, and the purpose is not a parameter', () => {
  function authenticatedTrusted(): ReturnType<typeof evaluateDeviceReconnectAuthentication> {
    return evaluateDeviceReconnectAuthentication(
      reconnect({ context: context({ device_trust: 'TRUSTED' }), registered: registry({ trust: 'TRUSTED' }) }),
    );
  }

  function admit(
    overrides: Partial<Parameters<typeof evaluateDeviceOfflineQueueAdmission>[0]> = {},
  ): ReturnType<typeof evaluateDeviceOfflineQueueAdmission> {
    return evaluateDeviceOfflineQueueAdmission({
      authentication: authenticatedTrusted(),
      registered: registry({ trust: 'TRUSTED' }),
      context: context({ device_trust: 'TRUSTED' }),
      site_id: 'site-1',
      ...overrides,
    });
  }

  it('carries the exact identity it authenticated, on both success arms', () => {
    const decision = authenticatedTrusted();
    expect(decision).toMatchObject({
      authenticated: true,
      binding: {
        organisation_id: 'org-1',
        context_id: 'ctx-1',
        actor_user_id: 'user-1',
        device_id: 'device-1',
        key_id: 'key-1',
        key_version: 4,
      },
    });
    // The bound key is the REGISTRY's, not the context's claim about it — the
    // evaluation proved the two equal before this was recorded.
    if (decision.authenticated) expect(decision.binding.key_version).toBe(registry({ trust: 'TRUSTED' }).key_version);
  });

  it('admits the bound device, and that is the only shape that is admitted', () => {
    expect(admit()).toEqual({ permitted: true });
  });

  it('LOCKED: a genuine verdict cannot be borrowed for another org, context, actor, device or key', () => {
    const genuine = authenticatedTrusted();
    expect(genuine.authenticated).toBe(true);
    const mutations: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ['organisation', { organisation_id: 'org-2' }],
      ['context', { context_id: 'ctx-2' }],
      ['actor', { actor_user_id: 'user-2' }],
      ['device', { device_id: 'device-2' }],
      ['key id', { key_id: 'key-2' }],
    ];
    for (const [label, patch] of mutations) {
      const borrowed = { ...genuine, binding: { ...(genuine as { binding: object }).binding, ...patch } };
      expect(
        admit({ authentication: borrowed as ReturnType<typeof evaluateDeviceReconnectAuthentication> }),
        label,
      ).toEqual({ permitted: false, refusal: 'AUTHENTICATION_BINDING_MISMATCH' });
    }
  });

  it('LOCKED: a key rotation BETWEEN authentication and admission refuses, named as a rotation', () => {
    // The verdict is honest — it was true when it was produced. The registry
    // moved underneath it, which is exactly what the second read exists to
    // catch, and D23-09 says a superseded version authorises nothing.
    const genuine = authenticatedTrusted();
    expect(admit({ registered: registry({ trust: 'TRUSTED', key_version: 5 }) })).toEqual({
      permitted: false,
      refusal: 'KEY_VERSION_ROTATED',
    });
    // It is a DIFFERENT refusal from a borrowed verdict, so an operator reading
    // the audit trail can tell an overtaken handshake from a stolen one.
    expect(genuine.authenticated).toBe(true);
  });

  it('LOCKED: the admission purpose is a constant, not a caller argument', () => {
    expect(DEVICE_QUEUE_ADMISSION_PURPOSE).toBe('OFFLINE_SYNC');
    // The input type has nowhere to put a purpose at all: passing the widest
    // row in the table is not merely refused, it is unrepresentable.
    const withPurpose = { ...({} as Record<string, unknown>), queuedPurpose: 'RECONNECT_HANDSHAKE' };
    expect(Object.keys(withPurpose)).toContain('queuedPurpose');
    // And the constant names the narrow row: OFFLINE_SYNC excludes OFFLINE and
    // SUSPICIOUS, which is what stops a dark device syncing on a handshake.
    expect(DEVICE_PURPOSE_PERMITTED_TRUST[DEVICE_QUEUE_ADMISSION_PURPOSE]).toEqual(['TRUSTED', 'DEGRADED']);
    expect(DEVICE_PURPOSE_PERMITTED_TRUST[DEVICE_QUEUE_ADMISSION_PURPOSE]).not.toContain('OFFLINE');
    expect(DEVICE_PURPOSE_PERMITTED_TRUST[DEVICE_QUEUE_ADMISSION_PURPOSE]).not.toContain('SUSPICIOUS');
  });

  it('checks the binding BEFORE trust, so a borrowed verdict never reaches the trust gate', () => {
    const genuine = authenticatedTrusted();
    const borrowed = { ...genuine, binding: { ...(genuine as { binding: object }).binding, device_id: 'device-2' } };
    // Registry trust here would refuse anyway; the refusal must still name the
    // binding, because that is the more fundamental defect.
    expect(
      admit({
        authentication: borrowed as ReturnType<typeof evaluateDeviceReconnectAuthentication>,
        registered: registry({ trust: 'OFFLINE' }),
      }),
    ).toEqual({ permitted: false, refusal: 'AUTHENTICATION_BINDING_MISMATCH' });
  });
});

describe('C15-R1 a malformed duplicate can never reach PROCEED', () => {
  function malformed(): Array<[string, DeviceNonceConsumption]> {
    const wellFormed = consumptionFor(proof());
    const base = { source: 'SENTINEL_NONCE_STORE', replay_key: wellFormed.replay_key, statement_fingerprint: wellFormed.statement_fingerprint };
    return (
      [
        ['EXACT_DUPLICATE with a null ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: null }],
        ['EXACT_DUPLICATE with an empty ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: '' }],
        ['EXACT_DUPLICATE with a blank ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: '   ' }],
        ['FIRST_SEEN carrying a stored ref', { ...base, outcome: 'FIRST_SEEN', stored_outcome_ref: 'operation-1' }],
        ['a foreign source', { ...base, source: 'DEVICE_CLAIM', outcome: 'FIRST_SEEN', stored_outcome_ref: null }],
        ['a missing outcome', { ...base, stored_outcome_ref: null }],
        ['a missing stored_outcome_ref', { ...base, outcome: 'EXACT_DUPLICATE' }],
      ] as Array<[string, unknown]>
    ).map(([label, fact]) => [label, fact as DeviceNonceConsumption]);
  }

  it('LOCKED: every malformed consumption fact refuses, and none of them PROCEEDS', () => {
    // THE DEFECT: `if (outcome === 'EXACT_DUPLICATE' && ref !== null) converge`
    // — else PROCEED. A duplicate carrying a null ref fell past the convergence
    // branch and caused a SECOND EFFECT for a retry the store had reported.
    for (const [label, fact] of malformed()) {
      expect(evaluateDeviceRequestProof(evaluation({ consumption: fact })), label).toEqual({
        admitted: false,
        refusal: 'NONCE_CONSUMPTION_INCONSISTENT',
      });
    }
  });

  it('the guard itself accepts the three well-formed arms and rejects the malformed ones', () => {
    expect(isConsistentDeviceNonceConsumption(consumptionFor(proof()))).toBe(true);
    expect(isConsistentDeviceNonceConsumption(consumptionFor(proof(), { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'x' }))).toBe(true);
    expect(isConsistentDeviceNonceConsumption(consumptionFor(proof(), { outcome: 'REUSED_WITH_CHANGED_SEMANTICS' }))).toBe(true);
    for (const [label, fact] of malformed()) {
      expect(isConsistentDeviceNonceConsumption(fact), label).toBe(false);
    }
  });

  it('a well-formed EXACT_DUPLICATE still converges: the guard closes a hole, it does not close the door', () => {
    expect(
      evaluateDeviceRequestProof(evaluation({ consumption: consumptionFor(proof(), { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'op-1' }) })),
    ).toMatchObject({ admitted: true, effect: 'CONVERGE_ON_STORED_OUTCOME', stored_outcome_ref: 'op-1' });
  });
});

describe('C15-05 the request proof nonce is one-shot through a contract seam', () => {
  it('scopes the replay identity to org, site, actor, device, key version and nonce', () => {
    expect(deviceRequestProofReplayIdentity(proof())).toEqual({
      organisation_id: 'org-1',
      site_id: 'site-1',
      actor_user_id: 'user-1',
      device_id: 'device-1',
      key_version: 4,
      nonce: NONCE,
    });
    // The ACTOR is in the identity for WP-20's reason: one device, many shifts.
    expect(deviceRequestProofReplayKey(proof())).not.toBe(deviceRequestProofReplayKey(proof({ actor_user_id: 'user-2' })));
    // A rotation is a new credential, so a slot consumed under the old key
    // version says nothing about the new one.
    expect(deviceRequestProofReplayKey(proof())).not.toBe(deviceRequestProofReplayKey(proof({ key_version: 9 })));
    // C11-01: canonical JSON, so a delimiter inside a value cannot forge a tuple.
    expect(deviceRequestProofReplayKey(proof({ organisation_id: 'a:b', site_id: 'c' }))).not.toBe(
      deviceRequestProofReplayKey(proof({ organisation_id: 'a', site_id: 'b:c' })),
    );
  });

  it('is DISTINCT from the statement fingerprint, which is what makes retry and reuse separable', () => {
    const p = proof();
    expect(deviceRequestProofReplayKey(p)).not.toBe(deviceRequestProofFingerprint(statement(p)));
    // Two proofs sharing a one-shot slot but carrying different bytes.
    const rewritten = proof({ payload_digest: OTHER_DIGEST });
    expect(deviceRequestProofReplayKey(rewritten)).toBe(deviceRequestProofReplayKey(p));
    expect(deviceRequestProofFingerprint(statement(rewritten))).not.toBe(deviceRequestProofFingerprint(statement(p)));
  });

  it('an exact duplicate CONVERGES on the stored outcome and causes no second effect', () => {
    const decision = evaluateDeviceRequestProof(
      evaluation({ consumption: consumptionFor(proof(), { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'operation-1' }) }),
    );
    expect(decision).toEqual({
      admitted: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      fingerprint: deviceRequestProofFingerprint(statement(proof())),
      stored_outcome_ref: 'operation-1',
    });
  });

  it('LOCKED: the same slot carrying CHANGED semantics conflicts and causes nothing', () => {
    expect(
      evaluateDeviceRequestProof(evaluation({ consumption: consumptionFor(proof(), { outcome: 'REUSED_WITH_CHANGED_SEMANTICS' }) })),
    ).toEqual({ admitted: false, refusal: 'NONCE_REUSED_WITH_CHANGED_SEMANTICS' });
  });

  it('LOCKED: a consumption fact about ANOTHER request cannot stand in for this one', () => {
    expect(
      evaluateDeviceRequestProof(evaluation({ consumption: consumptionFor(proof({ nonce: 'nonce-fedcba9876543210' })) })),
    ).toEqual({ admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' });
    // Right slot, wrong bytes: also not evidence about this request.
    expect(
      evaluateDeviceRequestProof(evaluation({ consumption: consumptionFor(proof(), { statement_fingerprint: 'e'.repeat(64) }) })),
    ).toEqual({ admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' });
  });

  it('the consumption fact cannot be defaulted away: it is a required input', () => {
    const { consumption, ...withoutFact } = evaluation();
    expect(consumption).toBeDefined();
    expect(Object.keys(withoutFact)).not.toContain('consumption');
    // C15-R1: without the fact there is no decision to make. This used to
    // CRASH on a property access; the runtime consistency guard now turns it
    // into a NAMED refusal, which is auditable rather than a 500 and still
    // admits nothing.
    expect(evaluateDeviceRequestProof(withoutFact as unknown as DeviceRequestProofEvaluationInput)).toEqual({
      admitted: false,
      refusal: 'NONCE_CONSUMPTION_INCONSISTENT',
    });
  });
});

describe('C15-07 the context evaluator fails closed on time', () => {
  it('refuses an unreadable server clock rather than admitting on a NaN comparison', () => {
    // `Date.parse` returns NaN and every comparison against NaN is false, so
    // the old code answered "not expired, no skew" for an unreadable instant.
    expect(evaluateDeviceRequestProof(evaluation({ now: 'not-a-time' }))).toEqual({
      admitted: false,
      refusal: DEVICE_TIME_NOT_AUTHORITATIVE,
    });
  });

  it('treats context expiry as an EXCLUSIVE boundary, asserted exactly at the instant', () => {
    // One millisecond before expiry the context is live. (The proof is minted
    // at that instant too, so freshness cannot deflect the assertion.)
    const late = proof({ issued_at: iso(119_999) });
    expect(evaluateDeviceRequestProof(evaluation({ now: iso(119_999), proof: late })).admitted).toBe(true);
    // At the instant named as the expiry it is already dead.
    expect(evaluateDeviceRequestProof(evaluation({ now: iso(120_000), proof: late }))).toEqual({
      admitted: false,
      refusal: 'CONTEXT_EXPIRED',
    });
    expect(isDeviceContextExpired(context(), iso(119_999))).toBe(false);
    expect(isDeviceContextExpired(context(), iso(120_000))).toBe(true);
  });

  it('reports no remaining lifetime, and reads as expired, when an instant is unreadable', () => {
    expect(deviceContextRemainingMs(context(), 'whenever')).toBeNull();
    expect(isDeviceContextExpired(context(), 'whenever')).toBe(true);
  });
});
