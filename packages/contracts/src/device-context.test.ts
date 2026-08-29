import { describe, expect, it } from 'vitest';
import {
  AuthenticatedDeviceContextSchema,
  canonicalDeviceRequestProofStatement,
  DEVICE_REQUEST_PROOF_DOMAIN,
  DEVICE_REQUEST_PURPOSES,
  deviceContextPermits,
  deviceContextRemainingMs,
  DeviceRequestProofSchema,
  deviceRequestProofFingerprint,
  evaluateDeviceReconnectHandshake,
  evaluateDeviceRequestProof,
  isDeviceContextExpired,
  type AuthenticatedDeviceContext,
  type DeviceRequestProof,
  type DeviceRequestProofEvaluationInput,
  type DeviceRequestProofStatementInput,
} from './device-context.js';
import { DEVICE_CONTEXT_MAX_LIFETIME_MS, DEVICE_REQUEST_PROOF_MAX_AGE_MS, DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS } from './device-identity.js';
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
    signature_profile: 'P256_ECDSA_SHA256',
    signature: SIGNATURE,
    ...overrides,
  });
}

function evaluation(overrides: Partial<DeviceRequestProofEvaluationInput> = {}): DeviceRequestProofEvaluationInput {
  return {
    context: context(),
    proof: proof(),
    now: NOW,
    expectedPayloadDigest: PAYLOAD_DIGEST,
    registered: { key_id: 'key-1', key_version: 4, revoked: false },
    verified: true,
    ...overrides,
  };
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
    expect(canonicalDeviceRequestProofStatement(proof())).toContain(DEVICE_REQUEST_PROOF_DOMAIN);
  });

  it('excludes the signature from the bytes it signs', () => {
    expect(canonicalDeviceRequestProofStatement(proof())).not.toContain(SIGNATURE);
  });

  it('changes the fingerprint for every individually mutated bound component, and never converges on the original', () => {
    const baseline = deviceRequestProofFingerprint(proof());
    const mutations: Array<[string, DeviceRequestProofStatementInput]> = [
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
      const digest = deviceRequestProofFingerprint(mutated);
      expect(digest, `${label} must move the fingerprint`).not.toBe(baseline);
      digests.add(digest);
    }
    expect(digests.size).toBe(mutations.length + 1);
  });

  it('cannot be forged by a value that contains a delimiter, because the statement is canonical JSON not a joined string', () => {
    const a = deviceRequestProofFingerprint(proof({ organisation_id: 'org\n1', site_id: 'site-1' }));
    const b = deviceRequestProofFingerprint(proof({ organisation_id: 'org', site_id: '1\nsite-1' }));
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
    if (decision.admitted) expect(decision.fingerprint).toBe(deviceRequestProofFingerprint(proof()));
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
    expect(evaluateDeviceRequestProof(evaluation({ registered: { key_id: 'key-1', key_version: 5, revoked: false } }))).toEqual({
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
    expect(evaluateDeviceRequestProof(evaluation({ registered: { key_id: 'key-1', key_version: 4, revoked: true } }))).toEqual({
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

  it('refuses a purpose outside the caller-declared allowlist', () => {
    expect(evaluateDeviceRequestProof(evaluation({ allowedPurposes: ['WHISPER_DEVICE_ACTION'] }))).toEqual({
      admitted: false,
      refusal: 'PURPOSE_NOT_ALLOWED',
    });
  });
});

describe('the reconnect handshake authenticates by possession (D23-13 / C14-03)', () => {
  it('admits a reconnect proved with the hardware key', () => {
    const decision = evaluateDeviceReconnectHandshake(evaluation({ proof: proof({ purpose: 'RECONNECT_HANDSHAKE' }) }));
    expect(decision.admitted).toBe(true);
  });

  it('refuses a presented token without possession', () => {
    expect(evaluateDeviceReconnectHandshake(evaluation({ proof: proof({ purpose: 'RECONNECT_HANDSHAKE' }), verified: false }))).toEqual({
      admitted: false,
      refusal: 'POSSESSION_NOT_PROVEN',
    });
  });

  it('refuses a proof minted for some other purpose being reused to reconnect', () => {
    expect(evaluateDeviceReconnectHandshake(evaluation())).toEqual({ admitted: false, refusal: 'PURPOSE_NOT_ALLOWED' });
  });

  it('fails closed as a whole before any queued operation could be examined', () => {
    const revoked = evaluation({ proof: proof({ purpose: 'RECONNECT_HANDSHAKE' }), registered: { key_id: 'key-1', key_version: 4, revoked: true } });
    expect(evaluateDeviceReconnectHandshake(revoked)).toEqual({ admitted: false, refusal: 'CREDENTIAL_REVOKED' });
  });
});
