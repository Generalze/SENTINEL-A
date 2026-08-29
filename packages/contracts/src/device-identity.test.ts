import { describe, expect, it } from 'vitest';
import * as deviceIdentityModule from './device-identity.js';
import {
  ALLOWED_DEVICE_ENROLLMENT_TRANSITIONS,
  ALLOWED_DEVICE_TRUST_TRANSITIONS,
  approvalMatchesEnrollmentRequest,
  attestationStandingPermitsTrusted,
  bootstrapGrantMatchesScope,
  canTransitionDeviceEnrollment,
  canTransitionDeviceTrust,
  canonicalDeviceJson,
  canonicalDevicePossessionStatement,
  classifyDeviceBootstrapGrant,
  classifyDeviceKeyChange,
  DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS,
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_CREDENTIAL_ESTABLISHES,
  DEVICE_CUSTODY_MODES,
  DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS,
  DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS,
  DEVICE_ENROLLMENT_REQUIRED_FACTS,
  DEVICE_ENROLLMENT_STATES,
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS,
  DEVICE_REQUEST_PROOF_MAX_AGE_MS,
  DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS,
  DEVICE_TRUST_RESTORATION_CAPABILITY,
  DeviceAttestationOutcomeSchema,
  DeviceCustodySchema,
  DeviceEnrollmentApprovalSchema,
  DeviceEnrollmentBootstrapGrantSchema,
  DeviceEnrollmentRequestSchema,
  DeviceIdentitySchema,
  DevicePossessionChallengeSchema,
  DevicePossessionResponseSchema,
  deviceEnrollmentRequestFingerprint,
  deviceKeyStoragePermitsTrusted,
  devicePossessionStatementFingerprint,
  deviceSequenceNamespaceId,
  evaluateAttestationStanding,
  evaluateDeviceEnrollmentCommit,
  evaluateDeviceOperationPrincipals,
  evaluateDeviceTrustTransition,
  initialDeviceTrustOnEnrollment,
  isCanonicalDeviceJsonRecord,
  isTerminalDeviceEnrollmentState,
  isTerminalDeviceTrust,
  USER_SESSION_ESTABLISHES,
  type DeviceEnrollmentApproval,
  type DeviceEnrollmentBootstrapGrant,
  type DeviceEnrollmentCommitInput,
  type DeviceEnrollmentRequest,
  type DeviceEnrollmentState,
  type DeviceKeyChangeProposal,
  type DeviceKeyChangeSubject,
  type DevicePossessionChallenge,
  type DeviceTrustTransitionBasis,
} from './device-identity.js';
import { DeviceTrustSchema, type DeviceTrust } from './device.js';

/** WP-23 Crucible — device identity, enrollment, keys, attestation and trust. */

const NOW = '2026-08-29T12:00:00.000Z';
const THUMBPRINT = 'a'.repeat(64);
const ATTACKER_THUMBPRINT = 'b'.repeat(64);
const SIGNATURE = Buffer.from(new Uint8Array(64).fill(7)).toString('base64url');
const NONCE = 'nonce-0123456789abcdef';

function iso(base: string, deltaMs: number): string {
  return new Date(Date.parse(base) + deltaMs).toISOString();
}

function grant(overrides: Record<string, unknown> = {}): DeviceEnrollmentBootstrapGrant {
  return DeviceEnrollmentBootstrapGrantSchema.parse({
    schema_version: 1,
    grant_id: 'grant-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    intended_user_id: 'user-1',
    issued_by_user_id: 'commander-1',
    issued_at: iso(NOW, -60_000),
    expires_at: iso(NOW, 300_000),
    single_use: true,
    consumed_at: null,
    revoked_at: null,
    ...overrides,
  });
}

function request(overrides: Record<string, unknown> = {}): DeviceEnrollmentRequest {
  return DeviceEnrollmentRequestSchema.parse({
    schema_version: 1,
    enrollment_request_id: 'enrol-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    intended_user_id: 'user-1',
    bootstrap_grant_id: 'grant-1',
    custody: 'PERSONAL',
    signature_profile: 'P256_ECDSA_SHA256',
    key_storage: 'HARDWARE_BACKED',
    public_key_thumbprint: THUMBPRINT,
    attestation: { outcome: 'VERIFIED', evaluated_at: NOW, attestation_reference: 'att-1' },
    requested_at: iso(NOW, -30_000),
    ...overrides,
  });
}

function approvalFor(target: DeviceEnrollmentRequest, overrides: Record<string, unknown> = {}): DeviceEnrollmentApproval {
  return DeviceEnrollmentApprovalSchema.parse({
    schema_version: 1,
    approval_id: 'approval-1',
    enrollment_request_id: target.enrollment_request_id,
    enrollment_request_fingerprint: deviceEnrollmentRequestFingerprint(target),
    organisation_id: target.organisation_id,
    site_id: target.site_id,
    custody: target.custody,
    approved_by_user_id: 'commander-1',
    approved_at: iso(NOW, -20_000),
    ...overrides,
  });
}

function challenge(overrides: Record<string, unknown> = {}): DevicePossessionChallenge {
  return DevicePossessionChallengeSchema.parse({
    schema_version: 1,
    challenge_id: 'challenge-1',
    enrollment_request_id: 'enrol-1',
    nonce: NONCE,
    issued_at: iso(NOW, -10_000),
    expires_at: iso(NOW, 60_000),
    ...overrides,
  });
}

function commitInput(overrides: Partial<DeviceEnrollmentCommitInput> = {}): DeviceEnrollmentCommitInput {
  const enrollmentRequest = overrides.request ?? request();
  return {
    request: enrollmentRequest,
    grant: grant(),
    approval: approvalFor(enrollmentRequest),
    challenge: challenge(),
    possessionVerified: true,
    possessionAnsweredAt: iso(NOW, -5_000),
    authenticatedUserId: 'user-1',
    now: NOW,
    ...overrides,
  };
}

const RESTORATION_BASIS: DeviceTrustTransitionBasis = {
  controlledRestoration: { decided_by_user_id: 'commander-1', capability: DEVICE_TRUST_RESTORATION_CAPABILITY, decided_at: NOW },
  attestationStanding: 'CURRENT',
  keyStorage: 'HARDWARE_BACKED',
  credentialContinuityIntact: true,
  revoked: false,
  previouslyEligible: true,
};

const BLIND_BASIS: DeviceTrustTransitionBasis = {
  controlledRestoration: null,
  attestationStanding: 'INELIGIBLE',
  keyStorage: 'SOFTWARE',
  credentialContinuityIntact: false,
  revoked: false,
  previouslyEligible: false,
};

// ---------------------------------------------------------------------------

describe('WP-23 numeric ceilings', () => {
  it('pins every ceiling to the value the directive locked, since raising one is a security-contract change', () => {
    expect(DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS).toBe(600_000);
    expect(DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS).toBe(900_000);
    expect(DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS).toBe(120_000);
    expect(DEVICE_CONTEXT_MAX_LIFETIME_MS).toBe(300_000);
    expect(DEVICE_REQUEST_PROOF_MAX_AGE_MS).toBe(60_000);
    expect(DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS).toBe(5_000);
    expect(DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS).toBe(21_600_000);
    expect(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS).toBe(21_600_000);
  });

  it('accepts a bootstrap grant exactly at DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS and refuses one millisecond past it (D23-04)', () => {
    const issued_at = NOW;
    expect(() => grant({ issued_at, expires_at: iso(NOW, DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS) })).not.toThrow();
    expect(() => grant({ issued_at, expires_at: iso(NOW, DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS + 1) })).toThrow();
  });

  it('accepts a possession challenge exactly at DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS and refuses one millisecond past it (D23-03)', () => {
    const issued_at = NOW;
    expect(() => challenge({ issued_at, expires_at: iso(NOW, DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS) })).not.toThrow();
    expect(() => challenge({ issued_at, expires_at: iso(NOW, DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS + 1) })).toThrow();
  });

  it('accepts an enrollment request exactly at DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS and refuses one millisecond past it (C14-02)', () => {
    const requested_at = iso(NOW, -DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS);
    const atBound = commitInput({ request: request({ requested_at }) });
    expect(evaluateDeviceEnrollmentCommit(atBound).decision).toBe('COMMIT');

    const pastBound = commitInput({ request: request({ requested_at: iso(NOW, -DEVICE_ENROLLMENT_REQUEST_MAX_AGE_MS - 1) }) });
    expect(evaluateDeviceEnrollmentCommit(pastBound)).toEqual({ decision: 'REFUSE', refusal: 'REQUEST_EXPIRED' });
  });
});

describe('D23-01/D23-02 the principal boundary', () => {
  it('refuses when a user session is presented alone: a valid login never manufactures device trust (D23-01)', () => {
    expect(
      evaluateDeviceOperationPrincipals({
        userAuthenticated: true,
        deviceAuthenticated: false,
        deviceTrust: 'TRUSTED',
        requiredTrust: ['TRUSTED'],
        siteAuthorityGranted: true,
        policySatisfied: true,
      }),
    ).toEqual({ admitted: false, refusal: 'DEVICE_NOT_AUTHENTICATED' });
  });

  it('refuses when a device credential is presented alone: a registered device never manufactures user authority (D23-02)', () => {
    expect(
      evaluateDeviceOperationPrincipals({
        userAuthenticated: false,
        deviceAuthenticated: true,
        deviceTrust: 'TRUSTED',
        requiredTrust: ['TRUSTED'],
        siteAuthorityGranted: true,
        policySatisfied: true,
      }),
    ).toEqual({ admitted: false, refusal: 'USER_NOT_AUTHENTICATED' });
  });

  it('requires all four facts together and names the missing one', () => {
    const base = {
      userAuthenticated: true,
      deviceAuthenticated: true,
      deviceTrust: 'TRUSTED' as DeviceTrust,
      requiredTrust: ['TRUSTED'] as readonly DeviceTrust[],
      siteAuthorityGranted: true,
      policySatisfied: true,
    };
    expect(evaluateDeviceOperationPrincipals(base)).toEqual({ admitted: true });
    expect(evaluateDeviceOperationPrincipals({ ...base, deviceTrust: 'DEGRADED' })).toEqual({
      admitted: false,
      refusal: 'DEVICE_TRUST_INSUFFICIENT',
    });
    expect(evaluateDeviceOperationPrincipals({ ...base, siteAuthorityGranted: false })).toEqual({
      admitted: false,
      refusal: 'SITE_AUTHORITY_MISSING',
    });
    expect(evaluateDeviceOperationPrincipals({ ...base, policySatisfied: false })).toEqual({ admitted: false, refusal: 'POLICY_NOT_SATISFIED' });
  });

  it('keeps the device-established and session-established fact sets disjoint', () => {
    const overlap = DEVICE_CREDENTIAL_ESTABLISHES.filter((fact) => (USER_SESSION_ESTABLISHES as readonly string[]).includes(fact));
    expect(overlap).toEqual([]);
  });
});

describe('the enrollment lifecycle (C14-02)', () => {
  it('pins the full transition matrix so no edge is added without a visible diff', () => {
    expect(ALLOWED_DEVICE_ENROLLMENT_TRANSITIONS).toEqual({
      REQUESTED: ['APPROVED', 'REJECTED', 'EXPIRED'],
      APPROVED: ['POSSESSION_PROVEN', 'REJECTED', 'EXPIRED'],
      POSSESSION_PROVEN: ['ENROLLED', 'REJECTED', 'EXPIRED'],
      ENROLLED: ['REVOKED'],
      REJECTED: [],
      EXPIRED: [],
      REVOKED: [],
    });
  });

  it('admits only the canonical edges across the whole state product', () => {
    for (const from of DEVICE_ENROLLMENT_STATES) {
      for (const to of DEVICE_ENROLLMENT_STATES) {
        const expected = ALLOWED_DEVICE_ENROLLMENT_TRANSITIONS[from].includes(to);
        expect(canTransitionDeviceEnrollment(from, to)).toBe(expected);
      }
    }
  });

  it('has no shortcut from REQUESTED to ENROLLED: approval and possession both stand in the way', () => {
    expect(canTransitionDeviceEnrollment('REQUESTED', 'ENROLLED')).toBe(false);
    expect(canTransitionDeviceEnrollment('REQUESTED', 'POSSESSION_PROVEN')).toBe(false);
    expect(canTransitionDeviceEnrollment('APPROVED', 'ENROLLED')).toBe(false);
  });

  it('never resurrects a terminal enrollment', () => {
    for (const terminal of ['REJECTED', 'EXPIRED', 'REVOKED'] as DeviceEnrollmentState[]) {
      expect(isTerminalDeviceEnrollmentState(terminal)).toBe(true);
      for (const to of DEVICE_ENROLLMENT_STATES) {
        expect(canTransitionDeviceEnrollment(terminal, to)).toBe(false);
      }
    }
  });

  it('does not admit a self-transition anywhere in the lifecycle', () => {
    for (const state of DEVICE_ENROLLMENT_STATES) {
      expect(canTransitionDeviceEnrollment(state, state)).toBe(false);
    }
  });
});

describe('the bootstrap grant (D23-04)', () => {
  it('classifies revoked, consumed and expired grants ahead of usable ones', () => {
    expect(classifyDeviceBootstrapGrant(grant(), NOW)).toBe('USABLE');
    expect(classifyDeviceBootstrapGrant(grant({ revoked_at: iso(NOW, -1_000) }), NOW)).toBe('REVOKED');
    expect(classifyDeviceBootstrapGrant(grant({ consumed_at: iso(NOW, -1_000) }), NOW)).toBe('CONSUMED');
    expect(classifyDeviceBootstrapGrant(grant({ expires_at: iso(NOW, -1) }), NOW)).toBe('EXPIRED');
  });

  it('binds to exactly one organisation, site and intended user', () => {
    const g = grant();
    expect(bootstrapGrantMatchesScope(g, { organisation_id: 'org-1', site_id: 'site-1', intended_user_id: 'user-1' })).toBe(true);
    expect(bootstrapGrantMatchesScope(g, { organisation_id: 'org-2', site_id: 'site-1', intended_user_id: 'user-1' })).toBe(false);
    expect(bootstrapGrantMatchesScope(g, { organisation_id: 'org-1', site_id: 'site-2', intended_user_id: 'user-1' })).toBe(false);
    expect(bootstrapGrantMatchesScope(g, { organisation_id: 'org-1', site_id: 'site-1', intended_user_id: 'user-2' })).toBe(false);
  });

  it('carries no token material anywhere in the grant record (D23-14)', () => {
    for (const field of ['token', 'bootstrap_token', 'secret', 'code']) {
      expect(() => grant({ [field]: 'super-secret' })).toThrow();
    }
  });

  it('has no multi-use grant to configure', () => {
    expect(() => grant({ single_use: false })).toThrow();
  });
});

describe('the enrollment request fingerprint (C14-02)', () => {
  it('changes when any bound component of the request changes, and never converges on the original', () => {
    const original = request();
    const baseline = deviceEnrollmentRequestFingerprint(original);
    const mutations: Array<[string, DeviceEnrollmentRequest]> = [
      ['enrollment_request_id', request({ enrollment_request_id: 'enrol-2' })],
      ['organisation_id', request({ organisation_id: 'org-2' })],
      ['site_id', request({ site_id: 'site-2' })],
      ['intended_user_id', request({ intended_user_id: 'user-2' })],
      ['bootstrap_grant_id', request({ bootstrap_grant_id: 'grant-2' })],
      ['custody', request({ custody: 'CONTROLLED_SHARED' })],
      ['key_storage', request({ key_storage: 'SOFTWARE' })],
      ['public_key_thumbprint', request({ public_key_thumbprint: ATTACKER_THUMBPRINT })],
      ['attestation.outcome', request({ attestation: { outcome: 'UNAVAILABLE', evaluated_at: NOW, attestation_reference: 'att-1' } })],
      ['requested_at', request({ requested_at: iso(NOW, -31_000) })],
    ];
    const digests = new Set<string>([baseline]);
    for (const [label, mutated] of mutations) {
      const digest = deviceEnrollmentRequestFingerprint(mutated);
      expect(digest, `${label} must move the fingerprint`).not.toBe(baseline);
      digests.add(digest);
    }
    expect(digests.size).toBe(mutations.length + 1);
  });

  it('is a lowercase 64-character SHA-256 hex digest', () => {
    expect(deviceEnrollmentRequestFingerprint(request())).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('refuses a private key, escrow or backup field anywhere in the request (D23-03)', () => {
    for (const field of ['private_key', 'key_escrow', 'key_backup', 'public_key_pem', 'secret_key']) {
      expect(() => request({ [field]: 'MIIE...' })).toThrow();
    }
  });
});

describe('C14-02 approval binds the exact request, not a device class', () => {
  it('matches the request it was issued for', () => {
    const target = request();
    expect(approvalMatchesEnrollmentRequest(approvalFor(target), target)).toBe(true);
  });

  it('refuses when the attacker substitutes their own public key into an otherwise identical request', () => {
    const intended = request();
    const attacker = request({ public_key_thumbprint: ATTACKER_THUMBPRINT });
    const approval = approvalFor(intended);
    expect(approvalMatchesEnrollmentRequest(approval, attacker)).toBe(false);
  });

  it('refuses an approval that names only the device class, site and custody but a different request', () => {
    const intended = request();
    const other = request({ enrollment_request_id: 'enrol-2', public_key_thumbprint: ATTACKER_THUMBPRINT });
    const classApproval = approvalFor(intended, { enrollment_request_id: other.enrollment_request_id });
    expect(approvalMatchesEnrollmentRequest(classApproval, other)).toBe(false);
  });

  it('LOCKED: a stolen bootstrap grant plus an attacker keypair cannot complete enrollment (C14-02)', () => {
    // The attacker holds a real, unused, in-scope grant and genuinely proves
    // possession — of THEIR OWN key. No human approved that request.
    const attackerRequest = request({ public_key_thumbprint: ATTACKER_THUMBPRINT });
    const stolen = evaluateDeviceEnrollmentCommit({
      request: attackerRequest,
      grant: grant(),
      approval: approvalFor(request()), // the approval a Command principal issued for the REAL device
      challenge: challenge(),
      possessionVerified: true,
      possessionAnsweredAt: iso(NOW, -5_000),
      authenticatedUserId: 'user-1',
      now: NOW,
    });
    expect(stolen).toEqual({ decision: 'REFUSE', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' });
  });
});

describe('the enrollment commit gate (C14-02)', () => {
  it('commits when all four required facts are present', () => {
    const decision = evaluateDeviceEnrollmentCommit(commitInput());
    expect(decision.decision).toBe('COMMIT');
    if (decision.decision === 'COMMIT') {
      expect(decision.enrollment_request_fingerprint).toBe(deviceEnrollmentRequestFingerprint(request()));
    }
  });

  it('names four required facts and refuses when any single one is removed', () => {
    expect(DEVICE_ENROLLMENT_REQUIRED_FACTS).toHaveLength(4);
    expect(evaluateDeviceEnrollmentCommit(commitInput({ grant: null }))).toEqual({ decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_MISSING' });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ approval: null }))).toEqual({ decision: 'REFUSE', refusal: 'APPROVAL_MISSING' });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ authenticatedUserId: null }))).toEqual({
      decision: 'REFUSE',
      refusal: 'USER_NOT_AUTHENTICATED',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ challenge: null }))).toEqual({ decision: 'REFUSE', refusal: 'CHALLENGE_MISSING' });
  });

  it('refuses an enrollment without proof of possession even when everything else is perfect (D23-03)', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerified: false }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_NOT_PROVEN',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionAnsweredAt: null }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_NOT_PROVEN',
    });
  });

  it('refuses a consumed grant: a second use is a conflict, never a second device (D23-04)', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ grant: grant({ consumed_at: iso(NOW, -1_000) }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'BOOTSTRAP_GRANT_UNUSABLE',
    });
  });

  it('refuses a grant revoked before use, and one used out of its scope', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ grant: grant({ revoked_at: iso(NOW, -1) }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'BOOTSTRAP_GRANT_UNUSABLE',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ grant: grant({ site_id: 'site-9' }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'BOOTSTRAP_SCOPE_MISMATCH',
    });
  });

  it('refuses when the authenticated user is not the intended user, keeping provenance distinct from identity (C14-02)', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ authenticatedUserId: 'user-9' }))).toEqual({
      decision: 'REFUSE',
      refusal: 'USER_NOT_INTENDED',
    });
  });

  it('refuses a challenge answered after it expired, and one bound to another request', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionAnsweredAt: iso(NOW, 60_001) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CHALLENGE_EXPIRED',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ challenge: challenge({ enrollment_request_id: 'enrol-other' }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CHALLENGE_MISBOUND',
    });
  });
});

describe('the possession statement (D23-03)', () => {
  it('binds the approved request fingerprint, so an attacker signature cannot answer an approval issued for a different request', () => {
    const intended = request();
    const base = {
      challenge_id: 'challenge-1',
      enrollment_request_id: 'enrol-1',
      enrollment_request_fingerprint: deviceEnrollmentRequestFingerprint(intended),
      nonce: NONCE,
      public_key_thumbprint: THUMBPRINT,
    };
    const attacker = { ...base, enrollment_request_fingerprint: deviceEnrollmentRequestFingerprint(request({ public_key_thumbprint: ATTACKER_THUMBPRINT })) };
    expect(devicePossessionStatementFingerprint(attacker)).not.toBe(devicePossessionStatementFingerprint(base));
  });

  it('is domain-tagged so a signature minted for another purpose cannot be replayed here', () => {
    expect(canonicalDevicePossessionStatement({
      challenge_id: 'c',
      enrollment_request_id: 'e',
      enrollment_request_fingerprint: THUMBPRINT,
      nonce: NONCE,
      public_key_thumbprint: THUMBPRINT,
    })).toContain('sentinel.device.possession-challenge.v1');
  });

  it('accepts only a canonical P-256 signature in the response (C14-01)', () => {
    const valid = {
      schema_version: 1,
      challenge_id: 'challenge-1',
      enrollment_request_id: 'enrol-1',
      signature_profile: 'P256_ECDSA_SHA256',
      signature: SIGNATURE,
      answered_at: NOW,
    };
    expect(() => DevicePossessionResponseSchema.parse(valid)).not.toThrow();
    expect(() => DevicePossessionResponseSchema.parse({ ...valid, signature: `${SIGNATURE}==` })).toThrow();
    expect(() => DevicePossessionResponseSchema.parse({ ...valid, signature_profile: 'Ed25519' })).toThrow();
  });
});

describe('attestation standing (C14-05)', () => {
  it('treats NEGATIVE, INVALID and REVOKED as device evidence that may lower trust immediately', () => {
    for (const outcome of ['NEGATIVE', 'INVALID', 'REVOKED'] as const) {
      expect(evaluateAttestationStanding({ outcome, lastVerifiedAt: NOW, now: NOW, hasPriorVerified: true }).standing).toBe('NEGATIVE');
    }
  });

  it('treats a verified result as CURRENT', () => {
    expect(evaluateAttestationStanding({ outcome: 'VERIFIED', lastVerifiedAt: NOW, now: NOW, hasPriorVerified: true }).standing).toBe('CURRENT');
  });

  it('retains last-known-good exactly at the grace bound and expires one millisecond past it (C14-05)', () => {
    const atBound = evaluateAttestationStanding({
      outcome: 'UNAVAILABLE',
      lastVerifiedAt: iso(NOW, -DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS),
      now: NOW,
      hasPriorVerified: true,
    });
    expect(atBound.standing).toBe('LAST_KNOWN_GOOD');
    expect(atBound.lastKnownGoodAgeMs).toBe(DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS);

    const pastBound = evaluateAttestationStanding({
      outcome: 'UNAVAILABLE',
      lastVerifiedAt: iso(NOW, -DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS - 1),
      now: NOW,
      hasPriorVerified: true,
    });
    expect(pastBound.standing).toBe('EXPIRED');
  });

  it('never lets a device with no prior verified attestation ride an outage (C14-05)', () => {
    expect(evaluateAttestationStanding({ outcome: 'UNAVAILABLE', lastVerifiedAt: null, now: NOW, hasPriorVerified: false }).standing).toBe(
      'INELIGIBLE',
    );
    expect(evaluateAttestationStanding({ outcome: 'UNAVAILABLE', lastVerifiedAt: NOW, now: NOW, hasPriorVerified: false }).standing).toBe(
      'INELIGIBLE',
    );
  });

  it('permits TRUSTED only for CURRENT and LAST_KNOWN_GOOD standings', () => {
    expect(attestationStandingPermitsTrusted('CURRENT')).toBe(true);
    expect(attestationStandingPermitsTrusted('LAST_KNOWN_GOOD')).toBe(true);
    expect(attestationStandingPermitsTrusted('EXPIRED')).toBe(false);
    expect(attestationStandingPermitsTrusted('NEGATIVE')).toBe(false);
    expect(attestationStandingPermitsTrusted('INELIGIBLE')).toBe(false);
  });

  it('separates an outage from a failure in the outcome vocabulary itself', () => {
    expect(DeviceAttestationOutcomeSchema.options).toEqual(['VERIFIED', 'NEGATIVE', 'INVALID', 'REVOKED', 'UNAVAILABLE']);
  });

  it('carries no attestation blob field anywhere in the evidence (D23-14)', () => {
    for (const field of ['blob', 'attestation_blob', 'token', 'jws', 'integrity_token']) {
      expect(() => request({ attestation: { outcome: 'VERIFIED', evaluated_at: NOW, attestation_reference: null, [field]: 'x' } })).toThrow();
    }
  });
});

describe('initial trust on enrollment (D23-03 / C14-05)', () => {
  it('grants TRUSTED only to a hardware-backed key with a currently verified attestation', () => {
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'CURRENT' })).toBe('TRUSTED');
  });

  it('refuses a first TRUSTED enrollment while attestation cannot be verified (C14-05)', () => {
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'INELIGIBLE' })).toBe('DEGRADED');
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'EXPIRED' })).toBe('DEGRADED');
  });

  it('enrols a software-key platform at a lower trust state rather than pretending otherwise (D23-03)', () => {
    expect(deviceKeyStoragePermitsTrusted('SOFTWARE')).toBe(false);
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'SOFTWARE', attestationStanding: 'CURRENT' })).toBe('DEGRADED');
  });

  it('quarantines an enrollment carrying negative attestation evidence', () => {
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'NEGATIVE' })).toBe('QUARANTINED');
  });
});

describe('device trust transitions (D23-05 / D23-07)', () => {
  it('pins the full trust matrix over the canonical six states', () => {
    expect(Object.keys(ALLOWED_DEVICE_TRUST_TRANSITIONS).sort()).toEqual([...DeviceTrustSchema.options].sort());
    expect(ALLOWED_DEVICE_TRUST_TRANSITIONS).toEqual({
      TRUSTED: ['DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
      DEGRADED: ['TRUSTED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
      SUSPICIOUS: ['TRUSTED', 'DEGRADED', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'],
      QUARANTINED: ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'COMPROMISED', 'OFFLINE'],
      COMPROMISED: [],
      OFFLINE: ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED'],
    });
  });

  it('makes COMPROMISED terminal: no evidence, decision or basis moves a device out of it (D23-05)', () => {
    expect(isTerminalDeviceTrust('COMPROMISED')).toBe(true);
    for (const to of DeviceTrustSchema.options) {
      expect(evaluateDeviceTrustTransition('COMPROMISED', to, RESTORATION_BASIS)).toEqual({
        allowed: false,
        refusal: 'SOURCE_STATE_TERMINAL',
      });
    }
  });

  it('reaches QUARANTINED fast from every non-terminal state, because quarantine acts before certainty', () => {
    for (const from of DeviceTrustSchema.options) {
      if (from === 'QUARANTINED' || from === 'COMPROMISED') continue;
      expect(canTransitionDeviceTrust(from, 'QUARANTINED', BLIND_BASIS)).toBe(true);
    }
  });

  it('never lets a device claim its way upward: a glowing self-report changes nothing (D23-05)', () => {
    const deviceClaim: DeviceTrustTransitionBasis = {
      ...BLIND_BASIS,
      deviceReportedHealth: { integrity: 'perfect', rooted: false, trust: 'TRUSTED', attestation: 'VERIFIED' },
    };
    expect(evaluateDeviceTrustTransition('QUARANTINED', 'TRUSTED', deviceClaim)).toEqual({
      allowed: false,
      refusal: 'RESTORATION_DECISION_REQUIRED',
    });
    // And the field is not consulted at all: identical inputs but for the claim
    // must produce identical answers.
    expect(evaluateDeviceTrustTransition('QUARANTINED', 'TRUSTED', deviceClaim)).toEqual(
      evaluateDeviceTrustTransition('QUARANTINED', 'TRUSTED', BLIND_BASIS),
    );
    expect(evaluateDeviceTrustTransition('SUSPICIOUS', 'TRUSTED', { ...RESTORATION_BASIS, deviceReportedHealth: 'ignored' })).toEqual(
      evaluateDeviceTrustTransition('SUSPICIOUS', 'TRUSTED', RESTORATION_BASIS),
    );
  });

  it('requires an explicit controlled-restoration decision to climb out of SUSPICIOUS or QUARANTINED', () => {
    for (const from of ['SUSPICIOUS', 'QUARANTINED'] as DeviceTrust[]) {
      expect(evaluateDeviceTrustTransition(from, 'DEGRADED', { ...RESTORATION_BASIS, controlledRestoration: null })).toEqual({
        allowed: false,
        refusal: 'RESTORATION_DECISION_REQUIRED',
      });
      expect(evaluateDeviceTrustTransition(from, 'TRUSTED', RESTORATION_BASIS)).toEqual({ allowed: true });
    }
  });

  it('refuses a restoration decided without the named capability', () => {
    const wrongCapability = {
      ...RESTORATION_BASIS,
      controlledRestoration: { decided_by_user_id: 'commander-1', capability: 'device.read' as never, decided_at: NOW },
    };
    expect(evaluateDeviceTrustTransition('QUARANTINED', 'TRUSTED', wrongCapability)).toEqual({
      allowed: false,
      refusal: 'RESTORATION_CAPABILITY_MISSING',
    });
  });

  it('refuses a blind OFFLINE to TRUSTED reconnect (D23-07)', () => {
    expect(evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', BLIND_BASIS)).toEqual({
      allowed: false,
      refusal: 'CREDENTIAL_CONTINUITY_LOST',
    });
    expect(
      evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', { ...RESTORATION_BASIS, previouslyEligible: false }),
    ).toEqual({ allowed: false, refusal: 'RECONNECT_BASIS_NOT_ESTABLISHED' });
    expect(evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', { ...RESTORATION_BASIS, attestationStanding: 'EXPIRED' })).toEqual({
      allowed: false,
      refusal: 'ATTESTATION_NOT_QUALIFYING',
    });
    expect(evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', { ...RESTORATION_BASIS, revoked: true })).toEqual({
      allowed: false,
      refusal: 'CREDENTIAL_REVOKED',
    });
  });

  it('admits an OFFLINE to TRUSTED reconnect only on intact continuity, no revocation, current-or-last-valid attestation and a prior basis', () => {
    expect(evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', RESTORATION_BASIS)).toEqual({ allowed: true });
    expect(
      evaluateDeviceTrustTransition('OFFLINE', 'TRUSTED', { ...RESTORATION_BASIS, attestationStanding: 'LAST_KNOWN_GOOD' }),
    ).toEqual({ allowed: true });
  });

  it('refuses TRUSTED for a software-backed key however good the rest of the basis is (D23-03)', () => {
    expect(evaluateDeviceTrustTransition('DEGRADED', 'TRUSTED', { ...RESTORATION_BASIS, keyStorage: 'SOFTWARE' })).toEqual({
      allowed: false,
      refusal: 'KEY_STORAGE_NOT_HARDWARE_BACKED',
    });
  });

  it('lets evidence lower trust without any human decision', () => {
    expect(evaluateDeviceTrustTransition('TRUSTED', 'DEGRADED', BLIND_BASIS)).toEqual({ allowed: true });
    expect(evaluateDeviceTrustTransition('TRUSTED', 'COMPROMISED', BLIND_BASIS)).toEqual({ allowed: true });
  });

  it('refuses a self-transition in every state', () => {
    for (const state of DeviceTrustSchema.options) {
      expect(canTransitionDeviceTrust(state, state, RESTORATION_BASIS)).toBe(false);
    }
  });
});

describe('rotation versus re-enrollment (D23-09)', () => {
  const previous: DeviceKeyChangeSubject = {
    device_id: 'device-1',
    sequence_namespace_id: deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' }),
    key_id: 'key-1',
    key_version: 3,
    public_key_thumbprint: THUMBPRINT,
  };

  function proposal(overrides: Partial<DeviceKeyChangeProposal> = {}): DeviceKeyChangeProposal {
    return {
      ...previous,
      key_id: 'key-2',
      key_version: 4,
      public_key_thumbprint: ATTACKER_THUMBPRINT,
      proved_possession_of_previous_key: true,
      continuity_loss_reason: null,
      ...overrides,
    };
  }

  it('treats an authenticated rotation as the same device: same device_id, same namespace, new version', () => {
    const result = classifyDeviceKeyChange(previous, proposal());
    expect(result).toEqual({
      classification: 'ROTATION',
      device_id: 'device-1',
      sequence_namespace_id: previous.sequence_namespace_id,
      from_key_version: 3,
      to_key_version: 4,
      invalidates_contexts_at_or_below_key_version: 3,
    });
  });

  it('mints a new identity with a fresh sequence namespace when the hardware credential loses continuity', () => {
    for (const reason of ['WIPE', 'RE_PROVISION', 'CONTINUITY_LOSS', 'COMPROMISE_RECOVERY', 'RE_ENROLLMENT'] as const) {
      expect(classifyDeviceKeyChange(previous, proposal({ continuity_loss_reason: reason }))).toEqual({
        classification: 'NEW_IDENTITY',
        reason,
        requires_new_device_id: true,
        requires_fresh_sequence_namespace: true,
      });
    }
  });

  it('mints a new identity when the device cannot prove possession of its current registered key', () => {
    expect(classifyDeviceKeyChange(previous, proposal({ proved_possession_of_previous_key: false }))).toEqual({
      classification: 'NEW_IDENTITY',
      reason: 'CONTINUITY_LOSS',
      requires_new_device_id: true,
      requires_fresh_sequence_namespace: true,
    });
  });

  it('mints a new identity when the device_id changes, whatever the key version says', () => {
    const result = classifyDeviceKeyChange(previous, proposal({ device_id: 'device-2', key_version: 1 }));
    expect(result.classification).toBe('NEW_IDENTITY');
  });

  it('LOCKED: refuses a namespace change dressed up as a rotation, because no caller-controlled sequence reset exists (C10-03)', () => {
    expect(classifyDeviceKeyChange(previous, proposal({ sequence_namespace_id: 'device-seq:something-else' }))).toEqual({
      classification: 'REFUSED',
      refusal: 'SEQUENCE_NAMESPACE_RESET_ATTEMPTED',
    });
  });

  it('refuses a rotation whose key version does not advance', () => {
    for (const key_version of [3, 2, 1]) {
      expect(classifyDeviceKeyChange(previous, proposal({ key_version }))).toEqual({
        classification: 'REFUSED',
        refusal: 'KEY_VERSION_NOT_ADVANCED',
      });
    }
  });
});

describe('the sequence namespace has no reset path (C10-03 / D23-09)', () => {
  it('derives from the organisation and device id alone, taking exactly one argument', () => {
    expect(deviceSequenceNamespaceId).toHaveLength(1);
    expect(deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' })).toBe(
      deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' }),
    );
  });

  it('ignores any epoch, generation or reset discriminator a caller tries to smuggle in', () => {
    const baseline = deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' });
    const smuggled = deviceSequenceNamespaceId({
      organisation_id: 'org-1',
      device_id: 'device-1',
      epoch: 2,
      generation: 7,
      reset: true,
      sequence_start: 0,
    } as unknown as { organisation_id: string; device_id: string });
    expect(smuggled).toBe(baseline);
  });

  it('yields a fresh namespace only for a new device_id, which only a new enrollment produces', () => {
    const original = deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' });
    expect(deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-2' })).not.toBe(original);
    expect(deviceSequenceNamespaceId({ organisation_id: 'org-2', device_id: 'device-1' })).not.toBe(original);
  });

  it('exports no reset, rewind or rollback helper anywhere in the module', () => {
    const suspicious = Object.keys(deviceIdentityModule).filter((name) => /reset|rewind|rollback|renumber/iu.test(name));
    expect(suspicious).toEqual([]);
  });
});

describe('device identity and custody (C14-02)', () => {
  it('separates enrollment provenance from the current actor', () => {
    const identity = DeviceIdentitySchema.parse({
      schema_version: 1,
      device_id: 'device-1',
      organisation_id: 'org-1',
      custody: 'CONTROLLED_SHARED',
      enrolled_by_user_id: 'commander-1',
      intended_user_id: 'user-1',
      sequence_namespace_id: deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' }),
      key: {
        key_id: 'key-1',
        key_version: 1,
        signature_profile: 'P256_ECDSA_SHA256',
        key_storage: 'HARDWARE_BACKED',
        public_key_thumbprint: THUMBPRINT,
      },
      trust: 'TRUSTED',
      enrolled_at: NOW,
      revoked_at: null,
    });
    expect(identity.intended_user_id).toBe('user-1');
    // There is no field naming the CURRENT authenticated actor: identity is not custody.
    expect(Object.keys(identity)).not.toContain('current_user_id');
    expect(Object.keys(identity)).not.toContain('actor_user_id');
  });

  it('offers exactly two custody modes and refuses an invented one', () => {
    expect(DEVICE_CUSTODY_MODES).toEqual(['PERSONAL', 'CONTROLLED_SHARED']);
    expect(DeviceCustodySchema.parse('CONTROLLED_SHARED')).toBe('CONTROLLED_SHARED');
    expect(() => DeviceCustodySchema.parse('ANY_USER')).toThrow();
  });
});

describe('canonical JSON refuses what it cannot represent (C11-03/C11-06/C11-07)', () => {
  it('refuses non-representable values rather than normalising them onto a shared digest', () => {
    expect(() => canonicalDeviceJson({ when: new Date() })).toThrow(TypeError);
    expect(() => canonicalDeviceJson({ n: Number.NaN })).toThrow(TypeError);
    expect(() => canonicalDeviceJson({ n: Number.POSITIVE_INFINITY })).toThrow(TypeError);
    // eslint-disable-next-line no-sparse-arrays
    expect(() => canonicalDeviceJson({ list: [1, , 3] })).toThrow(TypeError);
    expect(() => canonicalDeviceJson({ m: new Map([['a', 1]]) })).toThrow(TypeError);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalDeviceJson(cyclic)).toThrow(TypeError);
  });

  it('sorts object keys so a re-serialised request is the same request', () => {
    expect(canonicalDeviceJson({ b: 1, a: 2 })).toBe(canonicalDeviceJson({ a: 2, b: 1 }));
  });

  it('recognises a canonicalisable record', () => {
    expect(isCanonicalDeviceJsonRecord({ a: [1, 'x', null] })).toBe(true);
    expect(isCanonicalDeviceJsonRecord(new Date())).toBe(false);
    expect(isCanonicalDeviceJsonRecord([1, 2])).toBe(false);
  });
});
