import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import * as deviceIdentityModule from './device-identity.js';
import { deriveP256PublicKeyThumbprint } from './device-signature.js';
import {
  ALLOWED_DEVICE_KEY_LIFECYCLE_TRANSITIONS,
  canTransitionDeviceKeyLifecycle,
  classifyDeviceNonceConsumption,
  DEVICE_KEY_LIFECYCLE_STATES,
  DEVICE_NONCE_CONSUMPTION_OUTCOMES,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  DeviceCustodyAssociationSchema,
  DevicePossessionVerificationResultSchema,
  DeviceRegistryKeyRecordSchema,
  deviceBootstrapGrantReplayKey,
  deviceCustodyAssociationBindsSite,
  deviceKeyStatePermitsHistoricalVerification,
  deviceKeyStatePermitsNewOperations,
  devicePossessionChallengeReplayKey,
  isExpiredAt,
  isTerminalDeviceKeyLifecycleState,
  parseAuthoritativeInstant,
  parseAuthoritativeInstants,
  refineDeviceInstantWindow,
  type DeviceNonceConsumption,
  type DevicePossessionVerificationResult,
} from './device-identity.js';
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
const SIGNATURE = Buffer.from(new Uint8Array(64).fill(7)).toString('base64url');
const NONCE = 'nonce-0123456789abcdef';

/** C15-02: fixtures use REAL canonical P-256 points, because the schema now decodes them. */
function canonicalPublicKey(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).subarray(-65).toString('base64url');
}

const PUBLIC_KEY = canonicalPublicKey();
const ATTACKER_PUBLIC_KEY = canonicalPublicKey();
const THUMBPRINT = deriveP256PublicKeyThumbprint(PUBLIC_KEY);
const ATTACKER_THUMBPRINT = deriveP256PublicKeyThumbprint(ATTACKER_PUBLIC_KEY);

function iso(base: string, deltaMs: number): string {
  return new Date(Date.parse(base) + deltaMs).toISOString();
}

/** C15-05: a store report shaped for the thing actually being presented. */
function consumption(replayKey: string, statementFingerprint: string, overrides: Partial<DeviceNonceConsumption> = {}): DeviceNonceConsumption {
  return {
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'FIRST_SEEN',
    replay_key: replayKey,
    statement_fingerprint: statementFingerprint,
    stored_outcome_ref: null,
    ...overrides,
  };
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
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    key_storage: 'HARDWARE_BACKED',
    public_key: PUBLIC_KEY,
    public_key_thumbprint: THUMBPRINT,
    attestation: { outcome: 'VERIFIED', evaluated_at: NOW, attestation_reference: 'att-1' },
    requested_at: iso(NOW, -30_000),
    ...overrides,
  });
}

/** The attacker's request: a different keypair, correctly self-consistent. */
function attackerRequest(overrides: Record<string, unknown> = {}): DeviceEnrollmentRequest {
  return request({ public_key: ATTACKER_PUBLIC_KEY, public_key_thumbprint: ATTACKER_THUMBPRINT, ...overrides });
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

/**
 * C15-03: the SERVER's verdict, correctly bound to one ceremony. Every field an
 * attack would have to forge is here, which is the point.
 */
function verificationFor(
  target: DeviceEnrollmentRequest,
  theChallenge: DevicePossessionChallenge,
  overrides: Record<string, unknown> = {},
): DevicePossessionVerificationResult {
  const fingerprint = deviceEnrollmentRequestFingerprint(target);
  return DevicePossessionVerificationResultSchema.parse({
    schema_version: 1,
    source: 'SENTINEL_SERVER_VERIFICATION',
    verified: true,
    challenge_id: theChallenge.challenge_id,
    enrollment_request_id: target.enrollment_request_id,
    enrollment_request_fingerprint: fingerprint,
    public_key_thumbprint: target.public_key_thumbprint,
    possession_statement_fingerprint: devicePossessionStatementFingerprint({
      challenge_id: theChallenge.challenge_id,
      enrollment_request_id: target.enrollment_request_id,
      enrollment_request_fingerprint: fingerprint,
      nonce: theChallenge.nonce,
      public_key_thumbprint: target.public_key_thumbprint,
      signature_profile: 'P256_ECDSA_SHA256',
    }),
    signature_profile: 'P256_ECDSA_SHA256',
    verified_at: iso(NOW, -5_000),
    ...overrides,
  });
}

function grantConsumptionFor(theGrant: DeviceEnrollmentBootstrapGrant, fingerprint: string): DeviceNonceConsumption {
  return consumption(
    deviceBootstrapGrantReplayKey({
      organisation_id: theGrant.organisation_id,
      site_id: theGrant.site_id,
      intended_user_id: theGrant.intended_user_id,
      grant_id: theGrant.grant_id,
    }),
    fingerprint,
  );
}

function challengeConsumptionFor(
  target: DeviceEnrollmentRequest,
  theChallenge: DevicePossessionChallenge,
  fingerprint: string,
): DeviceNonceConsumption {
  return consumption(
    devicePossessionChallengeReplayKey({
      organisation_id: target.organisation_id,
      site_id: target.site_id,
      intended_user_id: target.intended_user_id,
      enrollment_request_id: target.enrollment_request_id,
      challenge_id: theChallenge.challenge_id,
      nonce: theChallenge.nonce,
    }),
    fingerprint,
  );
}

function commitInput(overrides: Partial<DeviceEnrollmentCommitInput> = {}): DeviceEnrollmentCommitInput {
  const enrollmentRequest = overrides.request ?? request();
  const theGrant = overrides.grant !== undefined ? overrides.grant : grant();
  const theChallenge = overrides.challenge !== undefined ? overrides.challenge : challenge();
  const fingerprint = deviceEnrollmentRequestFingerprint(enrollmentRequest);
  const base: DeviceEnrollmentCommitInput = {
    request: enrollmentRequest,
    grant: theGrant,
    approval: approvalFor(enrollmentRequest),
    challenge: theChallenge,
    serverSelectedSignatureProfile: 'P256_ECDSA_SHA256',
    possessionVerification: theChallenge === null ? null : verificationFor(enrollmentRequest, theChallenge),
    grantConsumption: grantConsumptionFor(theGrant ?? grant(), fingerprint),
    challengeConsumption: challengeConsumptionFor(enrollmentRequest, theChallenge ?? challenge(), fingerprint),
    authenticatedUserId: 'user-1',
    now: NOW,
  };
  return { ...base, ...overrides };
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
      ['public key', attackerRequest()],
      ['attestation.outcome', request({ attestation: { outcome: 'UNAVAILABLE', evaluated_at: NOW, attestation_reference: 'att-1' } })],
      // C15-03: the WHOLE evidence record is bound, not just its outcome.
      ['attestation.evaluated_at', request({ attestation: { outcome: 'VERIFIED', evaluated_at: iso(NOW, -3_600_000), attestation_reference: 'att-1' } })],
      ['attestation.attestation_reference', request({ attestation: { outcome: 'VERIFIED', evaluated_at: NOW, attestation_reference: 'att-2' } })],
      ['attestation.attestation_reference null', request({ attestation: { outcome: 'VERIFIED', evaluated_at: NOW, attestation_reference: null } })],
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
    const attacker = attackerRequest();
    const approval = approvalFor(intended);
    expect(approvalMatchesEnrollmentRequest(approval, attacker)).toBe(false);
  });

  it('refuses an approval that names only the device class, site and custody but a different request', () => {
    const intended = request();
    const other = attackerRequest({ enrollment_request_id: 'enrol-2' });
    const classApproval = approvalFor(intended, { enrollment_request_id: other.enrollment_request_id });
    expect(approvalMatchesEnrollmentRequest(classApproval, other)).toBe(false);
  });

  it('LOCKED: a stolen bootstrap grant plus an attacker keypair cannot complete enrollment (C14-02)', () => {
    // The attacker holds a real, unused, in-scope grant and genuinely proves
    // possession — of THEIR OWN key. No human approved that request.
    const attackers = attackerRequest();
    const stolen = evaluateDeviceEnrollmentCommit(
      commitInput({
        request: attackers,
        approval: approvalFor(request()), // the approval a Command principal issued for the REAL device
      }),
    );
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
    const negative = verificationFor(request(), challenge(), { verified: false });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: negative }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_NOT_PROVEN',
    });
    // C15-03: a MISSING verdict is not a passing one, and is named separately
    // so an absent check can never read as a successful check.
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: null }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_VERIFICATION_MISSING',
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

  it('refuses a challenge verified after it expired, and one bound to another request', () => {
    // C15-03/C15-07: judged on the SERVER's verification instant, and the
    // expiry boundary is exclusive — exactly at expires_at is already expired.
    const expired = verificationFor(request(), challenge(), { verified_at: iso(NOW, 60_000) });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: expired }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CHALLENGE_EXPIRED',
    });
    const justInside = verificationFor(request(), challenge(), { verified_at: iso(NOW, 59_999) });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: justInside })).decision).toBe('COMMIT');

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
      signature_profile: 'P256_ECDSA_SHA256',
    } as const;
    const attacker = { ...base, enrollment_request_fingerprint: deviceEnrollmentRequestFingerprint(attackerRequest()) };
    expect(devicePossessionStatementFingerprint(attacker)).not.toBe(devicePossessionStatementFingerprint(base));
  });

  it('is domain-tagged so a signature minted for another purpose cannot be replayed here', () => {
    expect(canonicalDevicePossessionStatement({
      challenge_id: 'c',
      enrollment_request_id: 'e',
      enrollment_request_fingerprint: THUMBPRINT,
      nonce: NONCE,
      public_key_thumbprint: THUMBPRINT,
      signature_profile: 'P256_ECDSA_SHA256',
    })).toContain('sentinel.device.possession-challenge.v1');
  });

  it('accepts only a canonical P-256 signature in the response (C14-01)', () => {
    const valid = {
      schema_version: 1,
      challenge_id: 'challenge-1',
      enrollment_request_id: 'enrol-1',
      claimed_signature_profile: 'P256_ECDSA_SHA256',
      signature: SIGNATURE,
      answered_at: NOW,
    };
    expect(() => DevicePossessionResponseSchema.parse(valid)).not.toThrow();
    expect(() => DevicePossessionResponseSchema.parse({ ...valid, signature: `${SIGNATURE}==` })).toThrow();
    expect(() => DevicePossessionResponseSchema.parse({ ...valid, claimed_signature_profile: 'Ed25519' })).toThrow();
    // C15-01: the profile field is a CLAIM and is named as one. The old
    // authoritative-sounding name must no longer parse.
    expect(() => DevicePossessionResponseSchema.parse({ ...valid, signature_profile: 'P256_ECDSA_SHA256' })).toThrow();
  });

  it('C15-01: a high-S signature cannot exist inside a parsed possession response', () => {
    const highS = Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32, 0xff)]).toString('base64url');
    expect(() =>
      DevicePossessionResponseSchema.parse({
        schema_version: 1,
        challenge_id: 'challenge-1',
        enrollment_request_id: 'enrol-1',
        claimed_signature_profile: 'P256_ECDSA_SHA256',
        signature: highS,
        answered_at: NOW,
      }),
    ).toThrow();
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

// ---------------------------------------------------------------------------
// C15 corrections
// ---------------------------------------------------------------------------

describe('C15-02 the registry key record can actually verify', () => {
  function keyRecord(overrides: Record<string, unknown> = {}): unknown {
    return {
      schema_version: 1,
      organisation_id: 'org-1',
      device_id: 'device-1',
      key_id: 'key-1',
      key_version: 3,
      public_key: PUBLIC_KEY,
      public_key_thumbprint: THUMBPRINT,
      signature_profile: 'P256_ECDSA_SHA256',
      key_storage: 'HARDWARE_BACKED',
      status: 'CURRENT',
      registered_at: NOW,
      rotated_at: null,
      revoked_at: null,
      revocation_disposition: null,
      ...overrides,
    };
  }

  it('carries the actual public key, not merely a digest of one', () => {
    const record = DeviceRegistryKeyRecordSchema.parse(keyRecord());
    expect(record.public_key).toBe(PUBLIC_KEY);
    expect(record.signature_profile).toBe('P256_ECDSA_SHA256');
  });

  it('C15-02: refuses a thumbprint that was not DERIVED from the key it sits beside', () => {
    // The whole defect: a digest supplied alongside a key is a second claim,
    // not corroboration of the first.
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ public_key_thumbprint: ATTACKER_THUMBPRINT }))).toThrow();
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ public_key_thumbprint: 'a'.repeat(64) }))).toThrow();
    // A non-canonical key is a parse failure, not a thrown deriver.
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ public_key: 'not-a-point' }))).toThrow();
  });

  it('refuses a record whose status and timestamps tell different stories', () => {
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ status: 'ROTATED' }))).toThrow();
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ status: 'REVOKED' }))).toThrow();
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ rotated_at: NOW }))).toThrow();
    expect(() =>
      DeviceRegistryKeyRecordSchema.parse(keyRecord({ status: 'ROTATED', rotated_at: NOW, revocation_disposition: 'LOST' })),
    ).toThrow();
    expect(() => DeviceRegistryKeyRecordSchema.parse(keyRecord({ status: 'ROTATED', rotated_at: NOW }))).not.toThrow();
    expect(() =>
      DeviceRegistryKeyRecordSchema.parse(keyRecord({ status: 'COMPROMISED', revoked_at: NOW, revocation_disposition: 'COMPROMISED_KEY' })),
    ).not.toThrow();
  });

  it('C15-02: ROTATED and REVOKED/COMPROMISED are DIFFERENT semantic states', () => {
    expect([...DEVICE_KEY_LIFECYCLE_STATES]).toEqual(['CURRENT', 'ROTATED', 'REVOKED', 'COMPROMISED']);
    // Routine rotation retires a key's AUTHORITY but not its history: the
    // evidence it signed while current was legitimate when it was made.
    expect(deviceKeyStatePermitsNewOperations('ROTATED')).toBe(false);
    expect(deviceKeyStatePermitsHistoricalVerification('ROTATED')).toBe(true);
    // Revocation and compromise withdraw BOTH.
    for (const state of ['REVOKED', 'COMPROMISED'] as const) {
      expect(deviceKeyStatePermitsNewOperations(state), state).toBe(false);
      expect(deviceKeyStatePermitsHistoricalVerification(state), state).toBe(false);
    }
    expect(deviceKeyStatePermitsNewOperations('CURRENT')).toBe(true);
    expect(deviceKeyStatePermitsHistoricalVerification('CURRENT')).toBe(true);
  });

  it('COMPROMISED is terminal and no edge climbs back', () => {
    expect(ALLOWED_DEVICE_KEY_LIFECYCLE_TRANSITIONS).toEqual({
      CURRENT: ['ROTATED', 'REVOKED', 'COMPROMISED'],
      ROTATED: ['REVOKED', 'COMPROMISED'],
      REVOKED: ['COMPROMISED'],
      COMPROMISED: [],
    });
    expect(isTerminalDeviceKeyLifecycleState('COMPROMISED')).toBe(true);
    expect(canTransitionDeviceKeyLifecycle('CURRENT', 'ROTATED')).toBe(true);
    // Learning something bad about a historical key must be expressible.
    expect(canTransitionDeviceKeyLifecycle('ROTATED', 'COMPROMISED')).toBe(true);
    // But nothing is ever rehabilitated.
    expect(canTransitionDeviceKeyLifecycle('ROTATED', 'CURRENT')).toBe(false);
    expect(canTransitionDeviceKeyLifecycle('REVOKED', 'CURRENT')).toBe(false);
    expect(canTransitionDeviceKeyLifecycle('COMPROMISED', 'REVOKED')).toBe(false);
  });

  it('C15-02: the enrollment request carries the key, and refuses a mismatched thumbprint', () => {
    expect(request().public_key).toBe(PUBLIC_KEY);
    expect(() => request({ public_key_thumbprint: ATTACKER_THUMBPRINT })).toThrow();
    expect(() => request({ public_key: ATTACKER_PUBLIC_KEY })).toThrow();
    // Consistent pairs on either side are fine.
    expect(() => attackerRequest()).not.toThrow();
  });
});

describe('C15-03 the possession verdict is bound, and cannot be borrowed', () => {
  it('commits on a correctly bound verdict', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput()).decision).toBe('COMMIT');
  });

  it('LOCKED: a genuine verified:true produced for ANOTHER challenge cannot be borrowed', () => {
    // The attack the bare boolean allowed: run one honest ceremony, keep the
    // `true`, present it against a different challenge. Everything else is valid.
    const otherCeremony = verificationFor(request(), challenge({ challenge_id: 'challenge-9' }));
    expect(otherCeremony.verified).toBe(true);
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: otherCeremony }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_VERIFICATION_MISBOUND',
    });
  });

  it('LOCKED: a verdict produced for ANOTHER key cannot be borrowed', () => {
    const otherKey = verificationFor(attackerRequest(), challenge());
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: otherKey }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_VERIFICATION_MISBOUND',
    });
  });

  it('LOCKED: a verdict over DIFFERENT statement bytes is refused', () => {
    const wrongStatement = verificationFor(request(), challenge(), { possession_statement_fingerprint: 'c'.repeat(64) });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: wrongStatement }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_STATEMENT_MISMATCH',
    });
    // A verdict over the statement for a DIFFERENT nonce is the same defect
    // wearing this ceremony's challenge id.
    const otherNonce = challenge({ nonce: 'nonce-fedcba9876543210' });
    const borrowed = verificationFor(request(), otherNonce, { challenge_id: 'challenge-1' });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: borrowed }))).toEqual({
      decision: 'REFUSE',
      refusal: 'POSSESSION_STATEMENT_MISMATCH',
    });
  });

  it('C15-01: the request cannot claim a profile the server did not select', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ serverSelectedSignatureProfile: 'Ed25519' as never }))).toEqual({
      decision: 'REFUSE',
      refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH',
    });
  });

  it('C15-03: freshness comes from the SERVER instant, not a device-supplied answered_at', () => {
    // `answered_at` is not an input to the gate at all any more — the only way
    // to move freshness is to move the SERVER's verification instant.
    const beforeIssuance = verificationFor(request(), challenge(), { verified_at: iso(NOW, -30_000) });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: beforeIssuance }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CHALLENGE_NOT_YET_ISSUED',
    });
  });

  it('C15-07: an unreadable verification instant refuses fail-closed', () => {
    const broken = { ...verificationFor(request(), challenge()), verified_at: 'not-a-time' };
    expect(evaluateDeviceEnrollmentCommit(commitInput({ possessionVerification: broken }))).toEqual({
      decision: 'REFUSE',
      refusal: DEVICE_TIME_NOT_AUTHORITATIVE,
    });
  });

  it('C15-07: a request or approval claiming to come from the FUTURE refuses', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ request: request({ requested_at: iso(NOW, 1_000) }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'REQUEST_NOT_YET_MADE',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ approval: approvalFor(request(), { approved_at: iso(NOW, 1_000) }) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'APPROVAL_NOT_YET_MADE',
    });
  });

  it('C15-07: an unreadable server clock refuses rather than admitting', () => {
    expect(evaluateDeviceEnrollmentCommit(commitInput({ now: 'whenever' }))).toEqual({
      decision: 'REFUSE',
      refusal: DEVICE_TIME_NOT_AUTHORITATIVE,
    });
  });
});

describe('C15-05 one-shot consumption is a required fact', () => {
  it('classifies the three cases, and only converges on identical bytes', () => {
    expect([...DEVICE_NONCE_CONSUMPTION_OUTCOMES]).toEqual(['FIRST_SEEN', 'EXACT_DUPLICATE', 'REUSED_WITH_CHANGED_SEMANTICS']);
    expect(classifyDeviceNonceConsumption({ replay_key: 'k', statement_fingerprint: 'f', stored: null }).outcome).toBe('FIRST_SEEN');
    expect(
      classifyDeviceNonceConsumption({
        replay_key: 'k',
        statement_fingerprint: 'f',
        stored: { statement_fingerprint: 'f', stored_outcome_ref: 'outcome-1' },
      }),
    ).toMatchObject({ outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'outcome-1' });
    // Same slot, different meaning: a conflict with NOTHING to converge on.
    expect(
      classifyDeviceNonceConsumption({
        replay_key: 'k',
        statement_fingerprint: 'f2',
        stored: { statement_fingerprint: 'f', stored_outcome_ref: 'outcome-1' },
      }),
    ).toMatchObject({ outcome: 'REUSED_WITH_CHANGED_SEMANTICS', stored_outcome_ref: null });
  });

  it('an exact retry of one enrollment ceremony CONVERGES rather than enrolling twice', () => {
    const fingerprint = deviceEnrollmentRequestFingerprint(request());
    const duplicate = challengeConsumptionFor(request(), challenge(), fingerprint);
    expect(
      evaluateDeviceEnrollmentCommit(
        commitInput({ challengeConsumption: { ...duplicate, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'device-1' } }),
      ),
    ).toEqual({ decision: 'CONVERGE', enrollment_request_fingerprint: fingerprint, stored_outcome_ref: 'device-1' });
  });

  it('a reused challenge carrying DIFFERENT semantics conflicts', () => {
    const fingerprint = deviceEnrollmentRequestFingerprint(request());
    const reused = challengeConsumptionFor(request(), challenge(), fingerprint);
    expect(
      evaluateDeviceEnrollmentCommit(commitInput({ challengeConsumption: { ...reused, outcome: 'REUSED_WITH_CHANGED_SEMANTICS' } })),
    ).toEqual({ decision: 'REFUSE', refusal: 'CHALLENGE_REUSED' });
  });

  it('D23-04: a reused bootstrap grant conflicts rather than producing a second device', () => {
    const fingerprint = deviceEnrollmentRequestFingerprint(request());
    const reused = grantConsumptionFor(grant(), fingerprint);
    expect(
      evaluateDeviceEnrollmentCommit(commitInput({ grantConsumption: { ...reused, outcome: 'REUSED_WITH_CHANGED_SEMANTICS' } })),
    ).toEqual({ decision: 'REFUSE', refusal: 'BOOTSTRAP_GRANT_REUSED' });
  });

  it('LOCKED: a consumption fact for a DIFFERENT identity cannot stand in for this one', () => {
    const fingerprint = deviceEnrollmentRequestFingerprint(request());
    expect(evaluateDeviceEnrollmentCommit(commitInput({ grantConsumption: consumption('some-other-grant', fingerprint) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'BOOTSTRAP_CONSUMPTION_MISBOUND',
    });
    expect(evaluateDeviceEnrollmentCommit(commitInput({ challengeConsumption: consumption('some-other-challenge', fingerprint) }))).toEqual({
      decision: 'REFUSE',
      refusal: 'CHALLENGE_CONSUMPTION_MISBOUND',
    });
    // A fact about the right slot but the wrong bytes is equally not evidence.
    expect(
      evaluateDeviceEnrollmentCommit(commitInput({ challengeConsumption: challengeConsumptionFor(request(), challenge(), 'd'.repeat(64)) })),
    ).toEqual({ decision: 'REFUSE', refusal: 'CHALLENGE_CONSUMPTION_MISBOUND' });
  });

  it('the consumption fact cannot be defaulted away: it is a required input', () => {
    // Enforced by the type in the contract; asserted structurally here so a
    // future edit reintroducing an optional field fails a test rather than
    // silently restoring the "no fact means no replay" behaviour.
    const full = commitInput();
    const { grantConsumption, challengeConsumption, ...withoutFacts } = full;
    expect(grantConsumption).toBeDefined();
    expect(challengeConsumption).toBeDefined();
    expect(Object.keys(withoutFacts)).not.toContain('grantConsumption');
    expect(() => evaluateDeviceEnrollmentCommit(withoutFacts as unknown as DeviceEnrollmentCommitInput)).toThrow();
  });

  it('replay identities are canonical JSON, so no two distinct tuples collide (C11-01)', () => {
    const a = deviceBootstrapGrantReplayKey({ organisation_id: 'a:b', site_id: 'c', intended_user_id: 'u', grant_id: 'g' });
    const b = deviceBootstrapGrantReplayKey({ organisation_id: 'a', site_id: 'b:c', intended_user_id: 'u', grant_id: 'g' });
    expect(a).not.toBe(b);
    expect(a).toContain('sentinel.device.bootstrap-grant.replay-identity.v1');
    const c = devicePossessionChallengeReplayKey({
      organisation_id: 'org-1',
      site_id: 'site-1',
      intended_user_id: 'user-1',
      enrollment_request_id: 'enrol-1',
      challenge_id: 'challenge-1',
      nonce: NONCE,
    });
    expect(c).toContain('sentinel.device.possession-challenge.replay-identity.v1');
    expect(c).not.toBe(a);
  });
});

describe('C15-07 authoritative time fails closed', () => {
  it('refuses an unparseable instant instead of returning NaN for comparison', () => {
    expect(parseAuthoritativeInstant(NOW)).toBe(Date.parse(NOW));
    for (const bad of ['', 'not-a-date', 'Invalid Date', '2026-13-45T99:99:99Z']) {
      expect(parseAuthoritativeInstant(bad), bad).toBeNull();
    }
    // All-or-nothing: one bad member poisons the set rather than being skipped.
    expect(parseAuthoritativeInstants({ a: NOW, b: NOW })).toEqual({ a: Date.parse(NOW), b: Date.parse(NOW) });
    expect(parseAuthoritativeInstants({ a: NOW, b: 'nope' })).toBeNull();
  });

  it('expiry is an EXCLUSIVE boundary, asserted exactly at the instant', () => {
    expect(isExpiredAt(100, 101)).toBe(false);
    expect(isExpiredAt(100, 100)).toBe(true);
    expect(isExpiredAt(101, 100)).toBe(true);
    // The bootstrap grant reads the same rule.
    const g = grant({ issued_at: iso(NOW, -60_000), expires_at: NOW });
    expect(classifyDeviceBootstrapGrant(g, iso(NOW, -1))).toBe('USABLE');
    expect(classifyDeviceBootstrapGrant(g, NOW)).toBe('EXPIRED');
    expect(classifyDeviceBootstrapGrant(g, 'not-a-time')).toBe(DEVICE_TIME_NOT_AUTHORITATIVE);
  });

  it('C15-07: a lastVerifiedAt in the FUTURE is INCONSISTENT, never clamped to fresh', () => {
    // The old behaviour clamped a negative age to zero, which read a future
    // timestamp as "verified just now" — the freshest possible standing, from
    // exactly the record that deserves the least confidence.
    expect(
      evaluateAttestationStanding({ outcome: 'UNAVAILABLE', lastVerifiedAt: iso(NOW, 60_000), now: NOW, hasPriorVerified: true }),
    ).toEqual({ standing: 'INCONSISTENT', lastKnownGoodAgeMs: null });
    expect(attestationStandingPermitsTrusted('INCONSISTENT')).toBe(false);
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'INCONSISTENT' })).toBe('DEGRADED');
  });

  it('an unreadable attestation instant is INCONSISTENT rather than fresh', () => {
    expect(evaluateAttestationStanding({ outcome: 'UNAVAILABLE', lastVerifiedAt: 'whenever', now: NOW, hasPriorVerified: true })).toEqual({
      standing: 'INCONSISTENT',
      lastKnownGoodAgeMs: null,
    });
  });

  it('a window schema refuses an impossible ordering through the one shared refinement', () => {
    expect(() => grant({ issued_at: NOW, expires_at: NOW })).toThrow(/after issued_at/u);
    expect(() => grant({ issued_at: NOW, expires_at: iso(NOW, -1) })).toThrow(/after issued_at/u);
    expect(typeof refineDeviceInstantWindow).toBe('function');
  });
});

describe('C15-08 derived and server-owned invariants are contracts', () => {
  const HARDWARE_KEY = {
    key_id: 'key-1',
    key_version: 1,
    signature_profile: 'P256_ECDSA_SHA256',
    key_storage: 'HARDWARE_BACKED',
    public_key_thumbprint: THUMBPRINT,
  };
  const SOFTWARE_KEY = { ...HARDWARE_KEY, key_storage: 'SOFTWARE' };

  function identity(overrides: Record<string, unknown> = {}): unknown {
    return {
      schema_version: 1,
      device_id: 'device-1',
      organisation_id: 'org-1',
      custody: 'PERSONAL',
      enrolled_by_user_id: 'commander-1',
      intended_user_id: 'user-1',
      sequence_namespace_id: deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-1' }),
      key: HARDWARE_KEY,
      trust: 'TRUSTED',
      enrolled_at: NOW,
      revoked_at: null,
      ...overrides,
    };
  }

  it('LOCKED: an arbitrary sequence_namespace_id fails to PARSE (D23-09)', () => {
    expect(() => DeviceIdentitySchema.parse(identity())).not.toThrow();
    // A namespace reset arriving through the front door rather than through
    // classifyDeviceKeyChange is still a namespace reset.
    expect(() => DeviceIdentitySchema.parse(identity({ sequence_namespace_id: 'device-seq:whatever-i-like' }))).toThrow(/derived/u);
    // Including one legitimately derived for a DIFFERENT device.
    expect(() =>
      DeviceIdentitySchema.parse(
        identity({ sequence_namespace_id: deviceSequenceNamespaceId({ organisation_id: 'org-1', device_id: 'device-2' }) }),
      ),
    ).toThrow(/derived/u);
  });

  it('LOCKED: a TRUSTED identity on a software-backed key fails to PARSE (D23-03)', () => {
    expect(() => DeviceIdentitySchema.parse(identity({ key: SOFTWARE_KEY }))).toThrow(/hardware-backed/u);
    // The same software key at a lower trust state is legitimate (D23-03).
    expect(() => DeviceIdentitySchema.parse(identity({ trust: 'DEGRADED', key: SOFTWARE_KEY }))).not.toThrow();
  });

  it('C15-08: a NEW identity cannot inherit the old identity last-known-good standing', () => {
    // D23-09 says re-enrollment produces a NEW identity, and LAST_KNOWN_GOOD is
    // a statement of CONTINUITY. A new identity has no "before" to ride, so the
    // fastest route to a Whisper-capable credential must not be "wipe and
    // re-enrol while the attestation provider happens to be down".
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'LAST_KNOWN_GOOD' })).toBe('DEGRADED');
    expect(initialDeviceTrustOnEnrollment({ keyStorage: 'HARDWARE_BACKED', attestationStanding: 'CURRENT' })).toBe('TRUSTED');
    // Continuity of an ALREADY-ESTABLISHED identity still accepts it, because
    // there the device being vouched for is the one that earned the result.
    expect(evaluateDeviceTrustTransition('DEGRADED', 'TRUSTED', { ...RESTORATION_BASIS, attestationStanding: 'LAST_KNOWN_GOOD' })).toEqual({
      allowed: true,
    });
  });

  it('locks the custody association shape WP-24 will persist', () => {
    const personal = DeviceCustodyAssociationSchema.parse({
      schema_version: 1,
      organisation_id: 'org-1',
      device_id: 'device-1',
      custody: 'PERSONAL',
      assigned_user_id: 'user-1',
      custody_regime_id: null,
      associated_site_ids: ['site-1', 'site-2'],
      associated_at: NOW,
      released_at: null,
    });
    expect(deviceCustodyAssociationBindsSite(personal, 'site-1')).toBe(true);
    expect(deviceCustodyAssociationBindsSite(personal, 'site-9')).toBe(false);
    // A released association binds nothing.
    expect(deviceCustodyAssociationBindsSite({ ...personal, released_at: NOW }, 'site-1')).toBe(false);
  });

  it('C14-02: the two custody modes have mutually exclusive shapes, enforced not described', () => {
    const base = {
      schema_version: 1,
      organisation_id: 'org-1',
      device_id: 'device-1',
      associated_site_ids: ['site-1'],
      associated_at: NOW,
      released_at: null,
    };
    // A shared device with a permanent assignee is custody fused into identity.
    expect(() =>
      DeviceCustodyAssociationSchema.parse({ ...base, custody: 'CONTROLLED_SHARED', assigned_user_id: 'user-1', custody_regime_id: 'regime-1' }),
    ).toThrow();
    // A personal device under a shared regime is an accountability gap.
    expect(() =>
      DeviceCustodyAssociationSchema.parse({ ...base, custody: 'PERSONAL', assigned_user_id: 'user-1', custody_regime_id: 'regime-1' }),
    ).toThrow();
    expect(() => DeviceCustodyAssociationSchema.parse({ ...base, custody: 'PERSONAL', assigned_user_id: null, custody_regime_id: null })).toThrow();
    expect(() =>
      DeviceCustodyAssociationSchema.parse({ ...base, custody: 'CONTROLLED_SHARED', assigned_user_id: null, custody_regime_id: null }),
    ).toThrow();
    expect(() =>
      DeviceCustodyAssociationSchema.parse({
        ...base,
        custody: 'CONTROLLED_SHARED',
        assigned_user_id: null,
        custody_regime_id: 'regime-1',
        associated_site_ids: ['site-1', 'site-1'],
      }),
    ).toThrow(/unique/u);
  });
});
