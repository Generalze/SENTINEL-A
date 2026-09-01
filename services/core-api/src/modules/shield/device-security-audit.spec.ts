import { describe, expect, it } from 'vitest';
import { buildDeviceSecurityEventPayload, type DeviceSecurityEventInput } from './device-security-audit';
import { DEVICE_SECURITY_EVENT_TYPES } from './shield.constants';

/**
 * WP-24/D24-12 — the payload ALLOWLIST, tested as a pure unit.
 *
 * Two properties, and the second is the one that matters:
 *
 *  1. every one of the eighteen event types D24-12 enumerates has a builder;
 *  2. a builder writes ONLY the fields it names, so a value passed in a field
 *     the builder does not list cannot reach a payload.
 *
 * Property 2 is what distinguishes an allowlist from a filter. A filter is
 * tested by proving it removes today's forbidden fields; an allowlist is
 * tested by proving that an UNKNOWN field is absent without anyone having had
 * to think of it — which is the case that actually occurs, years later, when
 * somebody widens an input type.
 */

/** One well-formed input per event type, so the sweep below is exhaustive. */
const SAMPLES: Readonly<Record<(typeof DEVICE_SECURITY_EVENT_TYPES)[number], DeviceSecurityEventInput>> = {
  BOOTSTRAP_ISSUED: {
    type: 'BOOTSTRAP_ISSUED',
    grantId: 'grant-1',
    siteId: 'site-1',
    intendedUserId: 'user-1',
    issuedByUserId: 'commander-1',
    expiresAt: '2026-09-01T12:10:00.000Z',
  },
  BOOTSTRAP_REVOKED: { type: 'BOOTSTRAP_REVOKED', grantId: 'grant-1', siteId: 'site-1', revokedByUserId: 'commander-1' },
  BOOTSTRAP_CONSUMED: {
    type: 'BOOTSTRAP_CONSUMED',
    grantId: 'grant-1',
    siteId: 'site-1',
    intendedUserId: 'user-1',
    enrollmentRequestId: 'req-1',
    enrollmentRequestFingerprint: 'a'.repeat(64),
  },
  BOOTSTRAP_REPLAY_REFUSED: {
    type: 'BOOTSTRAP_REPLAY_REFUSED',
    grantId: 'grant-1',
    refusal: 'BOOTSTRAP_CONTEXT_MISMATCH',
    presentedOrganisationId: 'org-2',
    presentedSiteId: 'site-9',
    presentedIntendedUserId: 'user-9',
  },
  ENROLLMENT_REQUESTED: {
    type: 'ENROLLMENT_REQUESTED',
    enrollmentRequestId: 'req-1',
    requestFingerprint: 'b'.repeat(64),
    siteId: 'site-1',
    intendedUserId: 'user-1',
    custody: 'PERSONAL',
    keyStorage: 'HARDWARE_BACKED',
    publicKeyThumbprint: 'c'.repeat(64),
    signatureProfile: 'P256_ECDSA_SHA256',
    attestationOutcome: 'UNAVAILABLE',
  },
  ENROLLMENT_APPROVED: {
    type: 'ENROLLMENT_APPROVED',
    enrollmentRequestId: 'req-1',
    approvedRequestFingerprint: 'b'.repeat(64),
    approvedByUserId: 'commander-2',
    siteId: 'site-1',
    custody: 'PERSONAL',
  },
  ENROLLMENT_REFUSED: { type: 'ENROLLMENT_REFUSED', enrollmentRequestId: 'req-1', requestFingerprint: null, refusal: 'APPROVAL_MISSING' },
  POSSESSION_VERIFIED: {
    type: 'POSSESSION_VERIFIED',
    enrollmentRequestId: 'req-1',
    challengeId: 'chal-1',
    publicKeyThumbprint: 'c'.repeat(64),
    possessionStatementFingerprint: 'd'.repeat(64),
    signatureProfile: 'P256_ECDSA_SHA256',
    verified: true,
  },
  DEVICE_ENROLLED: {
    type: 'DEVICE_ENROLLED',
    deviceId: 'dev-1',
    enrollmentRequestId: 'req-1',
    requestFingerprint: 'b'.repeat(64),
    siteId: 'site-1',
    custody: 'PERSONAL',
    sequenceNamespaceId: 'device-seq:abc',
    keyId: 'key-1',
    keyVersion: 1,
    publicKeyThumbprint: 'c'.repeat(64),
    keyStorage: 'HARDWARE_BACKED',
    signatureProfile: 'P256_ECDSA_SHA256',
    initialTrust: 'DEGRADED',
  },
  TRUST_CHANGED: { type: 'TRUST_CHANGED', previousTrust: 'DEGRADED', newTrust: 'TRUSTED', reason: 'R', authorisedByUserId: 'commander-2' },
  DEVICE_QUARANTINED: { type: 'DEVICE_QUARANTINED', previousTrust: 'TRUSTED', reason: 'ATTESTATION_NEGATIVE' },
  DEVICE_LOST: { type: 'DEVICE_LOST', previousTrust: 'TRUSTED', newTrust: 'QUARANTINED', disposition: 'LOST' },
  DEVICE_STOLEN: {
    type: 'DEVICE_STOLEN',
    previousTrust: 'TRUSTED',
    newTrust: 'QUARANTINED',
    disposition: 'STOLEN',
    keyId: 'key-1',
    keyVersion: 1,
  },
  DEVICE_REVOKED: {
    type: 'DEVICE_REVOKED',
    disposition: 'STOLEN',
    previousTrust: 'TRUSTED',
    newTrust: 'QUARANTINED',
    revokedAt: '2026-09-01T12:00:00.000Z',
  },
  KEY_ROTATED: {
    type: 'KEY_ROTATED',
    rotationRequestId: 'rot-1',
    rotationRequestFingerprint: 'e'.repeat(64),
    fromKeyId: 'key-1',
    fromKeyVersion: 1,
    toKeyId: 'key-2',
    toKeyVersion: 2,
    newPublicKeyThumbprint: 'f'.repeat(64),
    newKeyStorage: 'HARDWARE_BACKED',
    signatureProfile: 'P256_ECDSA_SHA256',
  },
  KEY_REVOKED: { type: 'KEY_REVOKED', keyId: 'key-1', keyVersion: 1, disposition: 'STOLEN' },
  KEY_COMPROMISED: { type: 'KEY_COMPROMISED', keyId: 'key-1', keyVersion: 1, disposition: 'COMPROMISED_KEY' },
  REPLAY_CONFLICT: {
    type: 'REPLAY_CONFLICT',
    ceremony: 'BOOTSTRAP_GRANT',
    replayIdentityDigest: '0'.repeat(64),
    presentedStatementFingerprint: '1'.repeat(64),
    outcome: 'BOOTSTRAP_GRANT_REUSED',
  },
};

/** Anything that must never appear as a payload KEY, however it is spelled. */
const FORBIDDEN_KEY_PATTERN = /private|secret|token|nonce|signature(?!_profile)|password|credential|blob|bearer/iu;

describe('WP-24/D24-12 device security event payloads', () => {
  it('D24-12 names eighteen event types and every one of them has a builder', () => {
    // A guard that silently stops covering the vocabulary is worse than none,
    // because it reads as evidence. The count is asserted so a type added
    // without a sample fails here rather than passing an empty sweep.
    expect(DEVICE_SECURITY_EVENT_TYPES).toHaveLength(18);
    expect(Object.keys(SAMPLES).sort()).toEqual([...DEVICE_SECURITY_EVENT_TYPES].sort());
    for (const type of DEVICE_SECURITY_EVENT_TYPES) {
      const payload = buildDeviceSecurityEventPayload(SAMPLES[type]);
      expect(Object.keys(payload).length, type).toBeGreaterThan(0);
    }
  });

  it('no payload carries a key material, token, nonce, signature or credential field', () => {
    for (const type of DEVICE_SECURITY_EVENT_TYPES) {
      for (const key of Object.keys(buildDeviceSecurityEventPayload(SAMPLES[type]))) {
        expect(FORBIDDEN_KEY_PATTERN.test(key), `${type}.${key}`).toBe(false);
      }
    }
  });

  it('IT IS AN ALLOWLIST: an unlisted field passed in cannot reach the payload', () => {
    // The property a filter cannot have. Every sample is contaminated with
    // fields nobody wrote a builder line for — including the two D24-12 names
    // explicitly — and the output is required not to contain them.
    for (const type of DEVICE_SECURITY_EVENT_TYPES) {
      // The cast goes through `unknown` deliberately: the union REFUSES these
      // fields, which is the compile-time half of the same guarantee. This
      // test exists for the runtime half — an object that reached the builder
      // anyway, from a JSON boundary or a future widened input type.
      const contaminated = {
        ...SAMPLES[type],
        rawBootstrapToken: 'aGlnaGx5LXNlY3JldA',
        privateKeyPem: '-----BEGIN PRIVATE KEY-----',
        attestationBlob: 'vendor-blob',
        sessionCookie: 'sid=1',
        somethingNobodyHasThoughtOfYet: 'x',
      } as unknown as DeviceSecurityEventInput;
      const payload = buildDeviceSecurityEventPayload(contaminated);
      const serialised = JSON.stringify(payload);
      for (const leak of ['aGlnaGx5LXNlY3JldA', 'BEGIN PRIVATE KEY', 'vendor-blob', 'sid=1', 'somethingNobodyHasThoughtOfYet']) {
        expect(serialised.includes(leak), `${type} leaked ${leak}`).toBe(false);
      }
    }
  });

  it('payloads are flat scalars, so there is nowhere for a blob to hide', () => {
    for (const type of DEVICE_SECURITY_EVENT_TYPES) {
      for (const value of Object.values(buildDeviceSecurityEventPayload(SAMPLES[type]))) {
        expect(['string', 'number', 'boolean'].includes(typeof value) || value === null, `${type}`).toBe(true);
      }
    }
  });

  it('records `verified: false` rather than omitting a negative verdict (C15-03)', () => {
    const payload = buildDeviceSecurityEventPayload({ ...SAMPLES.POSSESSION_VERIFIED, verified: false } as DeviceSecurityEventInput);
    expect(payload.verified).toBe(false);
  });
});
