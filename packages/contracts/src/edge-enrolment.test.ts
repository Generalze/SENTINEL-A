import { describe, expect, it } from 'vitest';
import {
  ALLOWED_EDGE_ENROLMENT_TRANSITIONS,
  EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS,
  EDGE_ENROLMENT_POSSESSION_DOMAIN,
  EDGE_ENROLMENT_REQUEST_DOMAIN,
  EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS,
  EdgeEnrolmentRequestIdentitySchema,
  canTransitionEdgeEnrolment,
  canonicalEdgeEnrolmentPossessionStatement,
  canonicalEdgeEnrolmentRequestStatement,
  classifyEdgeEnrolmentAuthority,
  edgeEnrolmentAuthorityReplayKey,
  edgeEnrolmentPossessionReplayKey,
  edgeEnrolmentPossessionStatementFingerprint,
  edgeEnrolmentRequestFingerprint,
  type EdgeEnrolmentPossessionStatementInput,
} from './edge-enrolment.js';
import { DEVICE_POSSESSION_CHALLENGE_DOMAIN, DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS, DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS } from './device-identity.js';
import { DEVICE_EDGE_RECEIPT_DOMAIN } from './device-offline.js';
import { EDGE_TRUSTED_TIME_ANCHOR_DOMAIN } from './edge-trusted-time.js';

/** WP-29B Crucible — the Edge enrolment ceremony's signed bytes and vocabulary. */

const NOW = '2026-09-06T12:00:00.000Z';
const MINUTE = 60_000;

function iso(deltaMs: number): string {
  return new Date(Date.parse(NOW) + deltaMs).toISOString();
}

function possession(overrides: Partial<EdgeEnrolmentPossessionStatementInput> = {}): EdgeEnrolmentPossessionStatementInput {
  return {
    challenge_id: 'challenge-1',
    enrolment_request_id: 'request-1',
    enrolment_request_fingerprint: 'a'.repeat(64),
    nonce: 'nonce-abcdefghijklmnop',
    public_key_thumbprint: 'b'.repeat(64),
    edge_id: 'edge-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    signature_profile: 'P256_ECDSA_SHA256',
    ...overrides,
  };
}

function requestIdentity(overrides: Record<string, unknown> = {}) {
  return EdgeEnrolmentRequestIdentitySchema.parse({
    schema_version: 1,
    organisation_id: 'org-1',
    site_id: 'site-1',
    authority_id: 'authority-1',
    edge_id: 'edge-1',
    public_key_thumbprint: 'b'.repeat(64),
    signature_profile: 'P256_ECDSA_SHA256',
    ...overrides,
  });
}

// ---------------------------------------------------------------------------

describe('the Edge ceremony has its own domains', () => {
  it('does not reuse the DEVICE possession domain', () => {
    // The defect this prevents: a signature captured from one ceremony replayed
    // into the other wherever the field names line up. C11-01 puts the tag
    // INSIDE the signed bytes for exactly this reason.
    expect(EDGE_ENROLMENT_POSSESSION_DOMAIN).not.toBe(DEVICE_POSSESSION_CHALLENGE_DOMAIN);
  });

  it('collides with no other signed-statement domain in the system', () => {
    const domains = [
      EDGE_ENROLMENT_REQUEST_DOMAIN,
      EDGE_ENROLMENT_POSSESSION_DOMAIN,
      DEVICE_POSSESSION_CHALLENGE_DOMAIN,
      DEVICE_EDGE_RECEIPT_DOMAIN,
      EDGE_TRUSTED_TIME_ANCHOR_DOMAIN,
    ];
    expect(new Set(domains).size).toBe(domains.length);
  });

  it('puts the domain inside the signed bytes, not beside them', () => {
    expect(JSON.parse(canonicalEdgeEnrolmentPossessionStatement(possession())).domain).toBe(EDGE_ENROLMENT_POSSESSION_DOMAIN);
    expect(JSON.parse(canonicalEdgeEnrolmentRequestStatement(requestIdentity())).domain).toBe(EDGE_ENROLMENT_REQUEST_DOMAIN);
  });
});

describe('the possession statement binds every substitution shut', () => {
  const mutations: ReadonlyArray<readonly [string, Partial<EdgeEnrolmentPossessionStatementInput>]> = [
    ['challenge_id', { challenge_id: 'challenge-OTHER' }],
    ['enrolment_request_id', { enrolment_request_id: 'request-OTHER' }],
    ['enrolment_request_fingerprint', { enrolment_request_fingerprint: 'c'.repeat(64) }],
    ['nonce', { nonce: 'nonce-OTHERabcdefghij' }],
    ['public_key_thumbprint', { public_key_thumbprint: 'd'.repeat(64) }],
    ['edge_id', { edge_id: 'edge-OTHER' }],
    ['organisation_id', { organisation_id: 'org-OTHER' }],
    ['site_id', { site_id: 'site-OTHER' }],
  ];

  it.each(mutations)('changing %s changes the bytes an Edge must sign', (_field, override) => {
    expect(canonicalEdgeEnrolmentPossessionStatement(possession(override))).not.toBe(
      canonicalEdgeEnrolmentPossessionStatement(possession()),
    );
  });

  it.each(mutations)('changing %s changes the statement fingerprint', (_field, override) => {
    expect(edgeEnrolmentPossessionStatementFingerprint(possession(override))).not.toBe(
      edgeEnrolmentPossessionStatementFingerprint(possession()),
    );
  });

  it('binds the SITE, so a proof from site X cannot activate a record for site Y', () => {
    // The property the coordinator named. It is a fact about the bytes rather
    // than about a comparison somebody remembered to write.
    const atX = canonicalEdgeEnrolmentPossessionStatement(possession({ site_id: 'site-X' }));
    const atY = canonicalEdgeEnrolmentPossessionStatement(possession({ site_id: 'site-Y' }));
    expect(atX).not.toBe(atY);
    expect(atX).toContain('"site_id":"site-X"');
  });

  it('binds the TENANT as well as the site', () => {
    expect(canonicalEdgeEnrolmentPossessionStatement(possession({ organisation_id: 'org-2' }))).toContain('"organisation_id":"org-2"');
  });

  it('is stable and order-independent', () => {
    expect(canonicalEdgeEnrolmentPossessionStatement(possession())).toBe(canonicalEdgeEnrolmentPossessionStatement(possession()));
    const shuffled = Object.fromEntries(Object.entries(possession()).reverse()) as EdgeEnrolmentPossessionStatementInput;
    expect(canonicalEdgeEnrolmentPossessionStatement(shuffled)).toBe(canonicalEdgeEnrolmentPossessionStatement(possession()));
  });
});

describe('the request identity carries no instants and nothing freely chosen', () => {
  it('accepts the server-resolved shape', () => {
    expect(requestIdentity().site_id).toBe('site-1');
  });

  it.each(['issued_at', 'created_at', 'requested_at', 'expires_at'])('refuses the instant %s', (field) => {
    // Two requests with the same fingerprint must really be the same request.
    // An instant would make every retry a different one.
    expect(EdgeEnrolmentRequestIdentitySchema.safeParse({ ...requestIdentity(), [field]: NOW }).success).toBe(false);
  });

  it.each(['public_key', 'private_key', 'authority_secret', 'trusted'])('refuses %s', (field) => {
    expect(EdgeEnrolmentRequestIdentitySchema.safeParse({ ...requestIdentity(), [field]: 'x' }).success).toBe(false);
  });

  it('refuses a signature profile that is not the approved one', () => {
    expect(EdgeEnrolmentRequestIdentitySchema.safeParse({ ...requestIdentity(), signature_profile: 'RSA_PKCS1' }).success).toBe(false);
  });

  it('changes its fingerprint when any bound field changes', () => {
    const baseline = edgeEnrolmentRequestFingerprint(requestIdentity());
    for (const override of [
      { organisation_id: 'org-2' },
      { site_id: 'site-2' },
      { authority_id: 'authority-2' },
      { edge_id: 'edge-2' },
      { public_key_thumbprint: 'e'.repeat(64) },
    ]) {
      expect(edgeEnrolmentRequestFingerprint(requestIdentity(override))).not.toBe(baseline);
    }
  });
});

describe('the two one-shot identities', () => {
  it('spends the AUTHORITY on (tenant, site, authority), not on the request id', () => {
    // The question is "has this authority been spent?", so a second request
    // under one authority must collide even though it carries a fresh id.
    const first = edgeEnrolmentAuthorityReplayKey({ organisation_id: 'org-1', site_id: 'site-1', authority_id: 'authority-1' });
    const second = edgeEnrolmentAuthorityReplayKey({ organisation_id: 'org-1', site_id: 'site-1', authority_id: 'authority-1' });
    expect(first).toBe(second);
    expect(first).not.toBe(edgeEnrolmentAuthorityReplayKey({ organisation_id: 'org-1', site_id: 'site-1', authority_id: 'authority-2' }));
  });

  it('separates authorities across tenants and sites', () => {
    const base = { organisation_id: 'org-1', site_id: 'site-1', authority_id: 'a' };
    expect(edgeEnrolmentAuthorityReplayKey(base)).not.toBe(edgeEnrolmentAuthorityReplayKey({ ...base, organisation_id: 'org-2' }));
    expect(edgeEnrolmentAuthorityReplayKey(base)).not.toBe(edgeEnrolmentAuthorityReplayKey({ ...base, site_id: 'site-2' }));
  });

  it('includes the NONCE in the challenge identity, so a re-issued challenge is a new identity', () => {
    // Re-issuing after a dropped connection must not collide with the first.
    const base = { organisation_id: 'org-1', site_id: 'site-1', enrolment_request_id: 'r', challenge_id: 'c', nonce: 'n1' };
    expect(edgeEnrolmentPossessionReplayKey(base)).not.toBe(edgeEnrolmentPossessionReplayKey({ ...base, nonce: 'n2' }));
    expect(edgeEnrolmentPossessionReplayKey(base)).toBe(edgeEnrolmentPossessionReplayKey({ ...base }));
  });

  it('keeps the two identities distinct from each other', () => {
    expect(edgeEnrolmentAuthorityReplayKey({ organisation_id: 'o', site_id: 's', authority_id: 'a' })).not.toBe(
      edgeEnrolmentPossessionReplayKey({ organisation_id: 'o', site_id: 's', enrolment_request_id: 'r', challenge_id: 'c', nonce: 'n' }),
    );
  });
});

describe('the authority standing', () => {
  const window = { issued_at: iso(0), expires_at: iso(10 * MINUTE), consumed_at: null, revoked_at: null };

  it('is USABLE inside its window', () => {
    expect(classifyEdgeEnrolmentAuthority(window, iso(MINUTE))).toBe('USABLE');
  });

  it('is EXPIRED at exactly expires_at, because the boundary is exclusive', () => {
    expect(classifyEdgeEnrolmentAuthority(window, iso(10 * MINUTE - 1))).toBe('USABLE');
    expect(classifyEdgeEnrolmentAuthority(window, iso(10 * MINUTE))).toBe('EXPIRED');
  });

  it('is NOT_YET_VALID before it was issued', () => {
    expect(classifyEdgeEnrolmentAuthority(window, iso(-1))).toBe('NOT_YET_VALID');
  });

  it('reads CONSUMED and REVOKED before expiry, so a burned authority reads as burned', () => {
    // The audit distinction matters most when the second use is an attacker's.
    expect(classifyEdgeEnrolmentAuthority({ ...window, consumed_at: iso(MINUTE) }, iso(999 * MINUTE))).toBe('CONSUMED');
    expect(classifyEdgeEnrolmentAuthority({ ...window, revoked_at: iso(MINUTE) }, iso(999 * MINUTE))).toBe('REVOKED');
  });

  it('answers TIME_NOT_AUTHORITATIVE on an unreadable instant rather than comparing NaN', () => {
    expect(classifyEdgeEnrolmentAuthority({ ...window, expires_at: 'nope' }, iso(0))).toBe('TIME_NOT_AUTHORITATIVE');
    expect(classifyEdgeEnrolmentAuthority(window, 'nope')).toBe('TIME_NOT_AUTHORITATIVE');
  });

  it('never answers USABLE for any failing case', () => {
    const failing = [
      classifyEdgeEnrolmentAuthority(window, iso(-1)),
      classifyEdgeEnrolmentAuthority(window, iso(10 * MINUTE)),
      classifyEdgeEnrolmentAuthority({ ...window, consumed_at: iso(0) }, iso(MINUTE)),
      classifyEdgeEnrolmentAuthority({ ...window, revoked_at: iso(0) }, iso(MINUTE)),
      classifyEdgeEnrolmentAuthority(window, 'nope'),
    ];
    for (const standing of failing) expect(standing).not.toBe('USABLE');
  });
});

describe('the lifecycle vocabulary', () => {
  it('starts PENDING and reaches ACTIVE only through a transition', () => {
    expect(canTransitionEdgeEnrolment('PENDING', 'ACTIVE')).toBe(true);
    expect(canTransitionEdgeEnrolment('PENDING', 'WITHDRAWN')).toBe(true);
  });

  it('makes WITHDRAWN terminal — re-admitting a box is a NEW identity', () => {
    // D23-09's rule: a re-provisioned credential is a new identity rather than
    // a rehabilitated one.
    expect(ALLOWED_EDGE_ENROLMENT_TRANSITIONS.WITHDRAWN).toEqual([]);
    expect(canTransitionEdgeEnrolment('WITHDRAWN', 'ACTIVE')).toBe(false);
    expect(canTransitionEdgeEnrolment('WITHDRAWN', 'PENDING')).toBe(false);
  });

  it('never returns an ACTIVE Edge to PENDING', () => {
    expect(canTransitionEdgeEnrolment('ACTIVE', 'PENDING')).toBe(false);
  });
});

describe('the ceilings are separate constants from the device ones', () => {
  it('matches the device windows numerically today', () => {
    expect(EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS).toBe(DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS);
    expect(EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS).toBe(DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS);
  });

  it('is nonetheless its own name, so the two policies cannot couple silently', () => {
    // D24-10A's rule. Changing what a phone gets must not silently change what
    // a site appliance gets, and the only way to keep that true is for the two
    // to be different constants even while they agree.
    expect(EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS).toBe(600_000);
    expect(EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS).toBe(120_000);
  });
});
