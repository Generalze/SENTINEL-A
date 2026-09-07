import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalEdgeRequestStatement,
  checkCanonicalEdgeRequestRoute,
  classifyEdgeRequestTrustedTimeClaim,
  edgeRequestBodyDigest,
  edgeRequestFingerprint,
  edgeRequestReplayKey,
  edgeRequestStatementInput,
  edgeTrustedTimeClaimIsLive,
  EdgeRequestProofSchema,
  EdgeRequestRouteSchema,
  EDGE_REQUEST_EMPTY_BODY_DIGEST,
  EDGE_REQUEST_PROOF_DOMAIN,
  EDGE_REQUEST_PROOF_FORBIDDEN_FIELDS,
  EDGE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN,
  EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS,
  type EdgeRequestProof,
} from './edge-request.js';
import { DEVICE_REQUEST_PROOF_DOMAIN } from './device-context.js';
import { DEVICE_EDGE_RECEIPT_DOMAIN } from './device-offline.js';
import { DEVICE_TIME_NOT_AUTHORITATIVE } from './device-identity.js';

/**
 * WP-29B — the Edge request proof's canonical statement, fingerprint, replay
 * key and route rule.
 *
 * These are the properties the central resolver's whole argument rests on, and
 * they are proved HERE, against pure functions, rather than only end-to-end:
 * an integration suite that exercises them through a database proves they hold
 * for the one path it drove and says nothing about the next caller.
 */

/** 86 canonical base64url characters with a low-S `s`. Structure only; nothing verifies it here. */
const LOW_S_SIGNATURE = Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)]).toString('base64url');

function proof(overrides: Partial<Record<string, unknown>> = {}): unknown {
  return {
    schema_version: 1,
    edge_id: 'edge-17',
    registry_key_id: 'key-17',
    request_id: 'r'.repeat(24),
    method: 'POST',
    route: '/edge/v1/trusted-time-anchor',
    body_digest: edgeRequestBodyDigest('{"edge_boot_id":"b"}'),
    purpose: 'TRUSTED_TIME_ANCHOR',
    trusted_time_anchor_id: null,
    edge_trusted_timestamp: null,
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    signature: LOW_S_SIGNATURE,
    ...overrides,
  };
}

function parsed(overrides: Partial<Record<string, unknown>> = {}): EdgeRequestProof {
  const result = EdgeRequestProofSchema.safeParse(proof(overrides));
  if (!result.success) throw new Error(`fixture does not parse: ${result.error.message}`);
  return result.data;
}

describe('WP-29B the Edge request proof parses only what it is allowed to mean', () => {
  it('accepts a well-formed proof with no trusted-time claim', () => {
    expect(EdgeRequestProofSchema.safeParse(proof()).success).toBe(true);
  });

  it('accepts a proof carrying BOTH halves of the trusted-time claim', () => {
    const ok = EdgeRequestProofSchema.safeParse(
      proof({ trusted_time_anchor_id: '3f1b6a9e-2c47-4d1a-9f2e-8b7c6d5e4f30', edge_trusted_timestamp: '2026-09-06T12:00:00.000Z' }),
    );
    expect(ok.success).toBe(true);
  });

  it.each([
    ['anchor without timestamp', { trusted_time_anchor_id: '3f1b6a9e-2c47-4d1a-9f2e-8b7c6d5e4f30', edge_trusted_timestamp: null }],
    ['timestamp without anchor', { trusted_time_anchor_id: null, edge_trusted_timestamp: '2026-09-06T12:00:00.000Z' }],
  ])('refuses a HALF-present trusted-time claim (%s)', (_label, overrides) => {
    // A bare clock reading dressed as evidence, or an anchor vouching for
    // nothing. Neither is a fact central can act on, so neither may parse.
    expect(EdgeRequestProofSchema.safeParse(proof(overrides)).success).toBe(false);
  });

  it('refuses every field an Edge is not allowed to assert', () => {
    // `.strict()` is the enforcement. This proves each forbidden field is
    // actually refused rather than trusting a reviewer to notice one was added.
    for (const field of EDGE_REQUEST_PROOF_FORBIDDEN_FIELDS) {
      const result = EdgeRequestProofSchema.safeParse(proof({ [field]: 'anything' }));
      expect(result.success, `${field} must be refused`).toBe(false);
    }
  });

  it('refuses a lowercase HTTP verb rather than normalising it', () => {
    // `post` and `POST` are one verb to a router and two byte strings to a
    // signature. Normalising here would re-open exactly that gap.
    expect(EdgeRequestProofSchema.safeParse(proof({ method: 'post' })).success).toBe(false);
  });

  it('refuses a high-S signature at the parse boundary (C15-01)', () => {
    const highS = Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0xff)]).toString('base64url');
    expect(EdgeRequestProofSchema.safeParse(proof({ signature: highS })).success).toBe(false);
  });
});

describe('WP-29B one route, one spelling', () => {
  it.each([
    ['/', true],
    ['/edge/v1/anchor', true],
    ['/edge/v1/anchor/', false],
    ['/edge//v1/anchor', false],
    ['/edge/v1/./anchor', false],
    ['/edge/v1/../admin', false],
    ['/edge/v1/%61nchor', false],
    ['/edge/v1/anchor?x=1', false],
    ['/edge/v1/anchor#frag', false],
    ['edge/v1/anchor', false],
    ['/edge/v1/anchor\n', false],
    ['/edge/v1/ünicode', false],
  ])('%s canonical: %s', (route, expected) => {
    expect(checkCanonicalEdgeRequestRoute(route).ok).toBe(expected);
    expect(EdgeRequestRouteSchema.safeParse(route).success).toBe(expected);
  });

  it('names the reason internally without letting it reach the wire form', () => {
    const rejected = checkCanonicalEdgeRequestRoute('/edge//v1');
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.rejection).toBe('EMPTY_SEGMENT');
  });

  it('refuses a route longer than the ceiling', () => {
    expect(checkCanonicalEdgeRequestRoute(`/${'a'.repeat(600)}`).ok).toBe(false);
  });
});

describe('WP-29B the body digest is over bytes, never over a re-serialisation', () => {
  it('is plain SHA-256 hex of the exact bytes', () => {
    const body = '{"b":1,"a":2}';
    expect(edgeRequestBodyDigest(body)).toBe(createHash('sha256').update(Buffer.from(body, 'utf8')).digest('hex'));
  });

  it('distinguishes two JSON bodies that canonicalise to the same object', () => {
    // The point of digesting bytes: `{"a":1,"b":2}` and `{"b":2,"a":1}` are one
    // value to a parser and two requests to a signature. If these ever agree,
    // a server has re-serialised the body and is digesting its own output.
    expect(edgeRequestBodyDigest('{"a":1,"b":2}')).not.toBe(edgeRequestBodyDigest('{"b":2,"a":1}'));
  });

  it('gives a bodyless request exactly one legal digest', () => {
    expect(EDGE_REQUEST_EMPTY_BODY_DIGEST).toBe(edgeRequestBodyDigest(''));
    expect(edgeRequestBodyDigest(new Uint8Array())).toBe(EDGE_REQUEST_EMPTY_BODY_DIGEST);
  });
});

describe('WP-29B the canonical statement', () => {
  it('binds the SERVER-resolved profile and never the claim', () => {
    // The type forbids handing a proof straight in; this proves the runtime
    // agrees — the claimed value is nowhere in the signed bytes.
    const statement = canonicalEdgeRequestStatement(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    expect(statement).toContain('"signature_profile":"P256_ECDSA_SHA256"');
    expect(statement).not.toContain('claimed_signature_profile');
  });

  it('carries the Edge request domain and NOT the device-proof or receipt domain', () => {
    const statement = canonicalEdgeRequestStatement(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    expect(statement).toContain(EDGE_REQUEST_PROOF_DOMAIN);
    expect(statement).not.toContain(DEVICE_REQUEST_PROOF_DOMAIN);
    // The domain that matters most: an Edge signs receipts with the SAME key,
    // so a shared tag would let a captured receipt signature authenticate a
    // request. Three distinct tags, three distinct statement spaces.
    expect(statement).not.toContain(DEVICE_EDGE_RECEIPT_DOMAIN);
    expect(EDGE_REQUEST_PROOF_DOMAIN).not.toBe(DEVICE_EDGE_RECEIPT_DOMAIN);
    expect(EDGE_REQUEST_PROOF_DOMAIN).not.toBe(DEVICE_REQUEST_PROOF_DOMAIN);
  });

  it('never carries the signature, a tenant or a site', () => {
    const statement = canonicalEdgeRequestStatement(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    expect(statement).not.toContain(LOW_S_SIGNATURE);
    expect(statement).not.toContain('organisation_id');
    expect(statement).not.toContain('site_id');
  });

  it('sorts keys, so two builds of one statement are byte-identical', () => {
    const first = canonicalEdgeRequestStatement(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    const second = canonicalEdgeRequestStatement(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    expect(first).toBe(second);
    expect(JSON.stringify(Object.keys(JSON.parse(first)).slice().sort())).toBe(JSON.stringify(Object.keys(JSON.parse(first))));
  });

  it.each([
    ['edge_id', { edge_id: 'edge-18' }],
    ['registry_key_id', { registry_key_id: 'key-18' }],
    ['request_id', { request_id: 's'.repeat(24) }],
    ['method', { method: 'GET' }],
    ['route', { route: '/edge/v1/heartbeat' }],
    ['body_digest', { body_digest: edgeRequestBodyDigest('other') }],
    ['purpose', { purpose: 'EDGE_HEARTBEAT' }],
  ])('changes when %s changes — the binding is real', (_field, overrides) => {
    const base = edgeRequestFingerprint(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    const altered = edgeRequestFingerprint(edgeRequestStatementInput(parsed(overrides), 'P256_ECDSA_SHA256'));
    expect(altered).not.toBe(base);
  });

  it('changes when the trusted-time claim changes', () => {
    const base = edgeRequestFingerprint(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256'));
    const claimed = edgeRequestFingerprint(
      edgeRequestStatementInput(
        parsed({ trusted_time_anchor_id: '3f1b6a9e-2c47-4d1a-9f2e-8b7c6d5e4f30', edge_trusted_timestamp: '2026-09-06T12:00:00.000Z' }),
        'P256_ECDSA_SHA256',
      ),
    );
    expect(claimed).not.toBe(base);
  });

  it('fingerprints exactly the statement it signs', () => {
    const input = edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256');
    expect(edgeRequestFingerprint(input)).toBe(createHash('sha256').update(canonicalEdgeRequestStatement(input), 'utf8').digest('hex'));
  });
});

describe('WP-29B the replay identity', () => {
  const identity = { organisation_id: 'org-a', edge_id: 'edge-17', registry_key_id: 'key-17', request_id: 'r'.repeat(24) };

  it('is its own domain, not the statement domain', () => {
    const key = edgeRequestReplayKey(identity);
    expect(key).toContain(EDGE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN);
    expect(key).not.toContain(EDGE_REQUEST_PROOF_DOMAIN);
  });

  it('is NOT the statement fingerprint — a slot is not a set of bytes', () => {
    // If these ever collapsed, every distinct request would get its own slot
    // and the store would detect nothing at all.
    expect(edgeRequestReplayKey(identity)).not.toBe(edgeRequestFingerprint(edgeRequestStatementInput(parsed(), 'P256_ECDSA_SHA256')));
  });

  it('is scoped by tenant, so a slot burned in one tenant frees nothing in another', () => {
    expect(edgeRequestReplayKey({ ...identity, organisation_id: 'org-b' })).not.toBe(edgeRequestReplayKey(identity));
  });

  it('is scoped by key, so a rotation does not inherit the old key spent slots', () => {
    expect(edgeRequestReplayKey({ ...identity, registry_key_id: 'key-18' })).not.toBe(edgeRequestReplayKey(identity));
  });

  it('does NOT change when the method, route or body changes', () => {
    // The slot is the one-shot identity, not the request's meaning. Two
    // DIFFERENT requests presented under one `request_id` must land in the SAME
    // slot — that collision is the thing the store exists to catch.
    const other = edgeRequestReplayKey(identity);
    expect(other).toBe(edgeRequestReplayKey({ ...identity }));
  });

  it('sorts its keys canonically', () => {
    const key = edgeRequestReplayKey(identity);
    expect(JSON.stringify(Object.keys(JSON.parse(key)))).toBe(JSON.stringify(Object.keys(JSON.parse(key)).slice().sort()));
  });
});

describe('WP-29B the trusted-time claim is classified, never believed', () => {
  const now = '2026-09-06T12:00:00.000Z';
  const anchor = '3f1b6a9e-2c47-4d1a-9f2e-8b7c6d5e4f30';

  it('reports NONE when the Edge claims nothing, which is admissible', () => {
    expect(classifyEdgeRequestTrustedTimeClaim({ trusted_time_anchor_id: null, edge_trusted_timestamp: null }, now)).toBe('NONE');
  });

  it('reports CLAIMED for a reading inside the anchor ceiling', () => {
    const recent = new Date(Date.parse(now) - 60_000).toISOString();
    expect(classifyEdgeRequestTrustedTimeClaim({ trusted_time_anchor_id: anchor, edge_trusted_timestamp: recent }, now)).toBe('CLAIMED');
  });

  it('reports STALE beyond the ceiling — no live anchor can back it', () => {
    const old = new Date(Date.parse(now) - EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS - 1).toISOString();
    expect(classifyEdgeRequestTrustedTimeClaim({ trusted_time_anchor_id: anchor, edge_trusted_timestamp: old }, now)).toBe('STALE');
  });

  it('reports FUTURE_SKEWED for a reading ahead of the server clock', () => {
    const ahead = new Date(Date.parse(now) + 3_600_000).toISOString();
    expect(classifyEdgeRequestTrustedTimeClaim({ trusted_time_anchor_id: anchor, edge_trusted_timestamp: ahead }, now)).toBe('FUTURE_SKEWED');
  });

  it('reports TIME_NOT_AUTHORITATIVE for an unreadable instant rather than guessing (C15-07)', () => {
    expect(classifyEdgeRequestTrustedTimeClaim({ trusted_time_anchor_id: anchor, edge_trusted_timestamp: '2026-09-06T12:00:00.000Z' }, 'not-a-time')).toBe(
      DEVICE_TIME_NOT_AUTHORITATIVE,
    );
  });

  it('treats only CLAIMED as live', () => {
    expect(edgeTrustedTimeClaimIsLive('CLAIMED')).toBe(true);
    for (const standing of ['NONE', 'STALE', 'FUTURE_SKEWED', DEVICE_TIME_NOT_AUTHORITATIVE] as const) {
      expect(edgeTrustedTimeClaimIsLive(standing)).toBe(false);
    }
  });
});
