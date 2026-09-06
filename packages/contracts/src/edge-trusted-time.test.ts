import { describe, expect, it } from 'vitest';
import {
  EDGE_TRUSTED_TIME_ANCHOR_DOMAIN,
  EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS,
  EdgeTrustedTimeAnchorClaimSchema,
  EdgeTrustedTimeAnchorStatementSchema,
  SignedEdgeTrustedTimeAnchorSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  edgeTrustedTimeAnchorFingerprint,
  type EdgeTrustedTimeAnchorStatement,
} from './edge-trusted-time.js';
import { DEVICE_EDGE_RECEIPT_DOMAIN, DEVICE_OFFLINE_OPERATION_DOMAIN } from './device-offline.js';
import { DEVICE_REQUEST_PROOF_DOMAIN } from './device-context.js';
import { DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS } from './device-identity.js';
import { P256_CURVE_ORDER, P256_HALF_CURVE_ORDER, encodeCanonicalP256Signature } from './device-signature.js';

/** WP-29B Crucible — the centrally signed trusted-time anchor statement. */

const ISSUED = '2026-08-29T12:00:00.000Z';
const HOUR = 3_600_000;
const ANCHOR_ID = '9c4e1f80-1a2b-4c3d-8e5f-6a7b8c9d0e1f';

/** A well-formed low-S signature. Its VALUE is irrelevant here — only its shape. */
const SIGNATURE = encodeCanonicalP256Signature(12345n, 67890n);

function iso(deltaMs: number): string {
  return new Date(Date.parse(ISSUED) + deltaMs).toISOString();
}

function statement(overrides: Record<string, unknown> = {}): EdgeTrustedTimeAnchorStatement {
  return EdgeTrustedTimeAnchorStatementSchema.parse({
    schema_version: 1,
    anchor_id: ANCHOR_ID,
    edge_id: 'edge-17',
    organisation_id: 'org-1',
    site_id: 'site-1',
    edge_boot_id: 'boot-4f2a',
    edge_monotonic_at_anchor: 1_000_000,
    server_issued_at: ISSUED,
    server_valid_until: iso(6 * HOUR),
    signer_key_id: 'central-tta-2026-01',
    ...overrides,
  });
}

// ---------------------------------------------------------------------------

describe('the domain separator is its own', () => {
  it('is the ruling-named domain', () => {
    expect(EDGE_TRUSTED_TIME_ANCHOR_DOMAIN).toBe('sentinel.edge.trusted-time-anchor.v1');
  });

  it('collides with no other signed statement domain', () => {
    // Purpose separation, enforced by bytes: even holding this signing key, an
    // attacker cannot produce anything that verifies as a device operation, an
    // Edge receipt or a request proof, because none of those begin this way.
    const others = [DEVICE_OFFLINE_OPERATION_DOMAIN, DEVICE_EDGE_RECEIPT_DOMAIN, DEVICE_REQUEST_PROOF_DOMAIN];
    expect(others).not.toContain(EDGE_TRUSTED_TIME_ANCHOR_DOMAIN);
    expect(new Set([...others, EDGE_TRUSTED_TIME_ANCHOR_DOMAIN]).size).toBe(others.length + 1);
  });

  it('is inside the signed bytes, not merely beside them', () => {
    expect(JSON.parse(canonicalEdgeTrustedTimeAnchorStatement(statement())).domain).toBe(EDGE_TRUSTED_TIME_ANCHOR_DOMAIN);
  });
});

describe('exactly two facts originate at Edge', () => {
  it('accepts the claim shape', () => {
    const claim = EdgeTrustedTimeAnchorClaimSchema.parse({ edge_boot_id: 'boot-4f2a', edge_monotonic_at_anchor: 5 });
    expect(claim).toEqual({ edge_boot_id: 'boot-4f2a', edge_monotonic_at_anchor: 5 });
  });

  it.each(['edge_id', 'organisation_id', 'site_id', 'server_issued_at', 'server_valid_until', 'signer_key_id'])(
    'refuses a claim naming %s, which central resolves',
    (field) => {
      // An Edge that could name its own tenant could ask for an anchor bound to
      // someone else's, and an Edge that could name a time would be supplying
      // the very thing the anchor exists to give it.
      expect(EdgeTrustedTimeAnchorClaimSchema.safeParse({ edge_boot_id: 'b', edge_monotonic_at_anchor: 1, [field]: 'x' }).success).toBe(
        false,
      );
    },
  );

  it('neither Edge-supplied field is a time', () => {
    const claim = EdgeTrustedTimeAnchorClaimSchema.parse({ edge_boot_id: 'boot-4f2a', edge_monotonic_at_anchor: 5 });
    expect(typeof claim.edge_boot_id).toBe('string');
    expect(Date.parse(claim.edge_boot_id)).toBeNaN();
    expect(typeof claim.edge_monotonic_at_anchor).toBe('number');
  });

  it('refuses a monotonic reading beyond exact integer arithmetic', () => {
    // Past MAX_SAFE_INTEGER the derivation silently stops being exact.
    expect(
      EdgeTrustedTimeAnchorClaimSchema.safeParse({ edge_boot_id: 'b', edge_monotonic_at_anchor: Number.MAX_SAFE_INTEGER + 2 }).success,
    ).toBe(false);
    expect(EdgeTrustedTimeAnchorClaimSchema.safeParse({ edge_boot_id: 'b', edge_monotonic_at_anchor: -1 }).success).toBe(false);
    expect(EdgeTrustedTimeAnchorClaimSchema.safeParse({ edge_boot_id: 'b', edge_monotonic_at_anchor: 1.5 }).success).toBe(false);
  });
});

describe('the statement binds every field, and the signature covers all of them', () => {
  it('carries all ten fields plus the domain in the signed bytes', () => {
    const signed = JSON.parse(canonicalEdgeTrustedTimeAnchorStatement(statement())) as Record<string, unknown>;
    expect(Object.keys(signed).sort()).toEqual(
      [
        'anchor_id',
        'domain',
        'edge_boot_id',
        'edge_id',
        'edge_monotonic_at_anchor',
        'organisation_id',
        'schema_version',
        'server_issued_at',
        'server_valid_until',
        'signer_key_id',
        'site_id',
      ].sort(),
    );
  });

  /**
   * THE PROPERTY THE WHOLE MODULE EXISTS FOR: there is no part of the anchor an
   * attacker can alter while leaving the signature valid. Every field is
   * mutated in turn and the signed bytes must change.
   */
  const mutations: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['anchor_id', { anchor_id: '00000000-0000-4000-8000-000000000000' }],
    ['edge_id', { edge_id: 'edge-OTHER' }],
    ['organisation_id', { organisation_id: 'org-OTHER' }],
    ['site_id', { site_id: 'site-OTHER' }],
    ['edge_boot_id', { edge_boot_id: 'boot-OTHER' }],
    ['edge_monotonic_at_anchor', { edge_monotonic_at_anchor: 999 }],
    ['server_issued_at', { server_issued_at: iso(-HOUR), server_valid_until: iso(HOUR) }],
    ['server_valid_until', { server_valid_until: iso(5 * HOUR) }],
    ['signer_key_id', { signer_key_id: 'central-tta-OTHER' }],
  ];

  it.each(mutations)('changing %s changes the signed bytes', (_field, override) => {
    const baseline = canonicalEdgeTrustedTimeAnchorStatement(statement());
    expect(canonicalEdgeTrustedTimeAnchorStatement(statement(override))).not.toBe(baseline);
  });

  it.each(mutations)('changing %s changes the fingerprint', (_field, override) => {
    const baseline = edgeTrustedTimeAnchorFingerprint(statement());
    expect(edgeTrustedTimeAnchorFingerprint(statement(override))).not.toBe(baseline);
  });

  it('is stable: the same statement always produces the same bytes', () => {
    expect(canonicalEdgeTrustedTimeAnchorStatement(statement())).toBe(canonicalEdgeTrustedTimeAnchorStatement(statement()));
  });

  it('does not depend on key insertion order', () => {
    // Canonical JSON sorts recursively, which is why re-serialisation cannot
    // break the signature relationship.
    const shuffled = Object.fromEntries(Object.entries(statement()).reverse());
    const reordered = EdgeTrustedTimeAnchorStatementSchema.parse(JSON.parse(JSON.stringify(shuffled)));
    expect(canonicalEdgeTrustedTimeAnchorStatement(reordered)).toBe(canonicalEdgeTrustedTimeAnchorStatement(statement()));
  });

  it('signs the monotonic reading, so it cannot be lowered locally', () => {
    // The load-bearing case. Signing only wall time and keeping the subtrahend
    // in an unsigned local field would let an attacker move every derived
    // instant forward by however much they chose, with the signature intact.
    const baseline = canonicalEdgeTrustedTimeAnchorStatement(statement());
    expect(canonicalEdgeTrustedTimeAnchorStatement(statement({ edge_monotonic_at_anchor: 1 }))).not.toBe(baseline);
    expect(baseline).toContain('"edge_monotonic_at_anchor"');
  });
});

describe('the lifetime ceiling cannot be signed into existence', () => {
  it('accepts exactly the frozen six-hour ceiling', () => {
    expect(statement({ server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS) }).server_valid_until).toBe(
      iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS),
    );
  });

  it('refuses one millisecond over the ceiling', () => {
    const result = EdgeTrustedTimeAnchorStatementSchema.safeParse({
      ...statement(),
      server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + 1),
    });
    expect(result.success).toBe(false);
  });

  it('reports an over-long lifetime on the field that is actually wrong', () => {
    const result = EdgeTrustedTimeAnchorStatementSchema.safeParse({
      ...statement(),
      server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + 1),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((issue) => issue.path.join('.') === 'server_valid_until')).toBe(true);
    }
  });

  it('accepts a SHORTER lifetime, because central may choose one', () => {
    expect(statement({ server_valid_until: iso(15 * 60_000) }).server_valid_until).toBe(iso(15 * 60_000));
  });

  it('refuses a window that ends before it starts', () => {
    expect(
      EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...statement(), server_valid_until: iso(-HOUR) }).success,
    ).toBe(false);
  });

  it('refuses a zero-length window', () => {
    expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...statement(), server_valid_until: ISSUED }).success).toBe(false);
  });

  it('refuses an unreadable instant rather than comparing NaN', () => {
    for (const bad of [{ server_issued_at: 'not-a-time' }, { server_valid_until: 'not-a-time' }]) {
      expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...statement(), ...bad }).success).toBe(false);
    }
  });
});

describe('a signed instruction from central cannot disable a rule', () => {
  it.each(EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS)('refuses a statement carrying %s', (field) => {
    // A compromised signing key must be able to lie about the TIME and nothing
    // else. If it could also switch off Edge's own defences, its compromise
    // would be unbounded rather than bounded by the six-hour ceiling.
    expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...statement(), [field]: true }).success).toBe(false);
  });

  it('has no signature-profile field, because the version fixes the algorithm', () => {
    expect(Object.keys(statement())).not.toContain('signature_profile');
    expect(Object.keys(statement())).not.toContain('claimed_signature_profile');
    expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...statement(), signature_profile: 'P256_ECDSA_SHA256' }).success).toBe(
      false,
    );
  });

  it('has no holdover field, because the window is two instants central owns', () => {
    expect(Object.keys(statement())).not.toContain('holdover_ms');
  });
});

describe('what Edge persists is the signed original, never a derivative', () => {
  it('accepts a statement plus its signature', () => {
    const anchor = SignedEdgeTrustedTimeAnchorSchema.parse({ statement: statement(), signature: SIGNATURE });
    expect(anchor.statement.anchor_id).toBe(ANCHOR_ID);
  });

  it.each(['trusted_now', 'derived_at', 'cached_offset', 'verified', 'verified_at', 'expires_at_ms'])(
    'refuses the persisted derivative %s',
    (field) => {
      // Anything Edge computed is a value produced BY verification that would
      // then be trusted WITHOUT verification after a restart.
      expect(SignedEdgeTrustedTimeAnchorSchema.safeParse({ statement: statement(), signature: SIGNATURE, [field]: 1 }).success).toBe(
        false,
      );
    },
  );

  it('refuses a high-S signature before it ever reaches a verifier', () => {
    // C14-01: a high-S value is REFUSED, never silently normalised, so the two
    // wire forms of one mathematical signature cannot both be admitted.
    const highS = Buffer.concat([
      Buffer.from(encodeCanonicalP256Signature(12345n, 1n), 'base64url').subarray(0, 32),
      bigIntTo32Bytes(P256_CURVE_ORDER - 1n),
    ]).toString('base64url');
    expect(SignedEdgeTrustedTimeAnchorSchema.safeParse({ statement: statement(), signature: highS }).success).toBe(false);
  });

  it('refuses a malformed, padded or wrong-length signature', () => {
    for (const bad of ['', 'not-base64url!!', 'AAAA', `${SIGNATURE}=`, SIGNATURE.slice(0, 40)]) {
      expect(SignedEdgeTrustedTimeAnchorSchema.safeParse({ statement: statement(), signature: bad }).success).toBe(false);
    }
  });

  it('refuses a signed anchor whose statement would not parse on its own', () => {
    expect(
      SignedEdgeTrustedTimeAnchorSchema.safeParse({
        statement: { ...statement(), server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + 1) },
        signature: SIGNATURE,
      }).success,
    ).toBe(false);
  });

  it('survives a JSON round trip, which is how it reaches disk', () => {
    const anchor = SignedEdgeTrustedTimeAnchorSchema.parse({ statement: statement(), signature: SIGNATURE });
    const round = SignedEdgeTrustedTimeAnchorSchema.parse(JSON.parse(JSON.stringify(anchor)));
    expect(canonicalEdgeTrustedTimeAnchorStatement(round.statement)).toBe(canonicalEdgeTrustedTimeAnchorStatement(anchor.statement));
    expect(round.signature).toBe(anchor.signature);
  });

  it('keeps the low-S boundary exactly where the contract puts it', () => {
    expect(SignedEdgeTrustedTimeAnchorSchema.safeParse({
      statement: statement(),
      signature: encodeCanonicalP256Signature(1n, P256_HALF_CURVE_ORDER),
    }).success).toBe(true);
  });
});

function bigIntTo32Bytes(value: bigint): Buffer {
  const hex = value.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}
