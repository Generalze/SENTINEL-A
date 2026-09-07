import { describe, expect, it } from 'vitest';
import { EdgeWitnessCorrelationService } from './edge-witness-correlation.service';

/**
 * M3B §8 — "NEVER CLOSEST MATCH" IS THE WHOLE TEST.
 *
 * The happy path is one test. The other five are the ones that matter: each
 * removes exactly one correlating fact and requires the answer to become
 * `null`. If any of them ever returns a row, an Edge witness can be attached
 * to an operation it never witnessed -- placing a shift's offline work inside
 * a lease window it never occupied, with central's own verification behind it.
 */

const MATCH = {
  organisationId: 'org-1',
  siteId: 'site-1',
  deviceId: 'device-1',
  offlineOperationId: '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
  operationFingerprint: 'a'.repeat(64),
};

const ROW = {
  id: 'obs-1',
  edgeId: 'edge-1',
  edgeKeyId: 'key-1',
  edgeKeyVersion: 1,
  verifiedEdgeTrustedTime: new Date('2026-09-07T00:00:30.000Z'),
  trustedTimeAnchorId: 'anchor-1',
  edgeMonotonicPosition: 1_030_000,
  observedAt: new Date('2026-09-07T00:01:00.000Z'),
};

/**
 * A fake that answers only when EVERY correlating fact in the query matches.
 *
 * Built this way on purpose: it models a real database, so a service that
 * dropped a field from its WHERE clause would start matching here exactly as
 * it would in Postgres. A stub that returned a fixed row would pass whatever
 * the service asked, and would prove nothing about the query.
 */
function serviceOver(stored: Record<string, unknown>): EdgeWitnessCorrelationService {
  const prisma = {
    edgeReceiptObservation: {
      findFirst: async (args: { where: Record<string, unknown> }) => {
        const matches = Object.entries(args.where).every(([key, value]) => stored[key] === value);
        return matches ? ROW : null;
      },
    },
  } as never;
  return new EdgeWitnessCorrelationService(prisma);
}

const STORED = {
  organisationId: MATCH.organisationId,
  siteId: MATCH.siteId,
  offlineOperationId: MATCH.offlineOperationId,
  witnessedOperationFingerprint: MATCH.operationFingerprint,
};

describe('resolving the Edge witness for a replayed operation', () => {
  it('returns the witness when every correlating fact agrees', async () => {
    const resolved = await serviceOver(STORED).resolve(MATCH);
    expect(resolved).not.toBeNull();
    expect(resolved?.edgeId).toBe('edge-1');
    expect(resolved?.verifiedEdgeTrustedTime?.toISOString()).toBe('2026-09-07T00:00:30.000Z');
  });

  it('returns null when no observation exists at all', async () => {
    const resolved = await serviceOver({}).resolve(MATCH);
    expect(resolved).toBeNull();
  });

  // Each of these is a near-match: the row is obviously "the right one" to a
  // human reader, and must still be refused.
  it('refuses an observation from another tenant', async () => {
    const resolved = await serviceOver({ ...STORED, organisationId: 'org-2' }).resolve(MATCH);
    expect(resolved).toBeNull();
  });

  it('refuses an observation from another site', async () => {
    const resolved = await serviceOver({ ...STORED, siteId: 'site-2' }).resolve(MATCH);
    expect(resolved).toBeNull();
  });

  it('refuses an observation of a different operation', async () => {
    const resolved = await serviceOver({
      ...STORED,
      offlineOperationId: '00000000-0000-4000-8000-000000000000',
    }).resolve(MATCH);
    expect(resolved).toBeNull();
  });

  // THE SUBTLEST ONE. Same operation id, different fingerprint: the device
  // re-signed a CHANGED request under an identity the Edge had already
  // witnessed. Inheriting that witness would let changed semantics hide behind
  // old provenance.
  it('refuses an observation whose witnessed fingerprint differs', async () => {
    const resolved = await serviceOver({ ...STORED, witnessedOperationFingerprint: 'b'.repeat(64) }).resolve(MATCH);
    expect(resolved).toBeNull();
  });

  it('carries a null trusted time through rather than inventing one', async () => {
    const prisma = {
      edgeReceiptObservation: {
        findFirst: async () => ({ ...ROW, verifiedEdgeTrustedTime: null, trustedTimeAnchorId: null }),
      },
    } as never;
    const resolved = await new EdgeWitnessCorrelationService(prisma).resolve(MATCH);
    // An observation central could not time is still a witness. What it must
    // not do is acquire a time on the way through.
    expect(resolved).not.toBeNull();
    expect(resolved?.verifiedEdgeTrustedTime).toBeNull();
    expect(resolved?.trustedTimeAnchorId).toBeNull();
  });
});
