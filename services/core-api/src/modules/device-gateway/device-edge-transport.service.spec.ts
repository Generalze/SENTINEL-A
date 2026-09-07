import type { AuthenticatedDeviceContext } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { DeviceEdgeTransportService } from './device-edge-transport.service';

/**
 * The descriptor is the ONLY thing standing between a Field handset and
 * whatever answers first on a hostile site LAN. Every case below is a way that
 * protection is lost: a stale pin outliving its authority, a pin for an Edge
 * the estate has disowned, or -- worst -- two candidate identities silently
 * resolved by picking one.
 */

const NOW = new Date('2026-09-07T00:00:00.000Z');
const SITE = 'site-1';
const ORG = 'org-1';

function context(overrides: Partial<AuthenticatedDeviceContext> = {}): AuthenticatedDeviceContext {
  return {
    schema_version: 1,
    context_id: 'ctx-1',
    organisation_id: ORG,
    device_id: 'dev-1',
    actor_user_id: 'user-1',
    key_id: 'key-1',
    key_version: 1,
    device_trust: 'TRUSTED',
    authorised_site_ids: [SITE],
    issued_at: '2026-09-07T00:00:00.000Z',
    expires_at: '2026-09-07T04:00:00.000Z',
    ...overrides,
  } as AuthenticatedDeviceContext;
}

const identity = {
  id: 'ti-1',
  edgeId: 'edge-1',
  siteId: SITE,
  transportKeyVersion: 1,
  httpsEndpoint: 'https://edge-1.site-1.sentinel.internal:8443',
  tlsSpkiSha256: 'a'.repeat(64),
  activatedAt: new Date('2026-09-06T00:00:00.000Z'),
  rotatedAt: null as Date | null,
  revokedAt: null as Date | null,
};

const trustedEdge = { edgeTrust: 'TRUSTED', enrolmentState: 'ACTIVE', withdrawnAt: null as Date | null };

function serviceWith(
  identities: ReadonlyArray<Record<string, unknown>>,
  edge: Record<string, unknown> | null = trustedEdge,
): DeviceEdgeTransportService {
  const prisma = {
    edgeTransportIdentity: { findMany: async () => identities },
    edgeNode: { findFirst: async () => edge },
  } as never;
  return new DeviceEdgeTransportService(prisma);
}

describe('issuing an Edge transport descriptor', () => {
  it('issues a pinned descriptor for the site the context authorises', async () => {
    const result = await serviceWith([identity]).issue(context(), null, NOW);

    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    expect(result.descriptor.tls_spki_sha256).toBe('a'.repeat(64));
    expect(result.descriptor.https_endpoint).toBe(identity.httpsEndpoint);
    expect(result.descriptor.site_id).toBe(SITE);
  });

  // THE DESCRIPTOR MUST NOT OUTLIVE THE AUTHORITY THAT JUSTIFIED IT. A device
  // holding a descriptor valid past its context could keep opening trusted Edge
  // connections on authority that has already lapsed -- the stale-authority
  // failure arriving through the transport layer instead of the operation layer.
  it('clamps the window to the authenticated context when that expires sooner', async () => {
    const result = await serviceWith([identity]).issue(context(), null, NOW);
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    expect(result.descriptor.expires_at).toBe('2026-09-07T04:00:00.000Z');
  });

  it('clamps to the offline ceiling when the context outlives it', async () => {
    const long = context({ expires_at: '2026-09-08T00:00:00.000Z' });
    const result = await serviceWith([identity]).issue(long, null, NOW);
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    // Six hours, not the context's twenty-four.
    expect(result.descriptor.expires_at).toBe('2026-09-07T06:00:00.000Z');
  });

  it('refuses when the context has already expired', async () => {
    const expired = context({ expires_at: '2026-09-06T00:00:00.000Z' });
    const result = await serviceWith([identity]).issue(expired, null, NOW);
    expect(result).toMatchObject({ refusal: 'DESCRIPTOR_WINDOW_UNAVAILABLE' });
  });

  // THE MOST IMPORTANT TEST IN THIS FILE. Picking one would mean the fleet's
  // trust anchor is decided by row ordering, and half a site could end up
  // pinned to a different key than the other half with nothing recording it.
  it('REFUSES rather than choosing when a site presents two current identities', async () => {
    const second = { ...identity, id: 'ti-2', tlsSpkiSha256: 'b'.repeat(64) };
    const result = await serviceWith([identity, second]).issue(context(), null, NOW);
    expect(result).toMatchObject({ refusal: 'AMBIGUOUS_TRANSPORT_IDENTITY' });
  });

  it('refuses when the site has no current transport identity', async () => {
    const result = await serviceWith([]).issue(context(), null, NOW);
    expect(result).toMatchObject({ refusal: 'NO_TRUSTED_EDGE_FOR_SITE' });
  });

  // `status` and the lifecycle instants do not move atomically, so they are
  // asked independently -- C15-R4-final, applied to transport. A row still
  // marked CURRENT whose revocation instant is set is revoked.
  it.each([
    ['revoked', { revokedAt: new Date('2026-09-06T12:00:00.000Z') }],
    ['rotated', { rotatedAt: new Date('2026-09-06T12:00:00.000Z') }],
    ['never activated', { activatedAt: null }],
  ])('refuses a %s identity even while it is still marked CURRENT', async (_label, override) => {
    const result = await serviceWith([{ ...identity, ...override }]).issue(context(), null, NOW);
    expect(result).toMatchObject({ refusal: 'TRANSPORT_IDENTITY_NOT_ACTIVE' });
  });

  // A transport identity outliving its Edge's trust would keep a pin alive for
  // a box the estate has already disowned.
  it.each([
    ['withdrawn', { ...trustedEdge, withdrawnAt: new Date('2026-09-06T00:00:00.000Z') }],
    ['not active', { ...trustedEdge, enrolmentState: 'PENDING' }],
    ['suspended', { ...trustedEdge, edgeTrust: 'SUSPENDED' }],
    ['revoked', { ...trustedEdge, edgeTrust: 'REVOKED' }],
  ])('refuses when the Edge itself is %s', async (_label, edge) => {
    const result = await serviceWith([identity], edge).issue(context(), null, NOW);
    expect(result).toMatchObject({ refusal: 'EDGE_NOT_AVAILABLE' });
  });

  it('refuses when the Edge row has gone entirely', async () => {
    const result = await serviceWith([identity], null).issue(context(), null, NOW);
    expect(result).toMatchObject({ refusal: 'EDGE_NOT_AVAILABLE' });
  });
});

describe('which site a descriptor is about', () => {
  it('uses the only authorised site when the caller names none', async () => {
    const result = await serviceWith([identity]).issue(context(), null, NOW);
    expect(result.outcome).toBe('ISSUED');
  });

  it('accepts a named site the context authorises', async () => {
    const multi = context({ authorised_site_ids: ['site-0', SITE] });
    const result = await serviceWith([identity]).issue(multi, SITE, NOW);
    expect(result.outcome).toBe('ISSUED');
  });

  // Not an oracle: membership is already known to whoever holds the context.
  // What matters is that the next two cases are INDISTINGUISHABLE.
  it('refuses a site the context does not authorise', async () => {
    const result = await serviceWith([identity]).issue(context(), 'site-99', NOW);
    expect(result).toMatchObject({ refusal: 'SITE_NOT_RESOLVED' });
  });

  it('gives the same answer for a site that does not exist at all', async () => {
    const result = await serviceWith([]).issue(context(), 'no-such-site', NOW);
    expect(result).toMatchObject({ refusal: 'SITE_NOT_RESOLVED' });
  });

  it('refuses to guess when several sites are authorised and none is named', async () => {
    const multi = context({ authorised_site_ids: ['site-0', SITE] });
    const result = await serviceWith([identity]).issue(multi, null, NOW);
    expect(result).toMatchObject({ refusal: 'SITE_NOT_RESOLVED' });
  });
});

describe('a bad stored row cannot be distributed with central authority behind it', () => {
  // The descriptor schema's rules must hold against a BAD ROW as well as a bad
  // request. A tampered or misconfigured endpoint column would otherwise reach
  // every device on the site, signed off by central.
  it.each([
    ['plaintext http', { httpsEndpoint: 'http://edge-1.internal:8443' }],
    ['credentials in the URL', { httpsEndpoint: 'https://u:p@edge-1.internal:8443' }],
    ['a malformed pin', { tlsSpkiSha256: 'not-a-digest' }],
    ['an upper-case pin', { tlsSpkiSha256: 'A'.repeat(64) }],
  ])('refuses to issue a descriptor built from a row with %s', async (_label, override) => {
    const result = await serviceWith([{ ...identity, ...override }]).issue(context(), null, NOW);
    expect(result.outcome).toBe('REFUSED');
  });
});
