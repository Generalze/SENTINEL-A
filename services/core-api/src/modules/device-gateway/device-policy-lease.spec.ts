import { DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS, type AuthenticatedDeviceContext } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import type { DeviceGatewayRepository, DevicePolicyLeaseRow } from './device-gateway.repository';
import { DevicePolicyLeaseService, WP29A_ADMITTED_OFFLINE_OPERATION_KINDS } from './device-policy-lease.service';
import type { ShieldRepository } from '../shield/shield.repository';

/**
 * WP-29A / D29A-26 §23 — THE LEASE, ON ITS OWN TERMS.
 *
 * These are the checks that do not need a database, and they are the ones most
 * worth having without one: issuance narrowing, the six-hour ceiling, and the
 * rule that a revoked lease resolves to NOTHING. The full path — a signed
 * envelope arriving through the gateway and landing on a receipt — is proven in
 * the live-stack acceptance suite, which needs Postgres.
 *
 * Note what is deliberately NOT re-tested here: the frozen evaluator's own
 * refusals (LEASE_IDENTITY_MISMATCH, LEASE_ACTOR_MISMATCH, LEASE_SCOPE_MISMATCH,
 * LEASE_NOT_IN_FORCE). Those belong to `packages/contracts` and are covered by
 * its suite. Restating them here would be a second opinion about a frozen
 * contract, and the two copies would eventually disagree.
 */

const NOW = new Date('2026-09-05T09:00:00.000Z');
const SITE = 'site-a1';
const ORG = 'org-a';
const DEVICE = 'dev-a';
const ACTOR = 'op-alpha';

function context(overrides: Partial<AuthenticatedDeviceContext> = {}): AuthenticatedDeviceContext {
  return {
    schema_version: 1,
    context_id: 'ctx-1',
    organisation_id: ORG,
    actor_user_id: ACTOR,
    device_id: DEVICE,
    authorised_site_ids: [SITE],
    device_trust: 'TRUSTED',
    key_id: 'key-1',
    key_version: 1,
    issued_at: '2026-09-05T08:58:00.000Z',
    expires_at: '2026-09-05T09:03:00.000Z',
    ...overrides,
  };
}

interface Recorded {
  readonly created: Array<Parameters<DeviceGatewayRepository['createPolicyLease']>[0]>;
}

/**
 * A repository that answers the four questions issuance asks, and records the
 * row it is told to write.
 *
 * `roles` is the lever every test below pulls: the actor's authority is the
 * thing being varied, and it is varied by changing the role assignments the
 * repository reports rather than by stubbing the capability answer directly.
 * Stubbing `holds_required_capability` would make these tests pass without ever
 * exercising the role-to-action mapping that decides it.
 */
function repositoryDouble(options: {
  roles?: Array<{ role: string; siteId: string | null }>;
  lease?: DevicePolicyLeaseRow | null;
  recorded?: Recorded;
}): DeviceGatewayRepository {
  const roles = options.roles ?? [{ role: 'field.operative', siteId: SITE }];
  return {
    now: async () => NOW,
    findActorAuthority: async (organisationId: string, userId: string) =>
      userId === ACTOR && organisationId === ORG ? { userId: ACTOR, organisationId: ORG, clearance: 3, roles } : null,
    listOrganisationSiteIds: async () => [SITE],
    createPolicyLease: async (input: Parameters<DeviceGatewayRepository['createPolicyLease']>[0]) => {
      options.recorded?.created.push(input);
    },
    findPolicyLease: async () => options.lease ?? null,
    revokePolicyLease: async () => true,
    findAuthorityBasis: async () => 'role-1',
  } as unknown as DeviceGatewayRepository;
}

function shieldDouble(options: { deviceExists?: boolean; siteScoped?: boolean } = {}): ShieldRepository {
  return {
    findDevice: async () => ((options.deviceExists ?? true) ? { id: DEVICE, organisationId: ORG } : null),
    hasActiveDeviceSiteScope: async () => options.siteScoped ?? true,
  } as unknown as ShieldRepository;
}

function leaseRow(overrides: Partial<DevicePolicyLeaseRow> = {}): DevicePolicyLeaseRow {
  return {
    id: 'lease-1',
    organisationId: ORG,
    deviceId: DEVICE,
    siteId: SITE,
    actorUserId: ACTOR,
    authorityBasisId: 'role-1',
    scope: ['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'],
    issuedAt: new Date('2026-09-05T08:00:00.000Z'),
    expiresAt: new Date('2026-09-05T14:00:00.000Z'),
    revokedAt: null,
    ...overrides,
  };
}

function service(repository: DeviceGatewayRepository, shield: ShieldRepository): DevicePolicyLeaseService {
  return new DevicePolicyLeaseService(repository, shield);
}

const ISSUE_INPUT = {
  siteId: SITE,
  requestedScope: WP29A_ADMITTED_OFFLINE_OPERATION_KINDS,
  authorityBasisId: 'role-1',
  requestedLifetimeMs: DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
};

describe('WP-29A/D29A-26 §7 the six-hour ceiling', () => {
  it('clamps a request that exceeds the frozen ceiling instead of honouring it', async () => {
    const recorded: Recorded = { created: [] };
    const lease = await service(repositoryDouble({ recorded }), shieldDouble()).issue({
      context: context(),
      ...ISSUE_INPUT,
      // A year. A client that asks for one must not receive one.
      requestedLifetimeMs: 365 * 24 * 60 * 60 * 1000,
    });

    expect(lease).not.toBeNull();
    const window = new Date(lease!.expires_at).getTime() - new Date(lease!.issued_at).getTime();
    expect(window).toBe(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
    expect(window).toBe(21_600_000);
  });

  it('issues from the SERVER clock, never a supplied instant', async () => {
    const recorded: Recorded = { created: [] };
    const lease = await service(repositoryDouble({ recorded }), shieldDouble()).issue({ context: context(), ...ISSUE_INPUT });

    // There is no parameter for a device-supplied time, and the issued window
    // is anchored on `repository.now()` — D29A-26 §8.
    expect(lease?.issued_at).toBe(NOW.toISOString());
    expect(recorded.created[0]?.issuedAt).toEqual(NOW);
  });

  it('refuses a zero-length lease rather than minting authority that admits nothing', async () => {
    const lease = await service(repositoryDouble({}), shieldDouble()).issue({
      context: context(),
      ...ISSUE_INPUT,
      requestedLifetimeMs: 0,
    });
    expect(lease).toBeNull();
  });
});

describe('WP-29A/D29A-26 §11-§12 a lease never out-scopes its device or its actor', () => {
  it('refuses when the device is not entitled to the site', async () => {
    const lease = await service(repositoryDouble({}), shieldDouble({ siteScoped: false })).issue({
      context: context(),
      ...ISSUE_INPUT,
    });
    expect(lease).toBeNull();
  });

  it('refuses when the device does not exist in this tenant', async () => {
    const lease = await service(repositoryDouble({}), shieldDouble({ deviceExists: false })).issue({
      context: context(),
      ...ISSUE_INPUT,
    });
    expect(lease).toBeNull();
  });

  it('refuses when the actor holds no role granting the operation', async () => {
    // `evidence.custodian` is a real role that genuinely lacks
    // `field.message.acknowledge`. The capability answer comes from the
    // role-to-action mapping in `identity/roles.ts`, not from a stub, so this
    // fails for the reason it claims to — and picking a role that turned out to
    // HOLD the action is exactly the mistake a stubbed answer would have hidden.
    const lease = await service(repositoryDouble({ roles: [{ role: 'evidence.custodian', siteId: SITE }] }), shieldDouble()).issue({
      context: context(),
      ...ISSUE_INPUT,
    });
    expect(lease).toBeNull();
  });

  it('refuses when the actor works a DIFFERENT site', async () => {
    const lease = await service(repositoryDouble({ roles: [{ role: 'field.operative', siteId: 'site-a2' }] }), shieldDouble()).issue({
      context: context(),
      ...ISSUE_INPUT,
    });
    expect(lease).toBeNull();
  });

  it('refuses a site the CONTEXT never authorised, even when everything else agrees', async () => {
    // The device is entitled, the actor is entitled — and the ceremony did not
    // establish this site. A lease for it would be authority nothing granted.
    const lease = await service(repositoryDouble({}), shieldDouble()).issue({
      context: context({ authorised_site_ids: ['site-a2'] }),
      ...ISSUE_INPUT,
    });
    expect(lease).toBeNull();
  });

  it('drops an unrecognised operation kind rather than reporting which ones exist', async () => {
    // Refusing loudly would let a caller discover the admitted vocabulary by
    // watching which strings produce a different answer. Unknown kinds are
    // dropped and the empty result is refused exactly like any other refusal.
    const lease = await service(repositoryDouble({}), shieldDouble()).issue({
      context: context(),
      ...ISSUE_INPUT,
      requestedScope: ['NOT_A_REAL_KIND', 'ALSO_NOT_REAL'],
    });
    expect(lease).toBeNull();
  });

  it('grants exactly the WP-29A scope and nothing wider', async () => {
    const lease = await service(repositoryDouble({}), shieldDouble()).issue({ context: context(), ...ISSUE_INPUT });
    expect(lease?.scope).toEqual(['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE']);
    // The admitted set IS the stale-tolerant set. Widening one without the
    // other would admit a kind that then refuses for want of a time witness.
    expect([...WP29A_ADMITTED_OFFLINE_OPERATION_KINDS]).toEqual(['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE']);
  });

  it('binds the issued lease to the CONTEXT identity, not to anything a caller passed', async () => {
    const lease = await service(repositoryDouble({}), shieldDouble()).issue({ context: context(), ...ISSUE_INPUT });
    expect(lease?.organisation_id).toBe(ORG);
    expect(lease?.device_id).toBe(DEVICE);
    expect(lease?.actor_user_id).toBe(ACTOR);
    expect(lease?.site_id).toBe(SITE);
  });
});

describe('WP-29A/D29A-26 §9 revocation is a state, and a revoked lease resolves to nothing', () => {
  it('resolves a live lease', async () => {
    const resolved = await service(repositoryDouble({ lease: leaseRow() }), shieldDouble()).resolve(ORG, 'lease-1');
    expect(resolved?.lease_id).toBe('lease-1');
    expect(resolved?.scope).toEqual(['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE']);
  });

  it('returns NULL for a revoked lease, so the evaluator answers LEASE_MISSING', async () => {
    // This is the load-bearing line of the whole file. The frozen evaluator has
    // NO revocation input — it judges identity, scope and the window — so
    // handing it a revoked lease would have it judged as though it were live
    // and the operation ADMITTED. Withholding it is the only fail-closed
    // answer, and the row itself is untouched so provenance survives.
    const resolved = await service(repositoryDouble({ lease: leaseRow({ revokedAt: new Date() }) }), shieldDouble()).resolve(
      ORG,
      'lease-1',
    );
    expect(resolved).toBeNull();
  });

  it('returns NULL for a lease that does not exist', async () => {
    const resolved = await service(repositoryDouble({ lease: null }), shieldDouble()).resolve(ORG, 'lease-nope');
    expect(resolved).toBeNull();
  });

  it('returns NULL for a row that no longer satisfies the frozen contract', async () => {
    // A row written by hand, or before a contract change, must fail closed here
    // rather than flow into the evaluator as a shape nothing checked. An empty
    // scope is unrepresentable in the contract (`min(1)`).
    const resolved = await service(repositoryDouble({ lease: leaseRow({ scope: [] }) }), shieldDouble()).resolve(ORG, 'lease-1');
    expect(resolved).toBeNull();
  });

  it('returns NULL for a row whose window exceeds the frozen ceiling', async () => {
    // Defence against a lease widened directly in the database: the contract
    // re-refines the window on the way out, not only on the way in.
    const resolved = await service(
      repositoryDouble({ lease: leaseRow({ expiresAt: new Date('2026-09-06T08:00:00.000Z') }) }),
      shieldDouble(),
    ).resolve(ORG, 'lease-1');
    expect(resolved).toBeNull();
  });
});

describe('WP-29A the in-force classifier defers to the frozen contract', () => {
  it('is VALID inside the window and not outside it', async () => {
    const subject = service(repositoryDouble({ lease: leaseRow() }), shieldDouble());
    const lease = await subject.resolve(ORG, 'lease-1');
    expect(lease).not.toBeNull();
    expect(subject.isInForce(lease!, new Date('2026-09-05T09:00:00.000Z'))).toBe(true);
    // Before it was issued.
    expect(subject.isInForce(lease!, new Date('2026-09-05T07:00:00.000Z'))).toBe(false);
    // After it expired — the case a reconnecting queue actually hits.
    expect(subject.isInForce(lease!, new Date('2026-09-05T15:00:00.000Z'))).toBe(false);
  });
});
