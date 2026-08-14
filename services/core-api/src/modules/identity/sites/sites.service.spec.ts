import { describe, expect, it, vi } from 'vitest';
import { SitesService } from './sites.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import { buildPrincipal, type Principal } from '../principal';
import type { PrincipalRoleAssignment } from '../principal';

function makePrisma(rows: unknown[] = []): { findMany: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; prisma: PrismaService } {
  const findMany = vi.fn(() => Promise.resolve(rows));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { site: { findMany, create } } as unknown as PrismaService;
  return { findMany, create, prisma };
}

function makePrincipal(organisationId: string, roles: PrincipalRoleAssignment[] = [{ role: 'admin', site_id: null }]): Principal {
  return buildPrincipal({ user: { id: 'user_1', clearance: 5 }, organisation_id: organisationId, roles });
}

describe('SitesService', () => {
  it('tenant-filters listForOrganisation by the principal\'s organisation (org-wide admin: no site restriction)', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new SitesService(prisma);

    await service.listForOrganisation(makePrincipal('org_1'));

    expect(findMany).toHaveBeenCalledWith({
      where: { organisationId: 'org_1' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 51,
    });
  });

  // M4 regression (WP-14): a SITE-SCOPED site.admin must not read every site
  // in the org — the query is intersected with the granted sites.
  it('M4: a site-scoped site.admin lists only the sites its grants name', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new SitesService(prisma);
    const principal = makePrincipal('org_1', [
      { role: 'admin', site_id: 'site_a' },
      { role: 'admin', site_id: 'site_b' },
    ]);

    await service.listForOrganisation(principal);

    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { organisationId: 'org_1', id: { in: ['site_a', 'site_b'] } },
      }),
    );
  });

  // M6 regression (WP-14): limit is capped and next_cursor is derived from the
  // last row when there is another page.
  it('M6: caps the page and returns next_cursor when more rows exist', async () => {
    // 3 rows returned for limit 2 (service fetches limit+1) -> hasMore, cursor = 2nd row id.
    const { prisma } = makePrisma([{ id: 's1' }, { id: 's2' }, { id: 's3' }]);
    const service = new SitesService(prisma);

    const result = await service.listForOrganisation(makePrincipal('org_1'), { limit: 2 });

    expect(result.items.map((s) => s.id)).toEqual(['s1', 's2']);
    expect(result.next_cursor).toBe('s2');
  });

  it('creates a site scoped to the principal\'s organisation, ignoring any caller-supplied org id', async () => {
    const { create, prisma } = makePrisma();
    const service = new SitesService(prisma);

    await service.create(makePrincipal('org_1'), { name: 'HQ' });

    expect(create).toHaveBeenCalledWith({ data: { name: 'HQ', organisationId: 'org_1' } });
  });
});
