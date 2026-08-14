import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { ZonesService } from './zones.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import { buildPrincipal, type Principal } from '../principal';
import type { PrincipalRoleAssignment } from '../principal';

function makePrisma(site: unknown): {
  findFirst: ReturnType<typeof vi.fn>;
  findMany: ReturnType<typeof vi.fn>;
  create: ReturnType<typeof vi.fn>;
  prisma: PrismaService;
} {
  const findFirst = vi.fn(() => Promise.resolve(site));
  const findMany = vi.fn(() => Promise.resolve([]));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { site: { findFirst }, zone: { findMany, create } } as unknown as PrismaService;
  return { findFirst, findMany, create, prisma };
}

function makePrincipal(organisationId: string, roles: PrincipalRoleAssignment[] = [{ role: 'admin', site_id: null }]): Principal {
  return buildPrincipal({ user: { id: 'user_1', clearance: 5 }, organisation_id: organisationId, roles });
}

describe('ZonesService', () => {
  it('acceptance #1: throws 404 (never leaking existence) when the site belongs to a different organisation', async () => {
    const { findFirst, prisma } = makePrisma(null); // findFirst scoped to caller's org finds nothing
    const service = new ZonesService(prisma);
    const principal = makePrincipal('org_alpha');

    await expect(service.listForSite(principal, 'site_owned_by_org_beta')).rejects.toBeInstanceOf(NotFoundException);
    expect(findFirst).toHaveBeenCalledWith({
      where: { id: 'site_owned_by_org_beta', organisationId: 'org_alpha' },
    });
  });

  it('throws 404 the same way for a site id that does not exist at all', async () => {
    const { prisma } = makePrisma(null);
    const service = new ZonesService(prisma);
    const principal = makePrincipal('org_alpha');

    await expect(service.create(principal, 'no_such_site', { name: 'Lobby' })).rejects.toBeInstanceOf(NotFoundException);
  });

  // M4 regression (WP-14): a site-scoped site.admin gets the same 404 for a
  // site that IS in its org but outside its granted sites.
  it('M4: a site-scoped site.admin gets 404 for an in-org site outside its grants', async () => {
    const { prisma } = makePrisma({ id: 'site_other', organisationId: 'org_alpha' });
    const service = new ZonesService(prisma);
    const principal = makePrincipal('org_alpha', [{ role: 'admin', site_id: 'site_hq' }]);

    await expect(service.listForSite(principal, 'site_other')).rejects.toBeInstanceOf(NotFoundException);
  });

  it('lists zones for a site that belongs to the caller\'s own organisation', async () => {
    const { findMany, prisma } = makePrisma({ id: 'site_hq', organisationId: 'org_alpha' });
    const service = new ZonesService(prisma);
    const principal = makePrincipal('org_alpha');

    await service.listForSite(principal, 'site_hq');

    expect(findMany).toHaveBeenCalledWith({
      where: { siteId: 'site_hq' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 51,
    });
  });

  it('creates a zone under a site owned by the caller\'s organisation', async () => {
    const { create, prisma } = makePrisma({ id: 'site_hq', organisationId: 'org_alpha' });
    const service = new ZonesService(prisma);
    const principal = makePrincipal('org_alpha');

    await service.create(principal, 'site_hq', { name: 'Lobby' });

    expect(create).toHaveBeenCalledWith({ data: { name: 'Lobby', siteId: 'site_hq' } });
  });
});
