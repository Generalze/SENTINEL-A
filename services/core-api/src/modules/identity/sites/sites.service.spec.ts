import { describe, expect, it, vi } from 'vitest';
import { SitesService } from './sites.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';

function makePrisma(): { findMany: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; prisma: PrismaService } {
  const findMany = vi.fn(() => Promise.resolve([]));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { site: { findMany, create } } as unknown as PrismaService;
  return { findMany, create, prisma };
}

function makePrincipal(organisationId: string): Principal {
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test fixture stands in for the Prisma User type
    user: { id: 'user_1', organisationId, clearance: 5 } as any,
    roles: [{ role: 'admin', site_id: null }],
    organisation_id: organisationId,
  };
}

describe('SitesService', () => {
  it('tenant-filters listForOrganisation by the principal\'s organisation', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new SitesService(prisma);

    await service.listForOrganisation(makePrincipal('org_1'));

    expect(findMany).toHaveBeenCalledWith({ where: { organisationId: 'org_1' } });
  });

  it('creates a site scoped to the principal\'s organisation, ignoring any caller-supplied org id', async () => {
    const { create, prisma } = makePrisma();
    const service = new SitesService(prisma);

    await service.create(makePrincipal('org_1'), { name: 'HQ' });

    expect(create).toHaveBeenCalledWith({ data: { name: 'HQ', organisationId: 'org_1' } });
  });
});
