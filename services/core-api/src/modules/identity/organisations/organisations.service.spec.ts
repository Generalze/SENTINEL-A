import { describe, expect, it, vi } from 'vitest';
import { OrganisationsService } from './organisations.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';

function makePrisma(): { findMany: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; prisma: PrismaService } {
  const findMany = vi.fn(() => Promise.resolve([]));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { organisation: { findMany, create } } as unknown as PrismaService;
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

describe('OrganisationsService', () => {
  it('filters listOwnOrganisation strictly by the principal\'s own organisation id', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new OrganisationsService(prisma);
    const principal = makePrincipal('org_1');

    await service.listOwnOrganisation(principal);

    expect(findMany).toHaveBeenCalledWith({ where: { id: 'org_1' } });
  });

  it('creates an organisation with the given name', async () => {
    const { create, prisma } = makePrisma();
    const service = new OrganisationsService(prisma);

    await service.create({ name: 'Alpha Site Security' });

    expect(create).toHaveBeenCalledWith({ data: { name: 'Alpha Site Security' } });
  });
});
