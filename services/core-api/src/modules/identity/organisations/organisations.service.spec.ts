import { describe, expect, it, vi } from 'vitest';
import { OrganisationsService } from './organisations.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import { buildPrincipal, type Principal } from '../principal';

function makePrisma(rows: unknown[] = []): { findMany: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; prisma: PrismaService } {
  const findMany = vi.fn(() => Promise.resolve(rows));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { organisation: { findMany, create } } as unknown as PrismaService;
  return { findMany, create, prisma };
}

function makePrincipal(organisationId: string): Principal {
  return buildPrincipal({ user: { id: 'user_1', clearance: 5 }, organisation_id: organisationId, roles: [{ role: 'admin', site_id: null }] });
}

describe('OrganisationsService', () => {
  it('filters listOwnOrganisation strictly by the principal\'s own organisation id', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new OrganisationsService(prisma);
    const principal = makePrincipal('org_1');

    await service.listOwnOrganisation(principal);

    expect(findMany).toHaveBeenCalledWith({
      where: { id: 'org_1' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 51,
    });
  });

  it('creates an organisation with the given name', async () => {
    const { create, prisma } = makePrisma();
    const service = new OrganisationsService(prisma);

    await service.create({ name: 'Alpha Site Security' });

    expect(create).toHaveBeenCalledWith({ data: { name: 'Alpha Site Security' } });
  });
});
