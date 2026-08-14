import { describe, expect, it, vi } from 'vitest';
import { UsersService } from './users.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';

function makePrisma(): { findMany: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; prisma: PrismaService } {
  const findMany = vi.fn(() => Promise.resolve([]));
  const create = vi.fn((args: unknown) => Promise.resolve(args));
  const prisma = { user: { findMany, create } } as unknown as PrismaService;
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

describe('UsersService', () => {
  it('tenant-filters listForOrganisation and includes role assignments', async () => {
    const { findMany, prisma } = makePrisma();
    const service = new UsersService(prisma);

    await service.listForOrganisation(makePrincipal('org_1'));

    expect(findMany).toHaveBeenCalledWith({
      where: { organisationId: 'org_1' },
      include: { roles: true },
    });
  });

  it('creates a user scoped to the principal\'s organisation with nested role assignments', async () => {
    const { create, prisma } = makePrisma();
    const service = new UsersService(prisma);

    await service.create(makePrincipal('org_1'), {
      email: 'field@alpha.test',
      display_name: 'Field Op',
      clearance: 3,
      roles: [{ role: 'field.operative', site_id: 'site_hq' }],
    });

    expect(create).toHaveBeenCalledWith({
      data: {
        organisationId: 'org_1',
        email: 'field@alpha.test',
        displayName: 'Field Op',
        clearance: 3,
        roles: { create: [{ role: 'field.operative', siteId: 'site_hq' }] },
      },
      include: { roles: true },
    });
  });

  it('defaults a role assignment with no site_id to an organisation-wide (null) scope', async () => {
    const { create, prisma } = makePrisma();
    const service = new UsersService(prisma);

    await service.create(makePrincipal('org_1'), {
      email: 'admin@alpha.test',
      display_name: 'Admin',
      clearance: 5,
      roles: [{ role: 'admin' }],
    });

    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          roles: { create: [{ role: 'admin', siteId: null }] },
        }),
      }),
    );
  });
});
