import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { UsersService } from './users.service';
import type { PrismaService } from '../../../prisma/prisma.service';
import type { ConstitutionService } from '../../constitution/constitution.service';
import type { ConstitutionDecision, Decision } from '../../constitution/constitution.engine';
import { buildPrincipal, type Principal } from '../principal';
import type { PrincipalRoleAssignment } from '../principal';

interface PrismaMocks {
  userFindMany: ReturnType<typeof vi.fn>;
  userCreate: ReturnType<typeof vi.fn>;
  siteFindMany: ReturnType<typeof vi.fn>;
  prisma: PrismaService;
}

/** `sites` is what site.findMany resolves to; `approvers` what user.findMany resolves to during create. */
function makePrisma(sites: Array<{ id: string }> = [], approvers: unknown[] = []): PrismaMocks {
  const userFindMany = vi.fn(() => Promise.resolve(approvers));
  const userCreate = vi.fn((args: unknown) => Promise.resolve({ ...(args as Record<string, unknown>), roles: [] }));
  const siteFindMany = vi.fn(() => Promise.resolve(sites));
  const prisma = {
    user: { findMany: userFindMany, create: userCreate },
    site: { findMany: siteFindMany },
  } as unknown as PrismaService;
  return { userFindMany, userCreate, siteFindMany, prisma };
}

/** A ConstitutionService double that returns the given decision from evaluate(). */
function makeConstitution(decision: Decision = 'ALLOW'): { evaluate: ReturnType<typeof vi.fn>; service: ConstitutionService } {
  const evaluate = vi.fn(() =>
    Promise.resolve({ decision, policyVersion: 'test', reasons: [], trace: [] } as ConstitutionDecision),
  );
  return { evaluate, service: { evaluate } as unknown as ConstitutionService };
}

function makePrincipal(organisationId: string, clearance = 5, roles: PrincipalRoleAssignment[] = [{ role: 'admin', site_id: null }]): Principal {
  return buildPrincipal({ user: { id: 'user_1', clearance }, organisation_id: organisationId, roles });
}

describe('UsersService', () => {
  it('tenant-filters listForOrganisation, includes roles, and is capped + ordered (org-wide admin)', async () => {
    const { userFindMany, prisma } = makePrisma();
    const service = new UsersService(prisma, makeConstitution().service);

    await service.listForOrganisation(makePrincipal('org_1'));

    expect(userFindMany).toHaveBeenCalledWith({
      where: { organisationId: 'org_1' },
      include: { roles: true },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 51,
    });
  });

  // M4 regression (WP-14): a site-scoped user.admin sees only users assigned
  // to one of its granted sites, never the whole organisation.
  it('M4: a site-scoped user.admin only lists users at its granted sites', async () => {
    const { userFindMany, prisma } = makePrisma();
    const service = new UsersService(prisma, makeConstitution().service);
    const principal = makePrincipal('org_1', 5, [{ role: 'admin', site_id: 'site_hq' }]);

    await service.listForOrganisation(principal);

    expect(userFindMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { organisationId: 'org_1', roles: { some: { siteId: { in: ['site_hq'] } } } },
      }),
    );
  });

  it('creates a user scoped to the principal\'s organisation with nested role assignments (constitution ALLOWs)', async () => {
    const { userCreate, prisma } = makePrisma([{ id: 'site_hq' }]);
    const service = new UsersService(prisma, makeConstitution('ALLOW').service);

    await service.create(makePrincipal('org_1'), {
      email: 'field@alpha.test',
      display_name: 'Field Op',
      clearance: 3,
      roles: [{ role: 'field.operative', site_id: 'site_hq' }],
    });

    expect(userCreate).toHaveBeenCalledWith({
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
    const { userCreate, prisma } = makePrisma();
    const service = new UsersService(prisma, makeConstitution('ALLOW').service);

    await service.create(makePrincipal('org_1'), {
      email: 'admin@alpha.test',
      display_name: 'Admin',
      clearance: 5,
      roles: [{ role: 'admin' }],
    });

    expect(userCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          roles: { create: [{ role: 'admin', siteId: null }] },
        }),
      }),
    );
  });

  // M1 regression (WP-14): the write is GATED by the Constitution's decision on
  // user.role.grant — a non-ALLOW decision rejects the grant and writes nothing.
  it('M1: rejects the grant and writes nothing when the Constitution does not ALLOW it', async () => {
    const { userCreate, prisma } = makePrisma();
    const { evaluate, service: constitution } = makeConstitution('REQUIRE_APPROVAL');
    const service = new UsersService(prisma, constitution);

    await expect(
      service.create(makePrincipal('org_1'), { email: 'x@alpha.test', display_name: 'X', clearance: 2, roles: [{ role: 'operator' }] }),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({ action: 'user.role.grant' }));
    expect(userCreate).not.toHaveBeenCalled();
  });

  // M2 regression (WP-14): approver AUTHORITY is resolved server-side from
  // Identity (mapped to Constitution roles), NEVER trusted from the body.
  it('M2: resolves approver roles server-side from Identity, not from the request body', async () => {
    const approver = { id: 'appr-1', organisationId: 'org_1', roles: [{ role: 'admin', siteId: null }] };
    const { evaluate, service: constitution } = makeConstitution('ALLOW');
    const { prisma } = makePrisma([], [approver]);
    const service = new UsersService(prisma, constitution);

    await service.create(makePrincipal('org_1'), {
      email: 'x@alpha.test',
      display_name: 'X',
      clearance: 2,
      roles: [{ role: 'operator' }],
      // The body could LIE about approver roles; only user_id is accepted, and the
      // server maps the approver's real Identity role (admin -> platform.admin).
      approvals: [{ user_id: 'appr-1' }],
    });

    expect(evaluate).toHaveBeenCalledWith(
      expect.objectContaining({ approver_roles: { 'appr-1': ['platform.admin'] } }),
    );
  });

  // H3 regression (WP-14): clearance ceiling — a creator may not mint a user
  // with a clearance above their own.
  it('H3: rejects (403) creating a user with a clearance above the creator\'s, and never writes', async () => {
    const { userCreate, prisma } = makePrisma();
    const service = new UsersService(prisma, makeConstitution('ALLOW').service);
    const creator = makePrincipal('org_1', 3); // creator clearance 3

    await expect(
      service.create(creator, { email: 'x@alpha.test', display_name: 'X', clearance: 4, roles: [{ role: 'operator' }] }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(userCreate).not.toHaveBeenCalled();
  });

  it('H3: allows a user whose clearance equals the creator\'s (boundary)', async () => {
    const { userCreate, prisma } = makePrisma();
    const service = new UsersService(prisma, makeConstitution('ALLOW').service);

    await service.create(makePrincipal('org_1', 3), { email: 'x@alpha.test', display_name: 'X', clearance: 3, roles: [{ role: 'operator' }] });

    expect(userCreate).toHaveBeenCalled();
  });

  // H3 regression (WP-14): a role site_id must belong to the creator's org.
  it('H3: rejects (400) a role assignment whose site_id is not in the creator\'s organisation, and never writes', async () => {
    // site.findMany resolves empty -> the requested site is not in this org.
    const { userCreate, prisma } = makePrisma([]);
    const service = new UsersService(prisma, makeConstitution('ALLOW').service);

    await expect(
      service.create(makePrincipal('org_1'), {
        email: 'x@alpha.test',
        display_name: 'X',
        clearance: 2,
        roles: [{ role: 'operator', site_id: 'site_of_other_org' }],
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(userCreate).not.toHaveBeenCalled();
  });
});
