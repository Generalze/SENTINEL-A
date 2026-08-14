import { ExecutionContext } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { DevAuthGuard } from './dev-auth.guard';
import type { AppConfigService } from '../../config/config.service';
import type { PrismaService } from '../../prisma/prisma.service';
import type { RequestWithPrincipal } from './http-types';

function makeConfig(devAuthEnabled: boolean): AppConfigService {
  return { values: { DEV_AUTH_ENABLED: devAuthEnabled } } as unknown as AppConfigService;
}

function makePrisma(user: unknown): PrismaService {
  return {
    user: { findUnique: vi.fn(() => Promise.resolve(user)) },
  } as unknown as PrismaService;
}

function makeContext(request: Partial<RequestWithPrincipal>): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request as RequestWithPrincipal,
    }),
  } as unknown as ExecutionContext;
}

const DB_USER = {
  id: 'user_1',
  organisationId: 'org_1',
  email: 'a@b.test',
  displayName: 'A B',
  clearance: 3,
  roles: [
    { id: 'ur_1', userId: 'user_1', role: 'operator', siteId: 'site_1' },
    { id: 'ur_2', userId: 'user_1', role: 'investigator', siteId: null },
  ],
};

describe('DevAuthGuard', () => {
  it('rejects with 401 when DEV_AUTH_ENABLED is false, regardless of header', async () => {
    const guard = new DevAuthGuard(makeConfig(false), makePrisma(DB_USER));
    const context = makeContext({ headers: { 'x-dev-user-id': 'user_1' } });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('rejects with 401 when the header is missing', async () => {
    const guard = new DevAuthGuard(makeConfig(true), makePrisma(DB_USER));
    const context = makeContext({ headers: {} });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('rejects with 401 when the header names an unknown user', async () => {
    const guard = new DevAuthGuard(makeConfig(true), makePrisma(null));
    const context = makeContext({ headers: { 'x-dev-user-id': 'ghost' } });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('attaches a principal built from the user and their role assignments on success', async () => {
    const guard = new DevAuthGuard(makeConfig(true), makePrisma(DB_USER));
    const request: Partial<RequestWithPrincipal> = { headers: { 'x-dev-user-id': 'user_1' } };
    const context = makeContext(request);

    const allowed = await guard.canActivate(context);

    expect(allowed).toBe(true);
    expect(request.principal).toEqual({
      user: DB_USER,
      organisation_id: 'org_1',
      roles: [
        { role: 'operator', site_id: 'site_1' },
        { role: 'investigator', site_id: null },
      ],
    });
  });

  it('uses the first value when the header is sent multiple times', async () => {
    const guard = new DevAuthGuard(makeConfig(true), makePrisma(DB_USER));
    const request: Partial<RequestWithPrincipal> = { headers: { 'x-dev-user-id': ['user_1', 'user_2'] } };
    const context = makeContext(request);

    await guard.canActivate(context);

    expect(request.principal?.user.id).toBe('user_1');
  });
});
