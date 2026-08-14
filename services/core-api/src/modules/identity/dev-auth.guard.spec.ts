import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
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

/** Reflector that reports whether the route is @Public. */
function makeReflector(isPublic: boolean): Reflector {
  return { getAllAndOverride: vi.fn(() => (isPublic ? true : undefined)) } as unknown as Reflector;
}

function makeContext(request: Partial<RequestWithPrincipal>): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request as RequestWithPrincipal,
    }),
    getHandler: () => (): void => {},
    getClass: () => class {},
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
    const guard = new DevAuthGuard(makeReflector(false), makeConfig(false), makePrisma(DB_USER));
    const context = makeContext({ headers: { 'x-dev-user-id': 'user_1' } });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  // WP-14: a @Public route (e.g. /health) is allowed through with no principal
  // even when DEV_AUTH_ENABLED is false — probes must answer.
  it('allows a @Public route through with no principal even when DEV_AUTH_ENABLED is false', async () => {
    const guard = new DevAuthGuard(makeReflector(true), makeConfig(false), makePrisma(null));
    const request: Partial<RequestWithPrincipal> = { headers: {} };
    const context = makeContext(request);

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.principal).toBeUndefined();
  });

  it('rejects with 401 when the header is missing', async () => {
    const guard = new DevAuthGuard(makeReflector(false), makeConfig(true), makePrisma(DB_USER));
    const context = makeContext({ headers: {} });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('rejects with 401 when the header names an unknown user', async () => {
    const guard = new DevAuthGuard(makeReflector(false), makeConfig(true), makePrisma(null));
    const context = makeContext({ headers: { 'x-dev-user-id': 'ghost' } });

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 401 });
  });

  it('attaches a canonical principal built from the user and their role assignments on success', async () => {
    const guard = new DevAuthGuard(makeReflector(false), makeConfig(true), makePrisma(DB_USER));
    const request: Partial<RequestWithPrincipal> = { headers: { 'x-dev-user-id': 'user_1' } };
    const context = makeContext(request);

    const allowed = await guard.canActivate(context);

    expect(allowed).toBe(true);
    expect(request.principal?.user).toEqual({ id: 'user_1', clearance: 3 });
    expect(request.principal?.organisation_id).toBe('org_1');
    expect(request.principal?.roles).toEqual([
      { role: 'operator', site_id: 'site_1' },
      { role: 'investigator', site_id: null },
    ]);
    // hasAction is derived from the §62 role table: operator grants event.ingest,
    // investigator grants ledger.read; nobody here grants org.admin.
    expect(request.principal?.hasAction('event.ingest')).toBe(true);
    expect(request.principal?.hasAction('ledger.read')).toBe(true);
    expect(request.principal?.hasAction('org.admin')).toBe(false);
  });

  it('uses the first value when the header is sent multiple times', async () => {
    const guard = new DevAuthGuard(makeReflector(false), makeConfig(true), makePrisma(DB_USER));
    const request: Partial<RequestWithPrincipal> = { headers: { 'x-dev-user-id': ['user_1', 'user_2'] } };
    const context = makeContext(request);

    await guard.canActivate(context);

    expect(request.principal?.user.id).toBe('user_1');
  });
});
