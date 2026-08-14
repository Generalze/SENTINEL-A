import { ExecutionContext, ForbiddenException, Logger, NotFoundException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import { AccessGuard } from './access.guard';
import { CLASSIFICATION_LEVELS } from './classification';
import type { RequestWithPrincipal } from './http-types';
import type { RequiredActionMetadata } from './requires-action.decorator';
import type { Principal } from './principal';

function makeReflector(metadata: RequiredActionMetadata | undefined): Reflector {
  return { getAllAndOverride: vi.fn(() => metadata) } as unknown as Reflector;
}

function makeContext(request: Partial<RequestWithPrincipal>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request as RequestWithPrincipal }),
    getHandler: () => (): void => {},
    getClass: () => class {},
  } as unknown as ExecutionContext;
}

function makePrincipal(overrides: Partial<Principal> = {}): Principal {
  return {
    user: {
      id: 'user_1',
      organisationId: 'org_1',
      email: 'a@b.test',
      displayName: 'A B',
      clearance: 3,
      createdAt: new Date(),
      updatedAt: new Date(),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test fixture stands in for the Prisma User type
    } as any,
    roles: [{ role: 'operator', site_id: null }],
    organisation_id: 'org_1',
    ...overrides,
  };
}

function baseRequest(principal: Principal | undefined, extra: Partial<RequestWithPrincipal> = {}): RequestWithPrincipal {
  return {
    headers: {},
    params: {},
    query: {},
    body: {},
    principal,
    ...extra,
  } as RequestWithPrincipal;
}

describe('AccessGuard', () => {
  it('allows the request through untouched when the route has no @RequiresAction metadata', () => {
    const guard = new AccessGuard(makeReflector(undefined));
    const context = makeContext(baseRequest(undefined));

    expect(guard.canActivate(context)).toBe(true);
  });

  it('denies (403) when there is no principal on the request at all', () => {
    const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.PUBLIC };
    const guard = new AccessGuard(makeReflector(required));
    const context = makeContext(baseRequest(undefined));

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  describe('conjunct: role permits action', () => {
    it('denies (403) when none of the principal\'s roles grant the action', () => {
      const required: RequiredActionMetadata = { action: 'org.admin', classification: CLASSIFICATION_LEVELS.PUBLIC };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      const context = makeContext(baseRequest(principal));

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('allows when at least one of several role assignments grants the action', () => {
      const required: RequiredActionMetadata = { action: 'evidence.read', classification: CLASSIFICATION_LEVELS.PUBLIC };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({
        roles: [
          { role: 'dispatcher', site_id: null },
          { role: 'investigator', site_id: null },
        ],
      });
      const context = makeContext(baseRequest(principal));

      expect(guard.canActivate(context)).toBe(true);
    });
  });

  describe('conjunct: organisation matches', () => {
    const required: RequiredActionMetadata = { action: 'site.admin', classification: CLASSIFICATION_LEVELS.PUBLIC };

    it('denies with 404 (not 403) when the request targets a different organisation', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ organisation_id: 'org_1', roles: [{ role: 'admin', site_id: null }] });
      const context = makeContext(baseRequest(principal, { params: { organisationId: 'org_2' } }));

      expect(() => guard.canActivate(context)).toThrow(NotFoundException);
    });

    it('allows when the request targets the principal\'s own organisation', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ organisation_id: 'org_1', roles: [{ role: 'admin', site_id: null }] });
      const context = makeContext(baseRequest(principal, { params: { organisationId: 'org_1' } }));

      expect(guard.canActivate(context)).toBe(true);
    });

    it('allows when the request carries no organisation id at all (the common case)', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'admin', site_id: null }] });
      const context = makeContext(baseRequest(principal));

      expect(guard.canActivate(context)).toBe(true);
    });
  });

  describe('conjunct: site scope matches', () => {
    const required: RequiredActionMetadata = { action: 'field.acknowledge', classification: CLASSIFICATION_LEVELS.PUBLIC };

    it('denies (403, not 404) when the granting role assignment is scoped to a different site', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'field.operative', site_id: 'site_hq' }] });
      const context = makeContext(baseRequest(principal, { params: { siteId: 'site_other' } }));

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('allows when the granting role assignment is scoped to the requested site', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'field.operative', site_id: 'site_hq' }] });
      const context = makeContext(baseRequest(principal, { params: { siteId: 'site_hq' } }));

      expect(guard.canActivate(context)).toBe(true);
    });

    it('allows any site when the granting role assignment is organisation-wide (site_id null)', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'field.operative', site_id: null }] });
      const context = makeContext(baseRequest(principal, { params: { siteId: 'site_anything' } }));

      expect(guard.canActivate(context)).toBe(true);
    });

    it('is not evaluated when the request carries no site id', () => {
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'field.operative', site_id: 'site_hq' }] });
      const context = makeContext(baseRequest(principal));

      expect(guard.canActivate(context)).toBe(true);
    });
  });

  describe('conjunct: clearance >= classification', () => {
    // Uses INTERNAL (below the SENSITIVE purpose-header threshold) so this
    // conjunct is isolated from the purpose conjunct below.
    it('denies (403) when clearance is one below the required classification', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.INTERNAL };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({
        roles: [{ role: 'operator', site_id: null }],
      });
      principal.user.clearance = CLASSIFICATION_LEVELS.INTERNAL - 1;
      const context = makeContext(baseRequest(principal));

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('allows when clearance exactly equals the required classification (boundary)', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.INTERNAL };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      principal.user.clearance = CLASSIFICATION_LEVELS.INTERNAL;
      const context = makeContext(baseRequest(principal));

      expect(guard.canActivate(context)).toBe(true);
    });
  });

  describe('conjunct: purpose is valid', () => {
    it('denies (403) a SENSITIVE+ route with no x-purpose header', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.SENSITIVE };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      const context = makeContext(baseRequest(principal));

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('denies (403) a SENSITIVE+ route when x-purpose is present but blank', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.SENSITIVE };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      const context = makeContext(baseRequest(principal, { headers: { 'x-purpose': '   ' } }));

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });

    it('allows a SENSITIVE+ route when x-purpose is present', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.SENSITIVE };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      const context = makeContext(baseRequest(principal, { headers: { 'x-purpose': 'incident-review' } }));

      expect(guard.canActivate(context)).toBe(true);
    });

    it('does not require x-purpose below the SENSITIVE threshold', () => {
      const required: RequiredActionMetadata = { action: 'incident.view', classification: CLASSIFICATION_LEVELS.INTERNAL };
      const guard = new AccessGuard(makeReflector(required));
      const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
      const context = makeContext(baseRequest(principal));

      expect(guard.canActivate(context)).toBe(true);
    });
  });

  it('logs the actor, action and failed conjunct on every denial', () => {
    const warnSpy = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const required: RequiredActionMetadata = { action: 'org.admin', classification: CLASSIFICATION_LEVELS.PUBLIC };
    const guard = new AccessGuard(makeReflector(required));
    const principal = makePrincipal({ roles: [{ role: 'operator', site_id: null }] });
    const context = makeContext(baseRequest(principal));

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('actor=user_1 action=org.admin failed_conjunct=role_permits_action'),
    );
    warnSpy.mockRestore();
  });
});
