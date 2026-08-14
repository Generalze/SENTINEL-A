import { ExecutionContext, ForbiddenException, Logger, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LedgerPrincipalActionGuard } from './ledger-principal-action.guard';
import type { RequestWithLedgerPrincipal } from './ledger.principal.types';

function makeReflector(action: string | undefined): Reflector {
  return { getAllAndOverride: vi.fn(() => action) } as unknown as Reflector;
}

function makeContext(request: Partial<RequestWithLedgerPrincipal>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request as RequestWithLedgerPrincipal }),
    getHandler: () => (): void => {},
    getClass: () => class {},
  } as unknown as ExecutionContext;
}

/**
 * Acceptance criterion 4: "Unauthorized role reading ledger -> denied + denial logged." Every
 * branch below both denies (throws) and logs (via the guard's Logger, which nestjs-pino wires
 * to pino at the application level — see main.ts).
 */
describe('LedgerPrincipalActionGuard', () => {
  const originalDevAuth = process.env.DEV_AUTH_ENABLED;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    if (originalDevAuth === undefined) {
      delete process.env.DEV_AUTH_ENABLED;
    } else {
      process.env.DEV_AUTH_ENABLED = originalDevAuth;
    }
  });

  it('denies with 401 and logs when no principal is present and DEV_AUTH_ENABLED is not "true"', () => {
    delete process.env.DEV_AUTH_ENABLED;
    const guard = new LedgerPrincipalActionGuard(makeReflector('ledger.read'));
    const context = makeContext({});

    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toContain('denied');
  });

  it('denies with 403 and logs when the principal lacks the required action', () => {
    const guard = new LedgerPrincipalActionGuard(makeReflector('ledger.read'));
    const context = makeContext({ principal: { organisation_id: 'org-1', hasAction: () => false } });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toContain('denied');
    expect(warnSpy.mock.calls[0]?.[0]).toContain('org-1');
  });

  it('denies with 403 and logs when the principal has no hasAction function at all (fails closed)', () => {
    const guard = new LedgerPrincipalActionGuard(makeReflector('ledger.read'));
    const context = makeContext({ principal: { organisation_id: 'org-1' } });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  it('allows when the principal has the required action', () => {
    const guard = new LedgerPrincipalActionGuard(makeReflector('ledger.read'));
    const context = makeContext({ principal: { organisation_id: 'org-1', hasAction: (a) => a === 'ledger.read' } });

    expect(guard.canActivate(context)).toBe(true);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('allows a request with no principal only via the DEV_AUTH_ENABLED bypass, and still logs it', () => {
    process.env.DEV_AUTH_ENABLED = 'true';
    const guard = new LedgerPrincipalActionGuard(makeReflector('ledger.verify'));
    const context = makeContext({});

    expect(guard.canActivate(context)).toBe(true);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toContain('dev bypass');
  });

  it('allows through when the route declares no required action at all', () => {
    const guard = new LedgerPrincipalActionGuard(makeReflector(undefined));
    const context = makeContext({ principal: { organisation_id: 'org-1' } });

    expect(guard.canActivate(context)).toBe(true);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
