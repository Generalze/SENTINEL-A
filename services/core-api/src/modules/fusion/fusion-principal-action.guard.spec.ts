import { ForbiddenException, Logger, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ACTION_HYPOTHESIS_READ } from './fusion.constants';
import { FusionPrincipalActionGuard } from './fusion-principal-action.guard';
import type { RequestWithPrincipal } from './fusion-principal.types';

function contextFor(request: Partial<RequestWithPrincipal>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => undefined,
    getClass: () => undefined,
  } as unknown as ExecutionContext;
}

function guardRequiring(action: string | undefined): FusionPrincipalActionGuard {
  const reflector = { getAllAndOverride: () => action } as unknown as Reflector;
  return new FusionPrincipalActionGuard(reflector);
}

describe('FusionPrincipalActionGuard (TODO-WIRED-IN-WAVE-4 stand-in)', () => {
  const originalDevAuth = process.env.DEV_AUTH_ENABLED;

  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalDevAuth === undefined) {
      delete process.env.DEV_AUTH_ENABLED;
    } else {
      process.env.DEV_AUTH_ENABLED = originalDevAuth;
    }
  });

  it('allows a principal that holds the required action', () => {
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    const context = contextFor({ principal: { organisation_id: 'org-1', hasAction: (a) => a === ACTION_HYPOTHESIS_READ } });
    expect(guard.canActivate(context)).toBe(true);
  });

  it('denies a principal that lacks the required action', () => {
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    const context = contextFor({ principal: { organisation_id: 'org-1', hasAction: () => false } });
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('fails closed when a principal is present but hasAction is missing entirely', () => {
    // A half-wired principal must not accidentally authorise anything.
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    const context = contextFor({ principal: { organisation_id: 'org-1' } });
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('rejects an anonymous request by default (401), never an open endpoint', () => {
    process.env.DEV_AUTH_ENABLED = 'false';
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    expect(() => guard.canActivate(contextFor({}))).toThrow(UnauthorizedException);
  });

  it('rejects an anonymous request when DEV_AUTH_ENABLED is unset', () => {
    delete process.env.DEV_AUTH_ENABLED;
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    expect(() => guard.canActivate(contextFor({}))).toThrow(UnauthorizedException);
  });

  it('allows an anonymous request only under the explicit DEV_AUTH_ENABLED bypass, and logs it', () => {
    process.env.DEV_AUTH_ENABLED = 'true';
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const guard = guardRequiring(ACTION_HYPOTHESIS_READ);
    expect(guard.canActivate(contextFor({}))).toBe(true);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('DEV_AUTH_ENABLED dev bypass'));
  });

  it('allows a principal through when the route declares no action requirement', () => {
    const guard = guardRequiring(undefined);
    const context = contextFor({ principal: { organisation_id: 'org-1' } });
    expect(guard.canActivate(context)).toBe(true);
  });
});
