/**
 * SENTINEL — `GET /api/v1/constitution/policy` and its admin gate.
 *
 * The guard is deliberately identity-agnostic (WP-03 is concurrent): it only requires that
 * *some* upstream layer attached a principal. These tests pin the fail-closed behaviour so the
 * lead's wiring cannot silently open the endpoint.
 */

import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import {
  CONSTITUTION_POLICY_READER_ROLES,
  ConstitutionAdminGuard,
  extractPrincipal,
} from './constitution-admin.guard';
import { ConstitutionController } from './constitution.controller';
import type { ActivePolicyMetadata, ConstitutionService } from './constitution.service';

function context(request: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

const guard = new ConstitutionAdminGuard();

describe('extractPrincipal', () => {
  it('reads a principal from either conventional request property', () => {
    expect(extractPrincipal({ principal: { userId: 'u-1', roles: ['viewer'] } })).toEqual({
      userId: 'u-1',
      roles: ['viewer'],
    });
    expect(extractPrincipal({ user: { user_id: 'u-2' } })).toEqual({ userId: 'u-2', roles: [] });
    expect(extractPrincipal({ user: { sub: 'u-3', roles: ['analyst'] } })).toEqual({
      userId: 'u-3',
      roles: ['analyst'],
    });
  });

  it('returns null for anything without a usable user id', () => {
    expect(extractPrincipal(undefined)).toBeNull();
    expect(extractPrincipal({})).toBeNull();
    expect(extractPrincipal({ principal: null })).toBeNull();
    expect(extractPrincipal({ principal: { userId: '   ' } })).toBeNull();
    expect(extractPrincipal({ principal: { roles: ['platform.admin'] } })).toBeNull();
  });

  it('ignores non-string entries in the roles array', () => {
    expect(extractPrincipal({ principal: { userId: 'u-1', roles: ['a', 7, null] } })).toEqual({
      userId: 'u-1',
      roles: ['a'],
    });
  });
});

describe('ConstitutionAdminGuard', () => {
  it('rejects a request with no principal (401)', () => {
    expect(() => guard.canActivate(context({}))).toThrow(UnauthorizedException);
  });

  it('rejects an authenticated principal without an administrative role (403)', () => {
    expect(() =>
      guard.canActivate(context({ principal: { userId: 'u-1', roles: ['analyst', 'viewer'] } })),
    ).toThrow(ForbiddenException);
  });

  it('admits each administrative role', () => {
    for (const role of CONSTITUTION_POLICY_READER_ROLES) {
      expect(guard.canActivate(context({ principal: { userId: 'u-1', roles: [role] } }))).toBe(
        true,
      );
    }
  });
});

describe('ConstitutionController', () => {
  it('returns the active policy metadata, and never the policy body', () => {
    const metadata: ActivePolicyMetadata = {
      version: 'sentinel-constitution-1.1.0',
      content_sha256: 'a'.repeat(64),
      status: 'active',
      activated_at: '2026-08-14T09:00:00.000Z',
      engine_version: 'constitution-engine-1.1.0',
    };
    const controller = new ConstitutionController({
      activePolicyMetadata: metadata,
    } as unknown as ConstitutionService);

    const response = controller.activePolicy();
    expect(response).toEqual(metadata);
    expect(Object.keys(response)).not.toContain('body');
    expect(Object.keys(response)).not.toContain('policy');
  });
});
