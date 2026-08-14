/**
 * SENTINEL — `GET /api/v1/constitution/policy`.
 *
 * WP-14: the bespoke `ConstitutionAdminGuard` is gone; the route is now gated
 * by the ONE global AccessGuard via `@RequiresAction('constitution.policy.read')`
 * (covered by identity/access.guard.spec.ts and the AppModule e2e). This spec
 * pins the controller's own contract: it returns policy METADATA and never the
 * policy body.
 */

import { describe, expect, it } from 'vitest';

import { ConstitutionController } from './constitution.controller';
import type { ActivePolicyMetadata, ConstitutionService } from './constitution.service';

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
