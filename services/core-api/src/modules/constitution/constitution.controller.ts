/**
 * SENTINEL — Constitution read API.
 *
 * `GET /api/v1/constitution/policy` returns the *metadata* of the policy currently in force:
 * version, content hash, activation time and the evaluator build. It deliberately does not
 * return the policy body — the hash is what an auditor needs to prove which constitution was
 * in force, and the body is a larger disclosure than a metadata endpoint should make.
 *
 * The route carries its own `api/v1` prefix because the service does not set a global prefix.
 */

import { Controller, Get, Inject } from '@nestjs/common';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { CLASSIFICATION_LEVELS } from '../identity/classification';
import { ConstitutionService, type ActivePolicyMetadata } from './constitution.service';

/**
 * WP-14: the bespoke `ConstitutionAdminGuard` (a duck-typed principal reader
 * with its own role list) is deleted in favour of the ONE global
 * AccessGuard + `@RequiresAction`. Reading active-policy metadata is an
 * administrative action, mapped to the §62 `constitution.policy.read` action
 * (granted to the `admin` role in identity/roles.ts) and classified INTERNAL.
 */
@Controller('api/v1/constitution')
export class ConstitutionController {
  constructor(
    @Inject(ConstitutionService) private readonly constitution: ConstitutionService,
  ) {}

  @Get('policy')
  @RequiresAction('constitution.policy.read', { classification: CLASSIFICATION_LEVELS.INTERNAL })
  activePolicy(): ActivePolicyMetadata {
    return this.constitution.activePolicyMetadata;
  }
}
