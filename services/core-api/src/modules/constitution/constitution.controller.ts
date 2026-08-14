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

import { Controller, Get, Inject, UseGuards } from '@nestjs/common';
import { ConstitutionAdminGuard } from './constitution-admin.guard';
import { ConstitutionService, type ActivePolicyMetadata } from './constitution.service';

@Controller('api/v1/constitution')
export class ConstitutionController {
  constructor(
    @Inject(ConstitutionService) private readonly constitution: ConstitutionService,
  ) {}

  @Get('policy')
  @UseGuards(ConstitutionAdminGuard)
  activePolicy(): ActivePolicyMetadata {
    return this.constitution.activePolicyMetadata;
  }
}
