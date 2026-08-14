/**
 * SENTINEL — Decision Ledger read API (WP-08, directive #4/#5).
 *
 * `GET /api/v1/ledger` — tenant-scoped, filterable, cursor-paginated read of the organisation's
 * Decision Ledger. `GET /api/v1/ledger/verify` — admin endpoint exposing
 * `LedgerService.verifyChain`. Both routes carry their own `api/v1` prefix because the service
 * does not set a global prefix (matches events/constitution controllers).
 *
 * Every read (successful or denied) is logged: `LedgerPrincipalActionGuard` logs denials (who
 * attempted, what action, why); this controller logs every read that reaches the service (who,
 * when, which filters) before executing it. `Logger` routes through pino — see main.ts's
 * `app.useLogger(app.get(Logger))`.
 */

import { BadRequestException, Controller, Get, Inject, Logger, Query, Req } from '@nestjs/common';
import { z } from 'zod';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import type { RequestWithPrincipal as RequestWithLedgerPrincipal } from '../../common/security/principal';
import { ACTION_LEDGER_READ, ACTION_LEDGER_VERIFY, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT } from './ledger.constants';
import { LedgerService } from './ledger.service';
import type { LedgerListResult, VerifyChainResult } from './ledger.types';

const ListQuerySchema = z.object({
  decision_type: z.string().min(1).optional(),
  decided_from: z.string().datetime().optional(),
  decided_to: z.string().datetime().optional(),
  limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  cursor: z.string().min(1).optional(),
  // Dev-bypass only (TODO-WIRED-IN-WAVE-4): required when no principal is present, since there
  // is otherwise no tenant to scope the read to.
  organisation_id: z.string().min(1).optional(),
});

function traceIdOf(req: RequestWithLedgerPrincipal): string {
  return req.traceId ?? 'unknown';
}

function callerOf(req: RequestWithLedgerPrincipal): string {
  return req.principal ? `org=${req.principal.organisation_id}` : 'no-principal(dev-bypass)';
}

/** Resolves the tenant a request is scoped to: the principal's own organisation when present,
 * otherwise the explicit dev-bypass query param (never a client-supplied override of a real
 * principal's organisation — mirrors events.controller.ts's `list` exactly). */
function resolveOrganisationId(req: RequestWithLedgerPrincipal, queryOrganisationId: string | undefined): string {
  if (req.principal) return req.principal.organisation_id;
  if (!queryOrganisationId) {
    throw new BadRequestException('organisation_id query param is required when no principal is present (dev bypass)');
  }
  return queryOrganisationId;
}

@Controller('api/v1/ledger')
export class LedgerController {
  private readonly logger = new Logger(LedgerController.name);

  constructor(@Inject(LedgerService) private readonly ledgerService: LedgerService) {}

  /** Deliverable #4: tenant-scoped, filterable, cursor-paginated read, newest first. */
  @Get()
  @RequiresAction(ACTION_LEDGER_READ)
  async list(@Req() req: RequestWithLedgerPrincipal, @Query() rawQuery: Record<string, unknown>): Promise<LedgerListResult> {
    const parsed = ListQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`) });
    }
    const query = parsed.data;
    const organisationId = resolveOrganisationId(req, query.organisation_id);

    const filters = { decision_type: query.decision_type ?? null, decided_from: query.decided_from ?? null, decided_to: query.decided_to ?? null };
    this.logger.log(
      `ledger.read by=${callerOf(req)} organisation_id=${organisationId} filters=${JSON.stringify(filters)} ` +
        `trace_id=${traceIdOf(req)} at=${new Date().toISOString()}`,
    );

    return this.ledgerService.query({
      organisationId,
      decisionType: query.decision_type,
      decidedFrom: query.decided_from ? new Date(query.decided_from) : undefined,
      decidedTo: query.decided_to ? new Date(query.decided_to) : undefined,
      limit: query.limit ?? DEFAULT_LIST_LIMIT,
      cursor: query.cursor,
    });
  }

  /** Deliverable #5: admin endpoint exposing `LedgerService.verifyChain`. */
  @Get('verify')
  @RequiresAction(ACTION_LEDGER_VERIFY)
  async verify(@Req() req: RequestWithLedgerPrincipal, @Query() rawQuery: Record<string, unknown>): Promise<VerifyChainResult> {
    const queryOrganisationId = typeof rawQuery['organisation_id'] === 'string' ? (rawQuery['organisation_id'] as string) : undefined;
    const organisationId = resolveOrganisationId(req, queryOrganisationId);

    this.logger.log(`ledger.verify by=${callerOf(req)} organisation_id=${organisationId} trace_id=${traceIdOf(req)} at=${new Date().toISOString()}`);

    return this.ledgerService.verifyChain(organisationId);
  }
}
