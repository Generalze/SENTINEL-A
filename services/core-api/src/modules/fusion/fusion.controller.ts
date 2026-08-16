/**
 * Hypothesis read API (WP-05 deliverable #6).
 *
 *   GET /api/v1/hypotheses      — tenant-scoped, filterable, cursor-paginated
 *   GET /api/v1/hypotheses/:id  — one hypothesis plus its transition log
 *
 * §11.4 DOCTRINE, ENFORCED BY CONSTRUCTION
 * ----------------------------------------
 * Both routes serialise through `toHypothesisView` (fusion.mapper.ts), which
 * always writes `supporting_event_ids` AND `contradicting_event_ids`, the
 * `confidence_explanation`, and all four §11.3 separated values. There is no
 * "summary" projection, no sparse fieldset parameter and no partial DTO in
 * this module, so no client — the Command UI included — can obtain supporting
 * evidence without the contradicting evidence beside it. Contradiction search
 * is first-class doctrine, so the API must not offer a way to hide it.
 *
 * TENANT SCOPING
 * --------------
 * The organisation is taken from the authenticated principal. Under the
 * Development bypass note: without a principal, an explicit `organisation_id`
 * is REQUIRED rather than defaulting
 * to "all organisations" — an unscoped read is never an acceptable fallback.
 * The detail route treats "belongs to another organisation" and "does not
 * exist" as the same 404, so the API cannot be used to probe for another
 * tenant's hypothesis ids.
 */

import {
  BadRequestException,
  Controller,
  Get,
  Inject,
  Logger,
  NotFoundException,
  Param,
  Query,
  Req,
} from '@nestjs/common';
import { z } from 'zod';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import type { RequestWithPrincipal } from '../../common/security/principal';
import { ACTION_HYPOTHESIS_READ, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT } from './fusion.constants';
import { FusionService } from './fusion.service';
import type { HypothesisDetailView, HypothesisListResult } from './fusion.types';

const ListQuerySchema = z.object({
  site_id: z.string().min(1).optional(),
  /** Matches `zone_id ?? 'site-wide'`, i.e. the value used in the correlation key. */
  zone_key: z.string().min(1).optional(),
  /** Inclusive lower bound on threat state — "everything at SUSPICIOUS or above" is `min_state=2`. */
  min_state: z.coerce.number().int().min(0).max(5).optional(),
  updated_from: z.string().datetime().optional(),
  updated_to: z.string().datetime().optional(),
  limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  cursor: z.string().min(1).optional(),
  // Development bypass only: required when no principal is
  // present, since there is otherwise no tenant to scope the list to.
  organisation_id: z.string().min(1).optional(),
});

const DetailQuerySchema = z.object({
  organisation_id: z.string().min(1).optional(),
});

function formatIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`);
}

@Controller('api/v1/hypotheses')
export class FusionController {
  private readonly logger = new Logger(FusionController.name);

  constructor(@Inject(FusionService) private readonly fusion: FusionService) {}

  @Get()
  @RequiresAction(ACTION_HYPOTHESIS_READ)
  async list(
    @Req() req: RequestWithPrincipal,
    @Query() rawQuery: Record<string, unknown>,
  ): Promise<HypothesisListResult> {
    const parsed = ListQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatIssues(parsed.error) });
    }
    const query = parsed.data;
    const organisationId = this.resolveOrganisationId(req, query.organisation_id);

    return this.fusion.list({
      organisationId,
      siteId: query.site_id,
      zoneKey: query.zone_key,
      minState: query.min_state,
      updatedFrom: query.updated_from ? new Date(query.updated_from) : undefined,
      updatedTo: query.updated_to ? new Date(query.updated_to) : undefined,
      limit: query.limit ?? DEFAULT_LIST_LIMIT,
      cursor: query.cursor,
    });
  }

  @Get(':id')
  @RequiresAction(ACTION_HYPOTHESIS_READ)
  async detail(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Query() rawQuery: Record<string, unknown>,
  ): Promise<HypothesisDetailView> {
    const parsed = DetailQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatIssues(parsed.error) });
    }
    const organisationId = this.resolveOrganisationId(req, parsed.data.organisation_id);

    const hypothesis = await this.fusion.getDetail(organisationId, id);
    if (!hypothesis) {
      // Same response for "not found" and "belongs to another organisation".
      throw new NotFoundException('Hypothesis not found');
    }
    return hypothesis;
  }

  /**
   * The principal's organisation always wins. The query parameter exists
   * solely for the dev bypass, and is ignored (never merged) when a principal
   * is present, so a caller cannot widen or redirect their own scope.
   */
  private resolveOrganisationId(req: RequestWithPrincipal, queryOrganisationId: string | undefined): string {
    const principal = req.principal;
    if (principal) {
      return principal.organisation_id;
    }
    if (!queryOrganisationId) {
      throw new BadRequestException(
        'organisation_id query param is required when no principal is present (dev bypass)',
      );
    }
    this.logger.warn(
      `hypothesis.read: no principal on request, tenant taken from organisation_id query param (dev bypass, trace_id=${req.traceId ?? 'unknown'})`,
    );
    return queryOrganisationId;
  }
}
