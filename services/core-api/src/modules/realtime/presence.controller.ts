import { BadRequestException, Controller, Get, Inject, Logger, Query, Req, UseGuards } from '@nestjs/common';
import { PresenceActionGuard, RequiresRealtimeAction } from './presence-action.guard';
import { PresenceService, type PresenceEntry } from './presence.service';
import { ACTION_PRESENCE_VIEW } from './realtime.constants';
import type { RequestWithPresencePrincipal } from './realtime-http-principal.types';

interface PresenceListResponse {
  organisation_id: string;
  presence: PresenceEntry[];
}

@Controller('api/v1/presence')
export class PresenceController {
  private readonly logger = new Logger(PresenceController.name);

  constructor(@Inject(PresenceService) private readonly presenceService: PresenceService) {}

  /** Deliverable #4: tenant-scoped presence list. */
  @Get()
  @UseGuards(PresenceActionGuard)
  @RequiresRealtimeAction(ACTION_PRESENCE_VIEW)
  async list(@Req() req: RequestWithPresencePrincipal, @Query() rawQuery: Record<string, unknown>): Promise<PresenceListResponse> {
    const principal = req.principal;
    let organisationId: string;

    if (principal) {
      organisationId = principal.organisation_id;
    } else {
      // TODO-WIRED-IN-WAVE-4 dev bypass (see presence-action.guard.ts):
      // no principal means no inferred tenant. Listing across every
      // organisation is never acceptable, even in dev, so require the
      // caller to say which org explicitly.
      const queryOrgId = rawQuery.organisation_id;
      if (typeof queryOrgId !== 'string' || queryOrgId.length === 0) {
        throw new BadRequestException('organisation_id query param is required when no principal is present (dev bypass)');
      }
      organisationId = queryOrgId;
      this.logger.warn(`presence.list: no principal on request, org-match not enforced (dev bypass, org=${organisationId})`);
    }

    const presence = await this.presenceService.list(organisationId);
    return { organisation_id: organisationId, presence };
  }
}
