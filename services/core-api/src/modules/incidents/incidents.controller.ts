import { BadRequestException, Body, Controller, Get, Inject, Param, Post, Query, Req } from '@nestjs/common';
import { z } from 'zod';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { intersectSiteScope } from '../identity/list-pagination';
import { ACTION_FIELD_ACKNOWLEDGE, ACTION_INCIDENT_VIEW } from './incidents.constants';
import { IncidentsService } from './incidents.service';
import type { IncidentDetailView } from './incidents.types';

const ListQuery = z.object({
  status: z.enum(['open', 'contained', 'closed']).optional(),
  severity: z.enum(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']).optional(),
  limit: z.coerce.number().int().positive().max(200).optional(),
});
const CloseBody = z.object({ closure_reason: z.string().trim().min(1).max(4000) });
const TransitionBody = z.object({
  status: z.enum(['contained', 'closed']),
  closure_reason: z.string().trim().min(1).max(4000).optional(),
});

@Controller('api/v1/incidents')
export class IncidentsController {
  constructor(@Inject(IncidentsService) private readonly incidents: IncidentsService) {}

  @Get()
  @RequiresAction(ACTION_INCIDENT_VIEW)
  async list(@Req() req: RequestWithPrincipal, @Query() query: Record<string, unknown>): Promise<IncidentDetailView[]> {
    const parsed = ListQuery.safeParse(query);
    if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
    const principal = requirePrincipal(req);
    return this.incidents.list({
      organisationId: principal.organisation_id,
      siteScope: intersectSiteScope(principal, ACTION_INCIDENT_VIEW),
      ...parsed.data,
      limit: parsed.data.limit ?? 50,
    });
  }

  @Get(':id')
  @RequiresAction(ACTION_INCIDENT_VIEW)
  async detail(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<IncidentDetailView> {
    const principal = requirePrincipal(req);
    return this.incidents.getDetail(principal.organisation_id, id, intersectSiteScope(principal, ACTION_INCIDENT_VIEW));
  }

  @Post(':id/tasks/:taskId/ack')
  @RequiresAction(ACTION_FIELD_ACKNOWLEDGE)
  async acknowledge(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Param('taskId') taskId: string,
  ): Promise<IncidentDetailView> {
    const principal = requirePrincipal(req);
    return this.incidents.acknowledge(
      principal.organisation_id,
      id,
      taskId,
      principal.user.id,
      intersectSiteScope(principal, ACTION_FIELD_ACKNOWLEDGE),
    );
  }

  @Post(':id/tasks/:taskId/silent-approvals')
  @RequiresAction('incident.silent.approve')
  async approveSilent(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Param('taskId') taskId: string): Promise<IncidentDetailView> {
    const principal = requirePrincipal(req);
    return this.incidents.approveSilentDispatch(
      principal.organisation_id,
      id,
      taskId,
      principal.user.id,
      intersectSiteScope(principal, 'incident.silent.approve'),
    );
  }

  @Post(':id/contain')
  @RequiresAction('incident.close')
  async contain(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<IncidentDetailView> {
    const principal = requirePrincipal(req);
    return this.incidents.transitionStatus(principal.organisation_id, id, intersectSiteScope(principal, 'incident.close'), {
      status: 'contained',
      actorUserId: principal.user.id,
    });
  }

  /** Stable lifecycle endpoint consumed by Command; service still enforces the full graph. */
  @Post(':id/transition')
  @RequiresAction('incident.close')
  async transition(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() rawBody: unknown): Promise<IncidentDetailView> {
    const parsed = TransitionBody.safeParse(rawBody);
    if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
    const principal = requirePrincipal(req);
    return this.incidents.transitionStatus(principal.organisation_id, id, intersectSiteScope(principal, 'incident.close'), {
      status: parsed.data.status,
      closureReason: parsed.data.closure_reason,
      actorUserId: principal.user.id,
    });
  }

  @Post(':id/close')
  @RequiresAction('incident.close')
  async close(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() rawBody: unknown): Promise<IncidentDetailView> {
    const parsed = CloseBody.safeParse(rawBody);
    if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
    const principal = requirePrincipal(req);
    return this.incidents.transitionStatus(principal.organisation_id, id, intersectSiteScope(principal, 'incident.close'), {
      status: 'closed',
      closureReason: parsed.data.closure_reason,
      actorUserId: principal.user.id,
    });
  }
}
