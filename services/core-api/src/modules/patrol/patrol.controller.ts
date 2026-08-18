import { Body, Controller, Get, Inject, Param, Post, Req } from '@nestjs/common';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { intersectSiteScope } from '../identity/list-pagination';
import {
  ACTION_PATROL_CHECKPOINT_VERIFY,
  ACTION_PATROL_ROUTE_MANAGE,
  ACTION_PATROL_ROUTE_READ,
  ACTION_PATROL_RUN_ACT,
  ACTION_PATROL_RUN_MANAGE,
  ACTION_PATROL_RUN_READ,
} from './patrol.constants';
import { PatrolService } from './patrol.service';
import type { PatrolRouteView, PatrolRunView, VerifyCheckpointResultView } from './patrol.types';

/**
 * WP-19 REST surface. REST is authoritative; the Field socket only signals.
 *
 * Every route carries exactly ONE `@RequiresAction`, mapped from the C9-09
 * matrix. There is deliberately NO complete endpoint: completion is
 * system-owned and happens inside the transaction that resolves the final
 * checkpoint. Abandonment has two routes because it has two authorities —
 * the operative's own run, and command intervention which must carry a reason.
 */
@Controller('api/v1/patrol')
export class PatrolController {
  constructor(@Inject(PatrolService) private readonly patrol: PatrolService) {}

  // --- Routes (definitions) ------------------------------------------------

  @Post('routes')
  @RequiresAction(ACTION_PATROL_ROUTE_MANAGE)
  async createRoute(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<PatrolRouteView> {
    const principal = requirePrincipal(req);
    return this.patrol.createRoute(principal, intersectSiteScope(principal, ACTION_PATROL_ROUTE_MANAGE), this.patrol.parseCreateRoute(body));
  }

  /** C9-04: the ONLY way to change a patrol standard — a new immutable version. */
  @Post('routes/:id/versions')
  @RequiresAction(ACTION_PATROL_ROUTE_MANAGE)
  async publishVersion(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<PatrolRouteView> {
    const principal = requirePrincipal(req);
    return this.patrol.publishVersion(principal, intersectSiteScope(principal, ACTION_PATROL_ROUTE_MANAGE), id, this.patrol.parsePublishVersion(body));
  }

  @Get('routes')
  @RequiresAction(ACTION_PATROL_ROUTE_READ)
  async listRoutes(@Req() req: RequestWithPrincipal): Promise<PatrolRouteView[]> {
    const principal = requirePrincipal(req);
    return this.patrol.listRoutes(principal, intersectSiteScope(principal, ACTION_PATROL_ROUTE_READ));
  }

  @Get('routes/:id')
  @RequiresAction(ACTION_PATROL_ROUTE_READ)
  async getRoute(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<PatrolRouteView> {
    const principal = requirePrincipal(req);
    return this.patrol.getRoute(principal, intersectSiteScope(principal, ACTION_PATROL_ROUTE_READ), id);
  }

  // --- Runs (executions) ---------------------------------------------------

  @Post('runs')
  @RequiresAction(ACTION_PATROL_RUN_MANAGE)
  async scheduleRun(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.scheduleRun(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_MANAGE), this.patrol.parseScheduleRun(body));
  }

  /**
   * C9-05 visibility is decided in the service: command reach for holders of
   * patrol.run.manage, own-runs-only for operatives — same guard either way.
   */
  @Get('runs')
  @RequiresAction(ACTION_PATROL_RUN_READ)
  async listRuns(@Req() req: RequestWithPrincipal): Promise<PatrolRunView[]> {
    const principal = requirePrincipal(req);
    return this.patrol.listRuns(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_READ));
  }

  @Get('runs/:id')
  @RequiresAction(ACTION_PATROL_RUN_READ)
  async getRun(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.getRun(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_READ), id);
  }

  /** START = assigned operative only (C9-09); a non-assignee gets 404. */
  @Post('runs/:id/start')
  @RequiresAction(ACTION_PATROL_RUN_ACT)
  async startRun(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.startRun(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_ACT), id, this.patrol.parseRunAction(body));
  }

  /** CANCEL = command authority, before the run ever starts (C9-03/C9-09). */
  @Post('runs/:id/cancel')
  @RequiresAction(ACTION_PATROL_RUN_MANAGE)
  async cancelRun(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.cancelRun(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_MANAGE), id, this.patrol.parseRunAction(body));
  }

  /** ABANDON, operative path: own run only. */
  @Post('runs/:id/abandon')
  @RequiresAction(ACTION_PATROL_RUN_ACT)
  async abandonOwnRun(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.abandonOwnRun(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_ACT), id, this.patrol.parseAbandon(body));
  }

  /** ABANDON, command path: requires a reason, which lands in the audit record. */
  @Post('runs/:id/abandon-command')
  @RequiresAction(ACTION_PATROL_RUN_MANAGE)
  async abandonAsCommand(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<PatrolRunView> {
    const principal = requirePrincipal(req);
    return this.patrol.abandonAsCommand(principal, intersectSiteScope(principal, ACTION_PATROL_RUN_MANAGE), id, this.patrol.parseAbandon(body));
  }

  /** VERIFY = assigned operative only (C9-09). */
  @Post('runs/:id/checkpoints/:runCheckpointId/verify')
  @RequiresAction(ACTION_PATROL_CHECKPOINT_VERIFY)
  async verifyCheckpoint(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Param('runCheckpointId') runCheckpointId: string,
    @Body() body: unknown,
  ): Promise<VerifyCheckpointResultView> {
    const principal = requirePrincipal(req);
    return this.patrol.verifyCheckpoint(principal, intersectSiteScope(principal, ACTION_PATROL_CHECKPOINT_VERIFY), id, runCheckpointId, this.patrol.parseVerify(body));
  }
}
