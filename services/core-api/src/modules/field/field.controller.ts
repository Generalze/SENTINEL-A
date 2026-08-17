import { Body, Controller, Get, Inject, Param, Post, Req } from '@nestjs/common';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { intersectSiteScope } from '../identity/list-pagination';
import {
  ACTION_FIELD_ASSIGNMENT_ACT,
  ACTION_FIELD_ASSIGNMENT_MANAGE,
  ACTION_FIELD_STATE_READ,
  ACTION_FIELD_STATE_WRITE,
} from './field.constants';
import { FieldService } from './field.service';
import type { FieldAssignmentView, FieldOperativeStateView } from './field.types';

@Controller('api/v1/field')
export class FieldController {
  constructor(@Inject(FieldService) private readonly field: FieldService) {}

  @Post('assignments')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_MANAGE)
  async createAssignment(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.createAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_MANAGE), this.field.parseCreateAssignment(body));
  }

  @Get('assignments')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_MANAGE)
  async listAssignments(@Req() req: RequestWithPrincipal): Promise<FieldAssignmentView[]> {
    const principal = requirePrincipal(req);
    return this.field.listAssignments(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_MANAGE));
  }

  /**
   * WP-17/D5: the operative's own refetch surface. `@RequiresAction` carries
   * exactly one action, so the assignee's read and the dispatcher's read are
   * separate routes rather than one route with a widened guard — the
   * `mine` routes are declared before `assignments/:id` so Nest matches the
   * literal segment first.
   */
  @Get('assignments/mine')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async listOwnAssignments(@Req() req: RequestWithPrincipal): Promise<FieldAssignmentView[]> {
    const principal = requirePrincipal(req);
    return this.field.listOwnAssignments(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT));
  }

  @Get('assignments/mine/:id')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async getOwnAssignment(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.getOwnAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT), id);
  }

  @Get('assignments/:id')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_MANAGE)
  async getAssignment(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.getAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_MANAGE), id);
  }

  @Post('assignments/:id/accept')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async accept(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.transitionAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT), id, 'accept', this.field.parseAssignmentAction(body));
  }

  @Post('assignments/:id/decline')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async decline(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.transitionAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT), id, 'decline', this.field.parseAssignmentAction(body));
  }

  @Post('assignments/:id/start')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async start(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.transitionAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT), id, 'start', this.field.parseAssignmentAction(body));
  }

  @Post('assignments/:id/complete')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_ACT)
  async complete(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.transitionAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_ACT), id, 'complete', this.field.parseAssignmentAction(body));
  }

  @Post('assignments/:id/cancel')
  @RequiresAction(ACTION_FIELD_ASSIGNMENT_MANAGE)
  async cancel(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<FieldAssignmentView> {
    const principal = requirePrincipal(req);
    return this.field.transitionAssignment(principal, intersectSiteScope(principal, ACTION_FIELD_ASSIGNMENT_MANAGE), id, 'cancel', this.field.parseAssignmentAction(body));
  }

  @Post('state')
  @RequiresAction(ACTION_FIELD_STATE_WRITE)
  async updateState(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<FieldOperativeStateView> {
    const principal = requirePrincipal(req);
    return this.field.recordState(principal, intersectSiteScope(principal, ACTION_FIELD_STATE_WRITE), this.field.parseStateUpdate(body));
  }

  /**
   * WP-17/D5: an operative's own state read-back. `field.state.read` is the
   * authority to read ANOTHER operative's state and the `field.operative` role
   * does not hold it (§62 table), so without this route the service's
   * "own state needs no extra authority" rule was unreachable — the guard on
   * `state/:userId` denied the operative before it ran. Gated on the write
   * action the operative already holds.
   */
  @Get('state/mine')
  @RequiresAction(ACTION_FIELD_STATE_WRITE)
  async getOwnState(@Req() req: RequestWithPrincipal): Promise<FieldOperativeStateView> {
    const principal = requirePrincipal(req);
    return this.field.getCurrentState(principal, intersectSiteScope(principal, ACTION_FIELD_STATE_WRITE), principal.user.id);
  }

  @Get('state/:userId')
  @RequiresAction(ACTION_FIELD_STATE_READ)
  async getState(@Req() req: RequestWithPrincipal, @Param('userId') userId: string): Promise<FieldOperativeStateView> {
    const principal = requirePrincipal(req);
    return this.field.getCurrentState(principal, intersectSiteScope(principal, ACTION_FIELD_STATE_READ), userId);
  }
}
