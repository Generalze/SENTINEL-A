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

  @Get('state/:userId')
  @RequiresAction(ACTION_FIELD_STATE_READ)
  async getState(@Req() req: RequestWithPrincipal, @Param('userId') userId: string): Promise<FieldOperativeStateView> {
    const principal = requirePrincipal(req);
    return this.field.getCurrentState(principal, intersectSiteScope(principal, ACTION_FIELD_STATE_READ), userId);
  }
}
