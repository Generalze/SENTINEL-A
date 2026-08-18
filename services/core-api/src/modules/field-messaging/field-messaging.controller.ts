import { Body, Controller, Get, Inject, Param, Post, Req } from '@nestjs/common';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { intersectSiteScope } from '../identity/list-pagination';
import {
  ACTION_MESSAGE_ACKNOWLEDGE,
  ACTION_MESSAGE_OVERSIGHT_READ,
  ACTION_MESSAGE_READ,
  ACTION_MESSAGE_SEND,
} from './field-messaging.constants';
import { FieldMessagingService } from './field-messaging.service';
import type { IncidentFieldMessageView } from './field-messaging.types';

/**
 * WP-18 REST surface. REST is authoritative; the socket only signals.
 *
 * Every route carries exactly ONE `@RequiresAction`. The recipient/sender read
 * and the command-oversight read are separate routes with separate guards
 * rather than one route with a widened check — `incident.view` is held by six
 * roles and must never reach message content.
 */
@Controller('api/v1/field-messages')
export class FieldMessagingController {
  constructor(@Inject(FieldMessagingService) private readonly messaging: FieldMessagingService) {}

  /**
   * Scope is server-derived: the path names the incident, and organisation and
   * site come from that incident. The body cannot choose either.
   */
  @Post('incidents/:incidentId')
  @RequiresAction(ACTION_MESSAGE_SEND)
  async send(@Req() req: RequestWithPrincipal, @Param('incidentId') incidentId: string, @Body() body: unknown): Promise<IncidentFieldMessageView> {
    const principal = requirePrincipal(req);
    return this.messaging.send(principal, intersectSiteScope(principal, ACTION_MESSAGE_SEND), incidentId, this.messaging.parseSend(body));
  }

  /** Messages on this incident the caller sent or was addressed in. Nothing else. */
  @Get('incidents/:incidentId/mine')
  @RequiresAction(ACTION_MESSAGE_READ)
  async listMine(@Req() req: RequestWithPrincipal, @Param('incidentId') incidentId: string): Promise<IncidentFieldMessageView[]> {
    const principal = requirePrincipal(req);
    return this.messaging.listEntitled(principal, intersectSiteScope(principal, ACTION_MESSAGE_READ), incidentId);
  }

  @Get('mine/:id')
  @RequiresAction(ACTION_MESSAGE_READ)
  async readMine(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<IncidentFieldMessageView> {
    const principal = requirePrincipal(req);
    return this.messaging.readEntitled(principal, intersectSiteScope(principal, ACTION_MESSAGE_READ), id);
  }

  /** Recipient-only. An oversight reader has no delivery row and cannot reach this. */
  @Post('mine/:id/acknowledge')
  @RequiresAction(ACTION_MESSAGE_ACKNOWLEDGE)
  async acknowledge(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<IncidentFieldMessageView> {
    const principal = requirePrincipal(req);
    return this.messaging.acknowledge(principal, intersectSiteScope(principal, ACTION_MESSAGE_ACKNOWLEDGE), id, this.messaging.parseAcknowledge(body));
  }

  /**
   * Command oversight. Separate route, separate action, granted to
   * site.commander only. Reading here creates no recipient row, no delivery
   * state, and no acknowledgement attributable to the reader.
   */
  @Get('oversight/incidents/:incidentId')
  @RequiresAction(ACTION_MESSAGE_OVERSIGHT_READ)
  async listOversight(@Req() req: RequestWithPrincipal, @Param('incidentId') incidentId: string): Promise<IncidentFieldMessageView[]> {
    const principal = requirePrincipal(req);
    return this.messaging.listForOversight(principal, intersectSiteScope(principal, ACTION_MESSAGE_OVERSIGHT_READ), incidentId);
  }

  @Get('oversight/:id')
  @RequiresAction(ACTION_MESSAGE_OVERSIGHT_READ)
  async readOversight(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<IncidentFieldMessageView> {
    const principal = requirePrincipal(req);
    return this.messaging.readForOversight(principal, intersectSiteScope(principal, ACTION_MESSAGE_OVERSIGHT_READ), id);
  }
}
