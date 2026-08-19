import { Body, Controller, Get, Inject, Param, Patch, Post, Query, Req } from '@nestjs/common';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import {
  ACTION_WHISPER_SIGNAL_APPROVE,
  ACTION_WHISPER_SIGNAL_MANAGE,
  ACTION_WHISPER_SIGNAL_READ,
} from './whisper.constants';
import { WhisperService } from './whisper.service';
import type { WhisperSignalFamilyView, WhisperSignalVersionView } from './whisper.types';

/**
 * WP-21B Whisper STUDIO surface (B11-03).
 *
 * THERE IS NO RECOGNITION ROUTE HERE, AND THERE MUST NEVER BE ONE.
 *
 * The runtime's entire safety argument rests on
 * `AuthenticatedWhisperDeviceContext` being SERVER-ESTABLISHED (W21-05): the
 * organisation, the actor, the device, its authorised sites, the platform's
 * trust judgement about it, and the id of the key its signature is checked
 * against. A `device_id` read from a JSON body is not authenticated device
 * identity, and neither is a `device_trust` a device asserts about itself.
 * Exposing an invoke endpoint before a genuine device-authentication facility
 * exists would mean accepting that context from the wire — the exact trust
 * hole WP-20/C10-02 forbids, on the one channel whose consequence is a silent
 * duress dispatch. `WhisperService.recognise` is the seam instead; whoever
 * builds that facility wires the transport.
 *
 * There is also NO DELETE ENDPOINT. Section 61: history is never erased to
 * make an administrative action possible. Withdrawing a signal is ROTATED or
 * RETIRED — an audited transition that leaves the record of what was once
 * live, and of every recognition it ever answered, intact.
 *
 * Every route carries exactly ONE `@RequiresAction`, mapped from the W21-12
 * matrix: read, manage and approve are three different powers, and activation
 * is deliberately the only one behind `approve`.
 */
@Controller('api/v1/whisper/signals')
export class WhisperController {
  constructor(@Inject(WhisperService) private readonly whisper: WhisperService) {}

  /** Creates a family at version 1, DRAFT. Organisation comes from the principal. */
  @Post()
  @RequiresAction(ACTION_WHISPER_SIGNAL_MANAGE)
  async create(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<WhisperSignalVersionView> {
    const principal = requirePrincipal(req);
    return this.whisper.createSignal(principal, this.whisper.parseCreateSignal(body));
  }

  @Get()
  @RequiresAction(ACTION_WHISPER_SIGNAL_READ)
  async list(@Req() req: RequestWithPrincipal, @Query() query: Record<string, unknown>): Promise<WhisperSignalVersionView[]> {
    const principal = requirePrincipal(req);
    return this.whisper.list(principal, this.whisper.parseListQuery(query));
  }

  /** One family and its whole version history; out of scope reads as not found. */
  @Get(':id')
  @RequiresAction(ACTION_WHISPER_SIGNAL_READ)
  async detail(@Req() req: RequestWithPrincipal, @Param('id') id: string): Promise<WhisperSignalFamilyView> {
    const principal = requirePrincipal(req);
    return this.whisper.getFamily(principal, id);
  }

  /** W21-02: the ONLY way to change a configuration that has left DRAFT. */
  @Post(':id/versions')
  @RequiresAction(ACTION_WHISPER_SIGNAL_MANAGE)
  async publishVersion(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<WhisperSignalVersionView> {
    const principal = requirePrincipal(req);
    return this.whisper.publishVersion(principal, id, this.whisper.parsePublishVersion(body));
  }

  /** A DRAFT-only configuration edit; past DRAFT the service answers 409 with the remedy. */
  @Patch(':id/versions/:version')
  @RequiresAction(ACTION_WHISPER_SIGNAL_MANAGE)
  async updateDraft(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Param('version') version: string,
    @Body() body: unknown,
  ): Promise<WhisperSignalVersionView> {
    const principal = requirePrincipal(req);
    return this.whisper.updateDraft(principal, id, this.whisper.parseVersion(version), this.whisper.parseUpdateDraft(body));
  }

  /**
   * One section 14.5 lifecycle step. ACTIVE is refused here: activation needs a
   * distinct approver and a fingerprint binding, so it has its own route.
   */
  @Post(':id/versions/:version/transitions')
  @RequiresAction(ACTION_WHISPER_SIGNAL_MANAGE)
  async transition(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Param('version') version: string,
    @Body() body: unknown,
  ): Promise<WhisperSignalVersionView> {
    const principal = requirePrincipal(req);
    return this.whisper.transition(principal, id, this.whisper.parseVersion(version), this.whisper.parseTransition(body));
  }

  /** W21-12/W21-13: APPROVAL -> ACTIVE, by a second person, bound to the tested configuration. */
  @Post(':id/versions/:version/activate')
  @RequiresAction(ACTION_WHISPER_SIGNAL_APPROVE)
  async activate(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Param('version') version: string,
    @Body() body: unknown,
  ): Promise<WhisperSignalVersionView> {
    const principal = requirePrincipal(req);
    return this.whisper.activate(principal, id, this.whisper.parseVersion(version), this.whisper.parseActivate(body));
  }
}
