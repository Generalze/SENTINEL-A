import { Body, Controller, Get, Inject, Post, Query, Req, UseGuards } from '@nestjs/common';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import type { RequestWithPrincipal } from '../http-types';
import { ListQuerySchema, type ListPageResponse } from '../list-query';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateOrganisationSchema, toOrganisationResponse, type OrganisationResponse } from './organisation.dto';
import { OrganisationsService } from './organisations.service';

@Controller('api/v1/organisations')
export class OrganisationsController {
  constructor(@Inject(OrganisationsService) private readonly organisations: OrganisationsService) {}

  /**
   * WP-14/L2: creating an organisation mints a brand-new top-level tenant, so
   * it is rate-limited (a strict per-caller cap) to stop an admin minting
   * unbounded orphan tenants. It still requires the `org.admin` action.
   */
  @Post()
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 3_600_000 } })
  @RequiresAction('org.admin')
  async create(@Body() body: unknown): Promise<OrganisationResponse> {
    const dto = parseOrThrow(CreateOrganisationSchema, body);
    const organisation = await this.organisations.create(dto);
    return toOrganisationResponse(organisation);
  }

  /** §39.2: "own org only" — always returns at most the caller's own organisation. Capped + cursor-paged (M6). */
  @Get()
  @RequiresAction('org.admin')
  async list(@Req() request: RequestWithPrincipal, @Query() rawQuery: unknown): Promise<ListPageResponse<OrganisationResponse>> {
    const principal = requirePrincipal(request);
    const query = parseOrThrow(ListQuerySchema, rawQuery);
    const { items, next_cursor } = await this.organisations.listOwnOrganisation(principal, query);
    return { items: items.map(toOrganisationResponse), next_cursor };
  }
}
