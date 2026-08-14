import { Body, Controller, Get, Inject, Param, Post, Query, Req } from '@nestjs/common';
import type { RequestWithPrincipal } from '../http-types';
import { ListQuerySchema, type ListPageResponse } from '../list-query';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateZoneSchema, toZoneResponse, type ZoneResponse } from './zone.dto';
import { ZonesService } from './zones.service';

/**
 * Nested under sites: a Zone always belongs to a Site, and `:siteId` here
 * doubles as the site-scope value AccessGuard reads for the §62.1
 * site-scope conjunct. A `:siteId` belonging to another organisation is
 * rejected as a 404 by ZonesService (never revealed as 403 "forbidden").
 */
@Controller('api/v1/sites/:siteId/zones')
export class ZonesController {
  constructor(@Inject(ZonesService) private readonly zones: ZonesService) {}

  @Post()
  @RequiresAction('site.admin')
  async create(
    @Req() request: RequestWithPrincipal,
    @Param('siteId') siteId: string,
    @Body() body: unknown,
  ): Promise<ZoneResponse> {
    const principal = requirePrincipal(request);
    const dto = parseOrThrow(CreateZoneSchema, body);
    const zone = await this.zones.create(principal, siteId, dto);
    return toZoneResponse(zone);
  }

  @Get()
  @RequiresAction('site.admin')
  async list(
    @Req() request: RequestWithPrincipal,
    @Param('siteId') siteId: string,
    @Query() rawQuery: unknown,
  ): Promise<ListPageResponse<ZoneResponse>> {
    const principal = requirePrincipal(request);
    const query = parseOrThrow(ListQuerySchema, rawQuery);
    const { items, next_cursor } = await this.zones.listForSite(principal, siteId, query);
    return { items: items.map(toZoneResponse), next_cursor };
  }
}
