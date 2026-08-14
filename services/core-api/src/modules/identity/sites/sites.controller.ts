import { Body, Controller, Get, Inject, Post, Query, Req } from '@nestjs/common';
import type { RequestWithPrincipal } from '../http-types';
import { ListQuerySchema, type ListPageResponse } from '../list-query';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateSiteSchema, toSiteResponse, type SiteResponse } from './site.dto';
import { SitesService } from './sites.service';

@Controller('api/v1/sites')
export class SitesController {
  constructor(@Inject(SitesService) private readonly sites: SitesService) {}

  @Post()
  @RequiresAction('site.admin')
  async create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<SiteResponse> {
    const principal = requirePrincipal(request);
    const dto = parseOrThrow(CreateSiteSchema, body);
    const site = await this.sites.create(principal, dto);
    return toSiteResponse(site);
  }

  /** WP-14/M4+M6: intersected with the caller's site scope, capped + cursor-paged. */
  @Get()
  @RequiresAction('site.admin')
  async list(@Req() request: RequestWithPrincipal, @Query() rawQuery: unknown): Promise<ListPageResponse<SiteResponse>> {
    const principal = requirePrincipal(request);
    const query = parseOrThrow(ListQuerySchema, rawQuery);
    const { items, next_cursor } = await this.sites.listForOrganisation(principal, query);
    return { items: items.map(toSiteResponse), next_cursor };
  }
}
