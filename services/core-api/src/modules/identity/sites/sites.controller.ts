import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import type { RequestWithPrincipal } from '../http-types';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateSiteSchema, toSiteResponse, type SiteResponse } from './site.dto';
import { SitesService } from './sites.service';

@Controller('api/v1/sites')
export class SitesController {
  constructor(private readonly sites: SitesService) {}

  @Post()
  @RequiresAction('site.admin')
  async create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<SiteResponse> {
    const principal = requirePrincipal(request);
    const dto = parseOrThrow(CreateSiteSchema, body);
    const site = await this.sites.create(principal, dto);
    return toSiteResponse(site);
  }

  @Get()
  @RequiresAction('site.admin')
  async list(@Req() request: RequestWithPrincipal): Promise<SiteResponse[]> {
    const principal = requirePrincipal(request);
    const sites = await this.sites.listForOrganisation(principal);
    return sites.map(toSiteResponse);
  }
}
