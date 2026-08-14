import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import type { RequestWithPrincipal } from '../http-types';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateOrganisationSchema, toOrganisationResponse, type OrganisationResponse } from './organisation.dto';
import { OrganisationsService } from './organisations.service';

@Controller('api/v1/organisations')
export class OrganisationsController {
  constructor(private readonly organisations: OrganisationsService) {}

  @Post()
  @RequiresAction('org.admin')
  async create(@Body() body: unknown): Promise<OrganisationResponse> {
    const dto = parseOrThrow(CreateOrganisationSchema, body);
    const organisation = await this.organisations.create(dto);
    return toOrganisationResponse(organisation);
  }

  /** §39.2: "own org only" — always returns at most the caller's own organisation. */
  @Get()
  @RequiresAction('org.admin')
  async list(@Req() request: RequestWithPrincipal): Promise<OrganisationResponse[]> {
    const principal = requirePrincipal(request);
    const organisations = await this.organisations.listOwnOrganisation(principal);
    return organisations.map(toOrganisationResponse);
  }
}
