import { Inject, Injectable } from '@nestjs/common';
import type { Site } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';
import type { CreateSiteDto } from './site.dto';

@Injectable()
export class SitesService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  create(principal: Principal, dto: CreateSiteDto): Promise<Site> {
    return this.prisma.site.create({
      data: { name: dto.name, organisationId: principal.organisation_id },
    });
  }

  listForOrganisation(principal: Principal): Promise<Site[]> {
    return this.prisma.site.findMany({ where: { organisationId: principal.organisation_id } });
  }
}
