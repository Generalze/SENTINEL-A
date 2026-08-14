import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { Site, Zone } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';
import type { CreateZoneDto } from './zone.dto';

@Injectable()
export class ZonesService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * §39.2 / deliverable #5: a site id that doesn't exist and a site id
   * that belongs to a different organisation are indistinguishable to the
   * caller — both throw a plain 404 so cross-org access never reveals
   * that the resource exists.
   */
  private async requireSiteInOwnOrganisation(principal: Principal, siteId: string): Promise<Site> {
    const site = await this.prisma.site.findFirst({
      where: { id: siteId, organisationId: principal.organisation_id },
    });
    if (!site) {
      throw new NotFoundException('Site not found');
    }
    return site;
  }

  async create(principal: Principal, siteId: string, dto: CreateZoneDto): Promise<Zone> {
    await this.requireSiteInOwnOrganisation(principal, siteId);
    return this.prisma.zone.create({ data: { name: dto.name, siteId } });
  }

  async listForSite(principal: Principal, siteId: string): Promise<Zone[]> {
    await this.requireSiteInOwnOrganisation(principal, siteId);
    return this.prisma.zone.findMany({ where: { siteId } });
  }
}
