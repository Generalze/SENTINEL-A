import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { Site, Zone } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { intersectSiteScope, resolveListPage, type ListPageQuery, type ListPageResult } from '../list-pagination';
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
   *
   * WP-14/M4: the same 404 also hides a site that IS in the caller's org but
   * outside the caller's site-scoped grants — a site-scoped `site.admin`
   * must not be able to probe or read zones of a site it was not granted.
   */
  private async requireSiteInScope(principal: Principal, siteId: string): Promise<Site> {
    const site = await this.prisma.site.findFirst({
      where: { id: siteId, organisationId: principal.organisation_id },
    });
    if (!site) {
      throw new NotFoundException('Site not found');
    }
    const scope = intersectSiteScope(principal, 'site.admin');
    if (!scope.orgWide && !scope.siteIds.includes(siteId)) {
      throw new NotFoundException('Site not found');
    }
    return site;
  }

  async create(principal: Principal, siteId: string, dto: CreateZoneDto): Promise<Zone> {
    await this.requireSiteInScope(principal, siteId);
    return this.prisma.zone.create({ data: { name: dto.name, siteId } });
  }

  /** WP-14/M6: capped + cursor-paged (site membership is already enforced above). */
  async listForSite(principal: Principal, siteId: string, query: ListPageQuery = {}): Promise<ListPageResult<Zone>> {
    await this.requireSiteInScope(principal, siteId);
    const page = resolveListPage(query);
    const rows = await this.prisma.zone.findMany({
      where: { siteId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: page.limit + 1,
      ...(page.cursor ? { cursor: { id: page.cursor }, skip: 1 } : {}),
    });
    return page.toResult(rows);
  }
}
