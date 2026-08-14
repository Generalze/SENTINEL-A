import { Inject, Injectable } from '@nestjs/common';
import type { Site } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { intersectSiteScope, resolveListPage, type ListPageQuery, type ListPageResult } from '../list-pagination';
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

  /**
   * WP-14/M4+M6: tenant-scoped, site-scope-intersected, capped + cursor-paged.
   * A site-scoped `site.admin` sees only the sites its grants name; an
   * org-wide grant sees every site in the organisation.
   */
  async listForOrganisation(principal: Principal, query: ListPageQuery = {}): Promise<ListPageResult<Site>> {
    const scope = intersectSiteScope(principal, 'site.admin');
    const page = resolveListPage(query);
    const rows = await this.prisma.site.findMany({
      where: {
        organisationId: principal.organisation_id,
        ...(scope.orgWide ? {} : { id: { in: scope.siteIds } }),
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: page.limit + 1,
      ...(page.cursor ? { cursor: { id: page.cursor }, skip: 1 } : {}),
    });
    return page.toResult(rows);
  }
}
