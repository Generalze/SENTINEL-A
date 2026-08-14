import { Inject, Injectable } from '@nestjs/common';
import type { Organisation } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { resolveListPage, type ListPageQuery, type ListPageResult } from '../list-pagination';
import type { Principal } from '../principal';
import type { CreateOrganisationDto } from './organisation.dto';

@Injectable()
export class OrganisationsService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  create(dto: CreateOrganisationDto): Promise<Organisation> {
    return this.prisma.organisation.create({ data: { name: dto.name } });
  }

  /**
   * §39.2: never list beyond the caller's own tenant — this always resolves
   * to at most the principal's own organisation. WP-14/M6: still capped +
   * cursor-paged for a uniform, bounded list contract.
   */
  async listOwnOrganisation(principal: Principal, query: ListPageQuery = {}): Promise<ListPageResult<Organisation>> {
    const page = resolveListPage(query);
    const rows = await this.prisma.organisation.findMany({
      where: { id: principal.organisation_id },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: page.limit + 1,
      ...(page.cursor ? { cursor: { id: page.cursor }, skip: 1 } : {}),
    });
    return page.toResult(rows);
  }
}
