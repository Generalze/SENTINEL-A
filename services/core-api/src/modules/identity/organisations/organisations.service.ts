import { Inject, Injectable } from '@nestjs/common';
import type { Organisation } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';
import type { CreateOrganisationDto } from './organisation.dto';

@Injectable()
export class OrganisationsService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  create(dto: CreateOrganisationDto): Promise<Organisation> {
    return this.prisma.organisation.create({ data: { name: dto.name } });
  }

  /** §39.2: never list beyond the caller's own tenant — this always resolves to at most the principal's own organisation. */
  listOwnOrganisation(principal: Principal): Promise<Organisation[]> {
    return this.prisma.organisation.findMany({ where: { id: principal.organisation_id } });
  }
}
