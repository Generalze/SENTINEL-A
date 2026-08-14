import { Inject, Injectable } from '@nestjs/common';
import type { User, UserRole } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import type { Principal } from '../principal';
import type { CreateUserDto } from './user.dto';

@Injectable()
export class UsersService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  create(principal: Principal, dto: CreateUserDto): Promise<User & { roles: UserRole[] }> {
    return this.prisma.user.create({
      data: {
        organisationId: principal.organisation_id,
        email: dto.email,
        displayName: dto.display_name,
        clearance: dto.clearance,
        roles: {
          create: dto.roles.map((assignment) => ({ role: assignment.role, siteId: assignment.site_id ?? null })),
        },
      },
      include: { roles: true },
    });
  }

  listForOrganisation(principal: Principal): Promise<Array<User & { roles: UserRole[] }>> {
    return this.prisma.user.findMany({
      where: { organisationId: principal.organisation_id },
      include: { roles: true },
    });
  }
}
