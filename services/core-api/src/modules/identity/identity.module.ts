import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule } from '../../config/config.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { AccessGuard } from './access.guard';
import { DevAuthGuard } from './dev-auth.guard';
import { OrganisationsController } from './organisations/organisations.controller';
import { OrganisationsService } from './organisations/organisations.service';
import { SitesController } from './sites/sites.controller';
import { SitesService } from './sites/sites.service';
import { UsersController } from './users/users.controller';
import { UsersService } from './users/users.service';
import { ZonesController } from './zones/zones.controller';
import { ZonesService } from './zones/zones.service';

/**
 * Registers DevAuthGuard then AccessGuard as global (APP_GUARD) guards —
 * order matters: DevAuthGuard populates `request.principal` first, and
 * AccessGuard's §62.1 checks depend on it. Nest applies multiple APP_GUARD
 * providers in registration order, so this array order IS the guard
 * execution order for every route in the application, not just this
 * module's own controllers.
 */
@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [OrganisationsController, SitesController, ZonesController, UsersController],
  providers: [
    OrganisationsService,
    SitesService,
    ZonesService,
    UsersService,
    { provide: APP_GUARD, useClass: DevAuthGuard },
    { provide: APP_GUARD, useClass: AccessGuard },
  ],
})
export class IdentityModule {}
