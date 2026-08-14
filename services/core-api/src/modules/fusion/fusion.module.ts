import { Module } from '@nestjs/common';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { FusionConsumerService } from './fusion-consumer.service';
import { FusionController } from './fusion.controller';
import { FusionPrincipalActionGuard } from './fusion-principal-action.guard';
import { FusionPublisherService } from './fusion-publisher.service';
import { FusionRepository } from './fusion.repository';
import { FusionService } from './fusion.service';

/**
 * Sentinel Fusion v1 (WP-05, architecture §11 / §65).
 *
 * Consumes `sentinel.events.>`, correlates events into hypotheses, assesses
 * them with the certified threat-state core, and publishes hypothesis updates
 * and incident-candidates. Depends only on the shared Prisma and Infra
 * modules — it reads no other domain module's code or tables.
 */
@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [FusionController],
  providers: [
    FusionRepository,
    FusionPublisherService,
    FusionService,
    FusionConsumerService,
    FusionPrincipalActionGuard,
  ],
  exports: [FusionService],
})
export class FusionModule {}
