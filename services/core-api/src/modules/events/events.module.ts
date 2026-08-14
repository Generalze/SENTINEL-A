import { Module } from '@nestjs/common';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { EventsController } from './events.controller';
import { EventsPublishSweepService } from './events-publish-sweep.service';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { EventsService } from './events.service';
import { PrincipalActionGuard } from './principal-action.guard';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [EventsController],
  providers: [EventsRepository, EventsPublisherService, EventsPublishSweepService, EventsService, PrincipalActionGuard],
})
export class EventsModule {}
