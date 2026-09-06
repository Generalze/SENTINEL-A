import { Module } from '@nestjs/common';
import { ConstitutionModule } from '../constitution/constitution.module';
import {
  IntervalOutboxPublishScheduler,
  OUTBOX_PUBLISH_SCHEDULER,
} from '../../common/scheduling/outbox-publish.scheduler';
import { EvidenceModule } from '../evidence/evidence.module';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { IncidentsConsumer } from './incidents.consumer';
import { IncidentsHypothesisConsumer } from './incidents-hypothesis.consumer';
import { IncidentsController } from './incidents.controller';
import { IncidentsPublisher } from './incidents.publisher';
import { IncidentsOutboxPublisher } from './incidents-outbox.publisher';
import { IncidentsRepository } from './incidents.repository';
import { IncidentsService } from './incidents.service';

@Module({
  imports: [PrismaModule, InfraModule, EvidenceModule, ConstitutionModule],
  controllers: [IncidentsController],
  providers: [
    IncidentsRepository,
    IncidentsPublisher,
    IncidentsOutboxPublisher,
    IncidentsService,
    IncidentsConsumer,
    IncidentsHypothesisConsumer,
    /**
     * TI-02: production always gets the real interval scheduler. This is one of
     * only three bindings of the token — one per publishing module, so each
     * publisher owns its own timer — and there is no env var and no config
     * field that can swap or silence any of them. A spec overrides the token
     * through `Test.createTestingModule(...).overrideProvider(...)`, which
     * reaches all three at once.
     */
    { provide: OUTBOX_PUBLISH_SCHEDULER, useClass: IntervalOutboxPublishScheduler },
  ],
  exports: [IncidentsService],
})
export class IncidentsModule {}
