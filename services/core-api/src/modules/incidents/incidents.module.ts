import { Module } from '@nestjs/common';
import { ConstitutionModule } from '../constitution/constitution.module';
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
  providers: [IncidentsRepository, IncidentsPublisher, IncidentsOutboxPublisher, IncidentsService, IncidentsConsumer, IncidentsHypothesisConsumer],
  exports: [IncidentsService],
})
export class IncidentsModule {}
