import { Module } from '@nestjs/common';
import {
  IntervalOutboxPublishScheduler,
  OUTBOX_PUBLISH_SCHEDULER,
} from '../../common/scheduling/outbox-publish.scheduler';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { FieldController } from './field.controller';
import { FieldOutboxPublisher } from './field-outbox.publisher';
import { FieldRepository } from './field.repository';
import { FieldService } from './field.service';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [FieldController],
  providers: [
    FieldRepository,
    FieldService,
    FieldOutboxPublisher,
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
  exports: [FieldService],
})
export class FieldModule {}
