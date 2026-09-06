import { Module } from '@nestjs/common';
import {
  IntervalOutboxPublishScheduler,
  OUTBOX_PUBLISH_SCHEDULER,
} from '../../common/scheduling/outbox-publish.scheduler';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { RealtimeModule } from '../realtime/realtime.module';
import { FieldMessagingConsumer } from './field-messaging.consumer';
import { FieldMessagingController } from './field-messaging.controller';
import { FieldMessagingOutboxPublisher } from './field-messaging-outbox.publisher';
import { FieldMessagingRepository } from './field-messaging.repository';
import { FieldMessagingService } from './field-messaging.service';

/**
 * WP-18 incident field messaging.
 *
 * Imports RealtimeModule for the one socket server, but keeps delivery
 * SEMANTICS here: the realtime module owns transport, this module owns what a
 * receipt means (C8-01).
 */
@Module({
  imports: [PrismaModule, InfraModule, RealtimeModule],
  controllers: [FieldMessagingController],
  providers: [
    FieldMessagingRepository,
    FieldMessagingService,
    FieldMessagingOutboxPublisher,
    FieldMessagingConsumer,
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
  exports: [FieldMessagingService],
})
export class FieldMessagingModule {}
