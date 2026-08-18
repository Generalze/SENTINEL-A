import { Module } from '@nestjs/common';
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
  providers: [FieldMessagingRepository, FieldMessagingService, FieldMessagingOutboxPublisher, FieldMessagingConsumer],
  exports: [FieldMessagingService],
})
export class FieldMessagingModule {}
