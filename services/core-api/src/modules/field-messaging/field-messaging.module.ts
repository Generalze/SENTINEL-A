import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { FieldMessagingController } from './field-messaging.controller';
import { FieldMessagingRepository } from './field-messaging.repository';
import { FieldMessagingService } from './field-messaging.service';

/**
 * WP-18 incident field messaging. Realtime publication is deliberately absent
 * at this checkpoint: outbox rows are written transactionally, but the
 * publisher and per-user socket routing are the next implementation stage.
 */
@Module({
  imports: [PrismaModule],
  controllers: [FieldMessagingController],
  providers: [FieldMessagingRepository, FieldMessagingService],
  exports: [FieldMessagingService],
})
export class FieldMessagingModule {}
