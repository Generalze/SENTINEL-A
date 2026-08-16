import { Module } from '@nestjs/common';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { FieldController } from './field.controller';
import { FieldOutboxPublisher } from './field-outbox.publisher';
import { FieldRepository } from './field.repository';
import { FieldService } from './field.service';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [FieldController],
  providers: [FieldRepository, FieldService, FieldOutboxPublisher],
  exports: [FieldService],
})
export class FieldModule {}
