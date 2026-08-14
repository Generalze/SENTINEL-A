import { Module } from '@nestjs/common';
import { InfraModule } from '../infra/infra.module';
import { PrismaModule } from '../prisma/prisma.module';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [HealthController],
  providers: [HealthService],
})
export class HealthModule {}
