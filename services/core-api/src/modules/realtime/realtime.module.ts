import { Module } from '@nestjs/common';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { PresenceActionGuard } from './presence-action.guard';
import { PresenceController } from './presence.controller';
import { PresenceRedisClient } from './presence-redis.client';
import { PresenceService } from './presence.service';
import { RealtimeNatsBridgeService } from './realtime-nats-bridge.service';
import { RealtimeGateway } from './realtime.gateway';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [PresenceController],
  providers: [RealtimeGateway, RealtimeNatsBridgeService, PresenceService, PresenceRedisClient, PresenceActionGuard],
})
export class RealtimeModule {}
