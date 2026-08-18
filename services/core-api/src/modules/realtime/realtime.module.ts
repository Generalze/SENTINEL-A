import { Module } from '@nestjs/common';
import { InfraModule } from '../../infra/infra.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { PresenceController } from './presence.controller';
import { PresenceRedisClient } from './presence-redis.client';
import { PresenceService } from './presence.service';
import { RealtimeNatsBridgeService } from './realtime-nats-bridge.service';
import { RealtimeGateway } from './realtime.gateway';

@Module({
  imports: [PrismaModule, InfraModule],
  controllers: [PresenceController],
  providers: [RealtimeGateway, RealtimeNatsBridgeService, PresenceService, PresenceRedisClient],
  // WP-18: field-messaging owns its own delivery semantics but needs the one
  // socket server to obtain transport evidence.
  exports: [RealtimeGateway],
})
export class RealtimeModule {}
