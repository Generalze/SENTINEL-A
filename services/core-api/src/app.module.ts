import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import type { RequestWithTraceId } from './common/http-types';
import { AppConfigService } from './config/config.service';
import { ConfigModule } from './config/config.module';
import { EventsModule } from './modules/events/events.module';
import { FusionModule } from './modules/fusion/fusion.module';
import { HealthModule } from './health/health.module';
import { IdentityModule } from './modules/identity/identity.module';
import { InfraModule } from './infra/infra.module';
import { ConstitutionModule } from './modules/constitution/constitution.module';
import { EvidenceModule } from './modules/evidence/evidence.module';
import { LedgerModule } from './modules/ledger/ledger.module';
import { RealtimeModule } from './modules/realtime/realtime.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [
    ConfigModule,
    LoggerModule.forRootAsync({
      inject: [AppConfigService],
      useFactory: (appConfig: AppConfigService) => ({
        pinoHttp: {
          level: appConfig.values.LOG_LEVEL,
          // trace-id.middleware runs before this (registered via raw
          // app.use in main.ts), so req.traceId is always already set.
          genReqId: (req: IncomingMessage): string => (req as RequestWithTraceId).traceId ?? randomUUID(),
          customProps: (req: IncomingMessage): Record<string, unknown> => ({
            trace_id: (req as RequestWithTraceId).traceId,
          }),
        },
      }),
    }),
    PrismaModule,
    InfraModule,
    HealthModule,
    EventsModule,
    IdentityModule,
    ConstitutionModule,
    EvidenceModule,
    LedgerModule,
    RealtimeModule,
    FusionModule,
  ],
})
export class AppModule {}
