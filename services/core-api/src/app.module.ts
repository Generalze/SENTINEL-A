import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
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
import { IncidentsModule } from './modules/incidents/incidents.module';
import { FieldModule } from './modules/field/field.module';
import { FieldMessagingModule } from './modules/field-messaging/field-messaging.module';
import { FieldOfflineModule } from './modules/field-offline/field-offline.module';
import { PatrolModule } from './modules/patrol/patrol.module';
import { WhisperModule } from './modules/whisper/whisper.module';

@Module({
  imports: [
    ConfigModule,
    // WP-14/M7+L2: a lenient default (only enforced on routes that opt in via
    // @UseGuards(ThrottlerGuard) — events ingest and organisation creation),
    // with per-route @Throttle overrides tightening specific endpoints.
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 300 }]),
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
    IncidentsModule,
    FieldModule,
    FieldMessagingModule,
    // WP-20 Checkpoint B. Registered for dependency wiring only: the module
    // declares no controller, so this adds no HTTP surface (C10-02).
    FieldOfflineModule,
    PatrolModule,
    // WP-21B. The controller it registers is STUDIO ONLY (signal lifecycle);
    // the recognition runtime is an exported service with no HTTP surface,
    // because an authenticated device context cannot come from a JSON body
    // (W21-05, the C10-02 boundary applied to a silent duress channel).
    WhisperModule,
  ],
})
export class AppModule {}
