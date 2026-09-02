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
import { DeviceEnrollmentIngressModule } from './modules/device-enrollment-ingress/device-enrollment-ingress.module';
import { DeviceGatewayModule } from './modules/device-gateway/device-gateway.module';
import { ShieldModule } from './modules/shield/shield.module';
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
    // WP-24 Shield device registry. Registered for dependency wiring only: the
    // module declares NO controller, so this adds no HTTP surface at all
    // (D24-13). There is still no production facility that authenticates an
    // incoming physical device, and WP-25 is the work package that lifts that
    // prohibition.
    ShieldModule,
    // WP-25 Authenticated Device Gateway. THIS is the lift, and it is the FIRST
    // device-facing HTTP surface in Sentinel. Every effect-causing route it
    // registers is authenticated by a fresh hardware-signed DeviceRequestProof
    // and by nothing else: there is no device bearer token, no device session
    // and no authenticated-socket path (D25-01, D25-10). See
    // device-gateway.controller.ts for what the boundary refuses.
    DeviceGatewayModule,
    // WP-26 Field Mobile Foundation — the device enrollment ingress. It is the
    // PRE-REGISTRATION surface, and the counterpart to the gateway above: the
    // gateway serves a device that is already registered, this serves the
    // ceremony that registers one. Neither route on it is `@Public()` and
    // neither authenticates the device — a phone holding a key registered
    // nowhere cannot be authenticated, which is the reason the two-human
    // ceremony exists rather than a gap in it (D26-01). It also owns the
    // Command-side transport for bootstrap issuance and approval, so Shield
    // keeps its property of having zero controllers (D24-13/D26-09).
    DeviceEnrollmentIngressModule,
  ],
})
export class AppModule {}
