import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import type { RequestWithTraceId } from './common/http-types';
import { EdgeConfigModule } from './config/config.module';
import { EdgeConfigService } from './config/config.service';
import { EdgeHealthModule } from './health/health.module';
import { EdgeTrustedTimeModule } from './modules/trusted-time/trusted-time.module';

/**
 * WP-29B / EDGE-A — the Edge runtime's root module.
 *
 * What is NOT here is as deliberate as what is. There is no PrismaModule and no
 * database: Edge's durable store is a local queue, not a relational database,
 * and an Edge holding a DB connection would be an Edge that stops working when
 * the WAN does — which is the one thing it exists not to do. There is no
 * ThrottlerModule yet because Edge has no effect-causing route yet; it arrives
 * with EDGE-B's ingress, alongside the authentication argument for it.
 */
@Module({
  imports: [
    EdgeConfigModule,
    LoggerModule.forRootAsync({
      inject: [EdgeConfigService],
      useFactory: (config: EdgeConfigService) => ({
        pinoHttp: {
          level: config.values.LOG_LEVEL,
          // trace-id.middleware runs before this (raw app.use in main.ts), so
          // req.traceId is always already set by the time pino reads it.
          genReqId: (req: IncomingMessage): string => (req as RequestWithTraceId).traceId ?? randomUUID(),
          customProps: (req: IncomingMessage): Record<string, unknown> => ({
            trace_id: (req as RequestWithTraceId).traceId,
            // Edge identity on every line. `edge_id` is a registry identity, in
            // the D23-14 spirit: an operator correlating two sites' logs needs
            // to know which box spoke, and nothing about who it spoke for.
            edge_id: config.identity.edge_id,
          }),
        },
      }),
    }),
    EdgeHealthModule,
    EdgeTrustedTimeModule,
  ],
})
export class AppModule {}
