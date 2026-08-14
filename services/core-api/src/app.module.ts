import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import type { RequestWithTraceId } from './common/http-types';
import { AppConfigService } from './config/config.service';
import { ConfigModule } from './config/config.module';
import { HealthModule } from './health/health.module';
import { InfraModule } from './infra/infra.module';
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
  ],
})
export class AppModule {}
