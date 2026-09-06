import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './common/global-exception.filter';
import { traceIdMiddleware } from './common/trace-id.middleware';
import { EdgeConfigService } from './config/config.service';
import { ConfigValidationError } from './config/env.schema';

/**
 * Hard cap on request body size, set explicitly rather than inherited, so the
 * bound is intentional and auditable. It is the same 1mb core-api uses: an
 * offline operation envelope plus its payload is far below it, and anything
 * larger is refused by the parser before a handler sees it.
 */
export const JSON_BODY_LIMIT = '1mb';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });

  app.useBodyParser('json', { limit: JSON_BODY_LIMIT });
  app.useBodyParser('urlencoded', { limit: JSON_BODY_LIMIT, extended: true });

  // Before Nest's module middleware (incl. pino-http), so trace_id has one
  // source of truth by the time anything logs or routes.
  app.use(traceIdMiddleware);

  app.useLogger(app.get(Logger));
  app.useGlobalFilters(new GlobalExceptionFilter());

  /**
   * GRACEFUL SHUTDOWN IS NOT COSMETIC ON AN EDGE.
   *
   * Edge holds queued Field operations that exist nowhere else while the WAN is
   * down. A process killed mid-write can leave a queue entry half-persisted,
   * and a half-persisted entry is one whose payload no longer digests to the
   * value the device signature covers — refused, hours later, with the original
   * bytes unrecoverable. Shutdown hooks give the queue lane an `onModuleDestroy`
   * in which to finish what it started.
   */
  app.enableShutdownHooks();

  const { values } = app.get(EdgeConfigService);
  await app.listen(values.PORT);
}

bootstrap().catch((error: unknown) => {
  if (error instanceof ConfigValidationError) {
    console.error(error.message);
  } else if (error instanceof Error) {
    console.error(`Failed to start Edge runtime: ${error.message}`);
  } else {
    console.error('Failed to start Edge runtime:', error);
  }
  process.exit(1);
});
