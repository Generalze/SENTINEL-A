import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './common/global-exception.filter';
import { traceIdMiddleware } from './common/trace-id.middleware';
import { GlobalValidationPipe } from './common/validation.pipe';
import { AppConfigService } from './config/config.service';
import { ConfigValidationError } from './config/env.schema';

/** WP-14/M7: hard cap on request body size. Comfortably above the event
 * contract's own metadata/location caps, but bounded so an oversized payload
 * is rejected by the parser before any handler sees it. */
export const JSON_BODY_LIMIT = '1mb';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });

  // WP-14/M7: explicit JSON/urlencoded body-size limit (default is Express's
  // 100kb, but set it explicitly so the bound is intentional and auditable).
  app.useBodyParser('json', { limit: JSON_BODY_LIMIT });
  app.useBodyParser('urlencoded', { limit: JSON_BODY_LIMIT, extended: true });

  // Raw Express middleware, registered before Nest's own module-based
  // middleware (incl. pino-http), so it is the single source of truth
  // for trace_id by the time any logging or routing happens.
  app.use(traceIdMiddleware);

  app.useLogger(app.get(Logger));
  app.useGlobalPipes(new GlobalValidationPipe());
  app.useGlobalFilters(new GlobalExceptionFilter());
  app.enableShutdownHooks();

  const { values } = app.get(AppConfigService);
  await app.listen(values.PORT);
}

bootstrap().catch((error: unknown) => {
  if (error instanceof ConfigValidationError) {
    console.error(error.message);
  } else if (error instanceof Error) {
    console.error(`Failed to start application: ${error.message}`);
  } else {
    console.error('Failed to start application:', error);
  }
  process.exit(1);
});
