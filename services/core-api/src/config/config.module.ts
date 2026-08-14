import { Global, Module } from '@nestjs/common';
import { AppConfigService } from './config.service';

/**
 * Global so every feature module (logging, prisma, infra providers,
 * health) can inject AppConfigService without each re-importing this
 * module explicitly.
 */
@Global()
@Module({
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class ConfigModule {}
