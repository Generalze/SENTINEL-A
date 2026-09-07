import { Global, Module } from '@nestjs/common';
import { EdgeConfigService } from './config.service';

/** Global so logging, health and the trusted-time lane all inject it without re-importing. */
@Global()
@Module({
  providers: [EdgeConfigService],
  exports: [EdgeConfigService],
})
export class EdgeConfigModule {}
