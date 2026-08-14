import { Controller, Get, Inject, Res } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { Public } from '../common/security/requires-action.decorator';
import { HealthService } from './health.service';
import { statusToHttpCode } from './readiness.util';

/**
 * WP-14: health probes are `@Public` so the global DevAuthGuard lets them
 * through with no principal — liveness/readiness must answer even when
 * `DEV_AUTH_ENABLED=false` (before the fix they 401'd).
 */
@Controller('health')
export class HealthController {
  constructor(@Inject(HealthService) private readonly healthService: HealthService) {}

  /** Liveness: always cheap, never calls a dependency. */
  @Get()
  @Public()
  liveness(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** Readiness: honestly reflects DB/NATS/Redis status; 503 if any is down. */
  @Get('ready')
  @Public()
  async readiness(@Res() res: ServerResponse): Promise<void> {
    const result = await this.healthService.checkReadiness();
    res.statusCode = statusToHttpCode(result.status);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(result));
  }
}
