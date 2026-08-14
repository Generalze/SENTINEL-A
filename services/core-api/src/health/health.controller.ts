import { Controller, Get, Inject, Res } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { HealthService } from './health.service';
import { statusToHttpCode } from './readiness.util';

@Controller('health')
export class HealthController {
  constructor(@Inject(HealthService) private readonly healthService: HealthService) {}

  /** Liveness: always cheap, never calls a dependency. */
  @Get()
  liveness(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** Readiness: honestly reflects DB/NATS/Redis status; 503 if any is down. */
  @Get('ready')
  async readiness(@Res() res: ServerResponse): Promise<void> {
    const result = await this.healthService.checkReadiness();
    res.statusCode = statusToHttpCode(result.status);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(result));
  }
}
