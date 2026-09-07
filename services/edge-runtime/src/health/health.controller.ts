import { Controller, Get, Inject, Res } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { EdgeHealthService } from './health.service';
import { statusToHttpCode } from './readiness.util';

/**
 * Edge's only HTTP surface this round, and both routes are deliberately
 * unauthenticated diagnostics that disclose nothing.
 *
 * Note what the readiness body cannot contain: no device id, no actor, no site,
 * no queued-operation detail, no clock reading. It is a map of dependency names
 * to up/down. Edge sits on a customer LAN, so this endpoint is reachable by
 * anything on that network, and it must stay boring.
 */
@Controller('health')
export class EdgeHealthController {
  constructor(@Inject(EdgeHealthService) private readonly healthService: EdgeHealthService) {}

  /**
   * Liveness: cheap, and touches NO dependency. It answers "is this process
   * running", which is the only question a restart policy should be asking. A
   * liveness probe that consults a dependency restarts a healthy Edge because
   * something else is unhappy.
   */
  @Get()
  liveness(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** Readiness: honest per-dependency status, 503 when any is down. Never throws. */
  @Get('ready')
  async readiness(@Res() res: ServerResponse): Promise<void> {
    const result = await this.healthService.checkReadiness();
    res.statusCode = statusToHttpCode(result.status);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(result));
  }
}
