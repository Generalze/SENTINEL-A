import { Controller, Get } from '@nestjs/common';

interface HealthResponse {
  status: string;
}

@Controller()
export class HealthController {
  @Get('/health')
  health(): HealthResponse {
    return { status: 'ok' };
  }
}
