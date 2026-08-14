import { Test, TestingModule } from '@nestjs/testing';
import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';
import type { ReadinessResult } from './health.types';

function makeRes(): ServerResponse & { statusCode: number; body?: string } {
  const res = {
    setHeader: vi.fn(),
    end: vi.fn(function (this: { body?: string }, chunk: string) {
      this.body = chunk;
    }),
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string };
}

describe('HealthController', () => {
  it('GET /health returns { status: "ok" } without calling any dependency', async () => {
    const checkReadiness = vi.fn();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [{ provide: HealthService, useValue: { checkReadiness } }],
    }).compile();

    const controller = module.get(HealthController);
    expect(controller.liveness()).toEqual({ status: 'ok' });
    expect(checkReadiness).not.toHaveBeenCalled();
  });

  it('GET /health/ready returns 200 and the readiness body when all dependencies are up', async () => {
    const readiness: ReadinessResult = {
      status: 'ok',
      dependencies: { database: 'up', nats: 'up', redis: 'up' },
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        { provide: HealthService, useValue: { checkReadiness: vi.fn().mockResolvedValue(readiness) } },
      ],
    }).compile();

    const controller = module.get(HealthController);
    const res = makeRes();
    await controller.readiness(res);

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body ?? '{}')).toEqual(readiness);
  });

  it('GET /health/ready returns 503 when a dependency is down', async () => {
    const readiness: ReadinessResult = {
      status: 'degraded',
      dependencies: { database: 'up', nats: 'up', redis: 'down' },
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        { provide: HealthService, useValue: { checkReadiness: vi.fn().mockResolvedValue(readiness) } },
      ],
    }).compile();

    const controller = module.get(HealthController);
    const res = makeRes();
    await controller.readiness(res);

    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body ?? '{}')).toEqual(readiness);
  });
});
