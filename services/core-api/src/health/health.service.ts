import { Inject, Injectable } from '@nestjs/common';
import { NatsProvider } from '../infra/nats.provider';
import { RedisProvider } from '../infra/redis.provider';
import { PrismaService } from '../prisma/prisma.service';
import type { DependencyStatus, ReadinessDependencies, ReadinessResult } from './health.types';
import { computeReadinessStatus, guardedProbe } from './readiness.util';

@Injectable()
export class HealthService {
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(RedisProvider) private readonly redis: RedisProvider,
  ) {}

  private async checkDatabase(): Promise<DependencyStatus> {
    await this.prisma.$queryRaw`SELECT 1`;
    return 'up';
  }

  async checkReadiness(): Promise<ReadinessResult> {
    const [database, nats, redis] = await Promise.all([
      guardedProbe(() => this.checkDatabase()),
      guardedProbe(() => this.nats.checkHealth()),
      guardedProbe(() => this.redis.checkHealth()),
    ]);

    const dependencies: ReadinessDependencies = { database, nats, redis };
    return { status: computeReadinessStatus(dependencies), dependencies };
  }
}
