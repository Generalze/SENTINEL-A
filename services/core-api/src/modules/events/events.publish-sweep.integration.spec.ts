import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { EventsPublishSweepService } from './events-publish-sweep.service';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { makeAppConfig, uniqueOrgId } from './test-integration-support';
import { makeNormalisedEvent } from './test-fixtures';

/**
 * AC4, recovery half (live stack): "retry sweep publishes when NATS
 * returns." Deliberately its own file, using only the real, live NATS
 * connection (localhost:4222) — see the class doc in
 * events.nats-down.integration.spec.ts for why the down/up transition is
 * split across two files rather than done end-to-end in one process.
 *
 * A row is inserted directly as "unpublished and overdue" (the same
 * end-state a failed publish-after-commit would have left behind,
 * regardless of what caused the earlier failure), and the sweep is run
 * directly to prove it republishes and marks the row published.
 */
describe('EventsPublishSweepService republishes overdue rows (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const repository = new EventsRepository(prisma);
  const nats = new NatsProvider(appConfig);
  const publisher = new EventsPublisherService(nats);
  const sweepService = new EventsPublishSweepService(repository, publisher);

  const createdOrgIds: string[] = [];
  function trackOrg(label: string): string {
    const id = uniqueOrgId(label);
    createdOrgIds.push(id);
    return id;
  }

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterEach(async () => {
    if (createdOrgIds.length > 0) {
      await prisma.event.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      createdOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
    await nats.onModuleDestroy();
  });

  it('AC4: republishes an overdue unpublished row and marks it published', async () => {
    const orgId = trackOrg('ac4-sweep');
    const event = makeNormalisedEvent({ organisation_id: orgId });

    const created = await repository.createCanonical(event, `it-sweep-key-${Date.now()}`);
    // Backdate straight through Prisma (test-only fixture setup, not part
    // of the service layer) so the row looks overdue to the sweep's
    // cutoff query without sleeping 15+ real seconds in the test.
    await prisma.event.update({ where: { id: created.id }, data: { createdAt: new Date(Date.now() - 20_000) } });

    const republished = await sweepService.sweep();
    expect(republished).toBeGreaterThanOrEqual(1);

    const row = await prisma.event.findUniqueOrThrow({ where: { id: created.id } });
    expect(row.publishedAt).not.toBeNull();
  }, 45_000);
  // Generous timeout: this file's very first live `connect()` call can
  // observably take up to ~25-30s (instead of the 1.5s CONNECT_TIMEOUT_MS)
  // when other concurrently-running test files in this same vitest worker
  // process have recently produced ECONNREFUSED connects (see the broken
  // NatsProvider used by events.nats-down/events.list integration specs).
  // Reproduced independently of this codebase with a bare `nats` client
  // script; it's an environment/OS+nats.js-client interaction under rapid
  // connection-refused churn, not a bug in EventsPublisherService/
  // EventsPublishSweepService. Both are already fully covered by
  // deterministic, fast, mocked unit tests (events-publish-sweep.service.spec.ts);
  // this file exists to additionally prove a real JetStream publish
  // succeeds end-to-end, so it tolerates real-network variance.
});
