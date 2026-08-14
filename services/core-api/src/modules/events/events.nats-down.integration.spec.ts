import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { EventsController } from './events.controller';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { EventsService } from './events.service';
import { makeAppConfig, makeCapturingRes, principalRequest, uniqueOrgId } from './test-integration-support';
import { makeNormalisedEvent } from './test-fixtures';

/**
 * AC4, persistence half (live stack): "NATS down during ingest -> event
 * persists, published_at null."
 *
 * Per WP-04 coordination rules we must not stop the shared sentinel-nats
 * container (other concurrent agents depend on it). Instead "NATS down" is
 * simulated the way this repo already does it elsewhere (see
 * src/infra/nats.provider.spec.ts) — a NatsProvider pointed at an
 * unreachable address, scoped to this test file's own module setup.
 *
 * The retry-sweep-recovers half of AC4 is deliberately a SEPARATE file
 * (events.publish-sweep.integration.spec.ts) rather than continuing on
 * from a broken connection in this same process: empirically, the `nats`
 * client (v2.29.x) has a reconnect quirk where any `connect()` call made
 * in a process that has already seen one failed `connect()` (to any
 * address, not just the same one) stalls for ~25-30s before succeeding,
 * regardless of the `timeout` option passed. That's a library-level
 * behaviour under a rapid down-then-up transition within a single
 * process, not something this module's code controls, and it made a
 * combined down+recover test in one file flaky/slow. Keeping "persists
 * while down" and "sweep recovers once up" in separate files (and
 * therefore, under vitest's default per-file isolation, separate module
 * realms) avoids it while still proving both halves against live infra.
 */
describe('Event ingestion — persists when NATS is unreachable (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const repository = new EventsRepository(prisma);

  // Deliberately unreachable — this file's own module setup, per the
  // coordination rule to never stop the shared sentinel-nats container.
  const brokenNats = new NatsProvider(makeAppConfig({ NATS_URL: 'nats://127.0.0.1:4' }));
  const publisher = new EventsPublisherService(brokenNats);
  const controller = new EventsController(new EventsService(repository, publisher));

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
    await brokenNats.onModuleDestroy();
  });

  it('AC4: an event ingested while NATS is unreachable persists successfully with published_at left null', async () => {
    const orgId = trackOrg('ac4-down');
    const event = makeNormalisedEvent({ organisation_id: orgId });
    const req = principalRequest(orgId);
    const res = makeCapturingRes();

    await controller.ingest(req, event, res);

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.body ?? '{}') as { duplicate: boolean; event: { id: string; published_at: string | null } };
    expect(body.duplicate).toBe(false);
    expect(body.event.published_at).toBeNull();

    const row = await prisma.event.findUniqueOrThrow({ where: { id: body.event.id } });
    expect(row.publishedAt).toBeNull();
    expect(row.organisationId).toBe(orgId);
  });
});
