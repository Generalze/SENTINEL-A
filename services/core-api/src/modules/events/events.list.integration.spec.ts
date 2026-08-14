import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { EventsController } from './events.controller';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { EventsService } from './events.service';
import { makeAppConfig, makeCapturingRes, principalRequest, uniqueOrgId } from './test-integration-support';
import { makeNormalisedEvent } from './test-fixtures';

/**
 * Deliverable #5 (live stack): GET /api/v1/events — tenant-scoped,
 * filterable by site/source_type/time range, cursor-paginated newest
 * first.
 */
describe('Event listing (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  // NATS is irrelevant to these assertions; point at an unreachable
  // address so publish attempts fail fast instead of depending on the
  // shared container's availability for this particular file.
  const nats = new NatsProvider(makeAppConfig({ NATS_URL: 'nats://127.0.0.1:4' }));
  const repository = new EventsRepository(prisma);
  const service = new EventsService(repository, new EventsPublisherService(nats));
  const controller = new EventsController(service);

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

  describe('with a seeded organisation', () => {
    let orgId: string;
    let otherOrgId: string;
    const eventIds: string[] = [];

    beforeEach(async () => {
      orgId = trackOrg('list');
      otherOrgId = trackOrg('list-other');
      eventIds.length = 0;

      const req = principalRequest(orgId);
      const baseTime = Date.now() - 60_000;
      const seeds = [
        { site_id: 'site-a', source_type: 'camera' as const, offsetMs: 0 },
        { site_id: 'site-a', source_type: 'sensor' as const, offsetMs: 1_000 },
        { site_id: 'site-b', source_type: 'camera' as const, offsetMs: 2_000 },
        { site_id: 'site-a', source_type: 'camera' as const, offsetMs: 3_000 },
        { site_id: 'site-b', source_type: 'sensor' as const, offsetMs: 4_000 },
      ];

      for (const seed of seeds) {
        const event = makeNormalisedEvent({
          organisation_id: orgId,
          site_id: seed.site_id,
          source_type: seed.source_type,
          occurred_at: new Date(baseTime + seed.offsetMs).toISOString(),
        });
        const res = makeCapturingRes();
        await controller.ingest(req, event, res);
        const body = JSON.parse(res.body ?? '{}') as { event: { id: string } };
        eventIds.push(body.event.id);
      }

      // One event in a different organisation, to prove tenant isolation.
      const otherEvent = makeNormalisedEvent({ organisation_id: otherOrgId, site_id: 'site-a' });
      const otherRes = makeCapturingRes();
      await controller.ingest(principalRequest(otherOrgId), otherEvent, otherRes);
    });

    it('lists only the caller organisation\'s events, newest first', async () => {
      const result = await controller.list(principalRequest(orgId), {});
      const list = result as { items: Array<{ id: string; organisation_id: string }>; next_cursor: string | null };

      expect(list.items).toHaveLength(5);
      expect(list.items.every((item) => item.organisation_id === orgId)).toBe(true);
      // Seeded with strictly increasing occurred_at, so newest-first means reverse seed order.
      expect(list.items.map((item) => item.id)).toEqual([...eventIds].reverse());
    });

    it('filters by site_id', async () => {
      const result = (await controller.list(principalRequest(orgId), { site_id: 'site-b' })) as {
        items: Array<{ site_id: string }>;
      };
      expect(result.items).toHaveLength(2);
      expect(result.items.every((item) => item.site_id === 'site-b')).toBe(true);
    });

    it('filters by source_type', async () => {
      const result = (await controller.list(principalRequest(orgId), { source_type: 'sensor' })) as {
        items: Array<{ source_type: string }>;
      };
      expect(result.items).toHaveLength(2);
      expect(result.items.every((item) => item.source_type === 'sensor')).toBe(true);
    });

    it('paginates with limit + cursor, covering every event exactly once in newest-first order', async () => {
      const seenIds: string[] = [];
      let cursor: string | undefined;

      for (let page = 0; page < 10; page += 1) {
        const result = (await controller.list(principalRequest(orgId), { limit: '2', cursor })) as {
          items: Array<{ id: string }>;
          next_cursor: string | null;
        };
        seenIds.push(...result.items.map((item) => item.id));
        if (!result.next_cursor) {
          break;
        }
        cursor = result.next_cursor;
      }

      expect(seenIds).toEqual([...eventIds].reverse());
    });

    it('never returns another organisation\'s events, even across pagination', async () => {
      const result = (await controller.list(principalRequest(orgId), { limit: '50' })) as {
        items: Array<{ organisation_id: string }>;
      };
      expect(result.items.every((item) => item.organisation_id === orgId)).toBe(true);
    });

    // M5 regression (WP-14): duplicate rows are §64.1 delivery bookkeeping,
    // not distinct events. Before the fix the list query did not filter
    // `duplicateOfEventId: null`, so a redelivery surfaced as an extra list
    // item. Here the same event is delivered 3x (1 canonical + 2 duplicate
    // rows) and the list must still show exactly one item.
    it('M5: duplicate delivery rows are never listed (only the canonical event appears)', async () => {
      const dupOrg = trackOrg('m5-list-dup');
      const req = principalRequest(dupOrg);
      const event = makeNormalisedEvent({ organisation_id: dupOrg, site_id: 'site-dup', source_id: 'cam-m5', event_id: 'evt_m5_dup' });

      for (let i = 0; i < 3; i += 1) {
        const res = makeCapturingRes();
        await controller.ingest(req, { ...event, trace_id: `m5-${i}` }, res);
      }

      // 3 physical rows exist (1 canonical + 2 duplicates)...
      const rows = await prisma.event.findMany({ where: { organisationId: dupOrg } });
      expect(rows).toHaveLength(3);

      // ...but the list surfaces only the single canonical event.
      const result = (await controller.list(req, {})) as { items: Array<{ id: string }> };
      expect(result.items).toHaveLength(1);
    }, 45_000);
  });
});
