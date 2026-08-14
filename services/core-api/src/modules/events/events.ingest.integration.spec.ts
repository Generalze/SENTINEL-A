import { Logger } from '@nestjs/common';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { EventsController } from './events.controller';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { EventsService } from './events.service';
import { makeAppConfig, makeCapturingRes, principalRequest, uniqueOrgId } from './test-integration-support';
import { makeNormalisedEvent } from './test-fixtures';

/**
 * Live-stack integration tests for WP-04 acceptance criteria 1-3. Requires
 * the compose stack's Postgres (localhost:5433) and NATS (localhost:4222)
 * to be reachable — both are up as part of this dev environment.
 *
 * Exercises the real EventsController -> EventsService -> EventsRepository
 * -> PrismaService stack (constructed directly, the same way this repo's
 * other provider tests bypass full Nest DI bootstrap) so persistence
 * assertions are against the actual database, not a mock.
 */
describe('Event ingestion (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const nats = new NatsProvider(appConfig);
  const repository = new EventsRepository(prisma);
  const publisher = new EventsPublisherService(nats);
  const service = new EventsService(repository, publisher);
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
    // Test-only teardown, not part of the service layer's mutation
    // surface (this file is excluded from the append-only grep check by
    // its *.spec.ts name, same as every other test in this module).
    if (createdOrgIds.length > 0) {
      await prisma.event.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      createdOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
    await nats.onModuleDestroy();
  });

  it('AC1: the same event delivered 3x yields one canonical row (received_count=3) and 2 linked duplicate rows, with no delivery data lost', async () => {
    const orgId = trackOrg('ac1');
    const base = makeNormalisedEvent({ organisation_id: orgId, source_id: 'camera-ac1', event_id: 'evt_ac1_fixed' });
    const req = principalRequest(orgId);
    const statuses: number[] = [];

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = makeCapturingRes();
      // Sequential on purpose: this simulates 3 real redeliveries of the
      // same event, each carrying its own trace_id, arriving one after
      // another (as an at-least-once transport would resend them).
      await controller.ingest(req, { ...base, trace_id: `trace-ac1-${attempt}` }, res);
      statuses.push(res.statusCode);
    }

    expect(statuses).toEqual([201, 200, 200]);

    const rows = await prisma.event.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(3);

    const canonical = rows.find((row) => row.duplicateOfEventId === null);
    const duplicates = rows.filter((row) => row.duplicateOfEventId !== null);

    expect(canonical).toBeDefined();
    expect(canonical?.receivedCount).toBe(3);
    expect(canonical?.idempotencyKey).not.toBeNull();
    expect(duplicates).toHaveLength(2);
    for (const duplicate of duplicates) {
      expect(duplicate.duplicateOfEventId).toBe(canonical?.id);
      expect(duplicate.idempotencyKey).toBeNull();
    }

    // "no data about redelivery is lost": every delivery's distinguishing
    // trace_id survives, across the 3 rows.
    expect(rows.map((row) => row.traceId).sort()).toEqual(['trace-ac1-0', 'trace-ac1-1', 'trace-ac1-2']);
  }, 45_000); // 3 sequential real JetStream publishes; the default 5s budget is too tight under parallel test-file load
  // (see events.publish-sweep.integration.spec.ts for why the first live `connect()` in a
  // worker process can occasionally take up to ~25-30s here).

  it('AC2: an invalid event (bad confidence, missing trace_id) is rejected 400 with field-level errors and nothing is persisted', async () => {
    const orgId = trackOrg('ac2');
    const valid = makeNormalisedEvent({ organisation_id: orgId });
    const invalidBody: Record<string, unknown> = { ...valid, confidence: 1.5 };
    delete invalidBody.trace_id;

    const req = principalRequest(orgId);
    const res = makeCapturingRes();

    await controller.ingest(req, invalidBody, res);

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body ?? '{}') as { error: string; field_errors: string[] };
    expect(body.error).toBe('Invalid event payload');
    expect(body.field_errors.some((line) => line.startsWith('confidence'))).toBe(true);
    expect(body.field_errors.some((line) => line.startsWith('trace_id'))).toBe(true);

    const rows = await prisma.event.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(0);
  });

  it('AC3: an org-mismatch injection attempt is denied 404, nothing is persisted, and the denial is logged', async () => {
    const bodyOrg = trackOrg('ac3-body');
    const principalOrg = trackOrg('ac3-principal');
    const event = makeNormalisedEvent({ organisation_id: bodyOrg });
    const req = principalRequest(principalOrg);
    const res = makeCapturingRes();
    const warnSpy = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);

    try {
      await controller.ingest(req, event, res);

      expect(res.statusCode).toBe(404);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('organisation mismatch'));

      const rows = await prisma.event.findMany({ where: { organisationId: bodyOrg } });
      expect(rows).toHaveLength(0);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
