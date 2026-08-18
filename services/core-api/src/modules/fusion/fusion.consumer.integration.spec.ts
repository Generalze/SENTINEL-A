import type { NormalisedEvent } from '@sentinel/contracts';
import { JSONCodec } from 'nats';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { EventsPublisherService } from '../events/events-publisher.service';
import { PrismaService } from '../../prisma/prisma.service';
import { FUSION_DURABLE_NAME } from './fusion.constants';
import { FusionConsumerService } from './fusion-consumer.service';
import { FusionPublisherService } from './fusion-publisher.service';
import { FusionRepository } from './fusion.repository';
import { FusionService } from './fusion.service';
import { makeAppConfig, makeEvent, scenarioWindowBase, uniqueOrgId, uniqueSiteId, waitUntil } from './test-support';

/**
 * End-to-end live-stack tests for the durable JetStream consumer (WP-05
 * deliverable #4) and acceptance criterion 3 (idempotency under redelivery).
 *
 * Events are published onto the real `SENTINEL_EVENTS` stream — created and
 * owned by WP-04, never modified here — on the real `sentinel.events.{org}.
 * {site}` subjects, and the real consumer picks them up. Nothing is stubbed
 * between the publish and the database row.
 *
 * ISOLATION FROM THE SERVICE'S OWN DURABLE
 * ----------------------------------------
 * The running service uses the durable `fusion-v1`. If this spec used that
 * name too, a locally running core-api (or a sibling test file) would compete
 * for the same messages and the assertions would be flaky. So the consumer is
 * started here with a per-run durable name and `deliverNewOnly`, which also
 * avoids replaying every event other work packages have left on the stream.
 * A separate assertion pins the production durable name to `fusion-v1`.
 */
describe('Fusion durable consumer (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const nats = new NatsProvider(appConfig);
  const eventsPublisher = new EventsPublisherService(nats);
  const repository = new FusionRepository(prisma);
  const publisher = new FusionPublisherService(nats);
  const service = new FusionService(repository, publisher);
  const consumer = new FusionConsumerService(nats, service);

  const durableName = `fusion-it-${Date.now().toString(36)}-${process.pid}`;
  const codec = JSONCodec<NormalisedEvent>();
  const createdOrgIds: string[] = [];

  function trackOrg(label: string): string {
    const id = uniqueOrgId(label);
    createdOrgIds.push(id);
    return id;
  }

  /** Publishes onto the events stream exactly as the events module does. */
  async function publishEvent(event: NormalisedEvent, options: { deduplicate?: boolean } = {}): Promise<void> {
    const nc = await nats.getConnection();
    const js = nc.jetstream();
    await js.publish(`sentinel.events.${event.organisation_id}.${event.site_id}`, codec.encode(event), {
      // Deliberately WITHOUT a msgID by default: JetStream's own publish-side
      // dedupe would otherwise absorb the redelivery and this suite would be
      // testing NATS rather than fusion's idempotency.
      ...(options.deduplicate ? { msgID: event.event_id } : {}),
      timeout: 5000,
    });
  }

  beforeAll(async () => {
    await prisma.$connect();

    // SENTINEL_EVENTS is owned by the Events module. This integration spec
    // invokes that owner's normal idempotent bootstrap rather than relying
    // on prior test execution or persistent local JetStream state.
    await eventsPublisher.onModuleInit();

    await consumer.start({ durableName, deliverNewOnly: true });
  }, 60_000);

  afterEach(async () => {
    if (createdOrgIds.length > 0) {
      await prisma.fusionAppliedEvent.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      await prisma.hypothesis.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      createdOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await consumer.stop();
    // Remove this run's throwaway durable so the server does not accumulate
    // one consumer per test run.
    try {
      const nc = await nats.getConnection();
      const jsm = await nc.jetstreamManager();
      await jsm.consumers.delete('SENTINEL_EVENTS', durableName);
    } catch {
      // Best-effort cleanup only.
    }
    await prisma.onModuleDestroy();
    await nats.onModuleDestroy();
  }, 30_000);

  it('uses the durable name the directive specifies', () => {
    expect(FUSION_DURABLE_NAME).toBe('fusion-v1');
  });

  it('AC1 (end-to-end): the 3-source scenario published to JetStream produces one hypothesis at state 3', async () => {
    const orgId = trackOrg('e2e');
    const siteId = uniqueSiteId('e2e');
    const base = scenarioWindowBase();
    const common = { organisation_id: orgId, site_id: siteId, zone_id: 'zone-lobby' };

    const events: NormalisedEvent[] = [
      makeEvent({
        ...common,
        source_type: 'camera',
        source_id: 'cam-01',
        event_type: 'person_detected',
        confidence: 0.5,
        occurred_at: base.toISOString(),
      }),
      makeEvent({
        ...common,
        source_type: 'sensor',
        source_id: 'motion-01',
        event_type: 'motion_detected',
        confidence: 0.5,
        occurred_at: new Date(base.getTime() + 20_000).toISOString(),
      }),
      makeEvent({
        ...common,
        source_type: 'access',
        source_id: 'door-01',
        event_type: 'access_denied_attempt',
        source_trust: 'degraded',
        confidence: 0.4,
        occurred_at: new Date(base.getTime() + 40_000).toISOString(),
      }),
    ];

    for (const event of events) {
      await publishEvent(event);
    }

    const applied = await waitUntil(
      async () => (await prisma.fusionAppliedEvent.count({ where: { organisationId: orgId } })) === 3,
      30_000,
    );
    expect(applied).toBe(true);

    const rows = await prisma.hypothesis.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(1);
    expect(rows[0].state).toBe(3);
    expect(rows[0].supportingEventIds.sort()).toEqual(events.map((event) => event.event_id).sort());
    expect(rows[0].confidenceExplanation).toContain('PROBABLE_THREAT');

    const transitions = await prisma.hypothesisTransition.count({ where: { hypothesisId: rows[0].id } });
    expect(transitions).toBe(2);
  }, 90_000);

  it('AC3: a redelivered event is not double-applied', async () => {
    const orgId = trackOrg('idem');
    const siteId = uniqueSiteId('idem');
    const base = scenarioWindowBase();
    const common = { organisation_id: orgId, site_id: siteId, zone_id: 'zone-dock' };

    const repeated = makeEvent({
      ...common,
      source_type: 'camera',
      source_id: 'cam-01',
      event_type: 'person_detected',
      confidence: 0.5,
      occurred_at: base.toISOString(),
    });
    // A distinct follow-up event acts as the synchronisation marker: JetStream
    // preserves per-subject order, so once this one has been applied both
    // deliveries of `repeated` have already been through the consumer.
    const marker = makeEvent({
      ...common,
      source_type: 'sensor',
      source_id: 'motion-01',
      event_type: 'motion_detected',
      confidence: 0.5,
      occurred_at: new Date(base.getTime() + 20_000).toISOString(),
    });

    await publishEvent(repeated);
    await publishEvent(repeated); // byte-identical redelivery, no publish-side dedupe
    await publishEvent(marker);

    const settled = await waitUntil(
      async () => (await prisma.fusionAppliedEvent.count({ where: { organisationId: orgId, eventId: marker.event_id } })) === 1,
      30_000,
    );
    expect(settled).toBe(true);

    // The redelivery was seen and deliberately discarded: exactly one applied
    // row, and the signal appears exactly once in the accumulated evidence.
    const appliedRows = await prisma.fusionAppliedEvent.findMany({ where: { organisationId: orgId } });
    expect(appliedRows).toHaveLength(2);
    expect(appliedRows.filter((row) => row.eventId === repeated.event_id)).toHaveLength(1);

    const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(hypothesis.supportingEventIds).toEqual([repeated.event_id, marker.event_id]);
    expect(Array.isArray(hypothesis.signals) ? hypothesis.signals : []).toHaveLength(2);
    // Two independent 0.50 sources -> 1-(0.5*0.5). A double-apply would have
    // pushed this to 1-(0.5*0.5*0.5) = 0.875 and the state to 4.
    expect(hypothesis.threatProbability).toBeCloseTo(0.75, 5);
    expect(hypothesis.state).toBe(3);
    expect(hypothesis.sourceDiversity).toBe(2);

    // And the transition log was not duplicated either.
    const transitions = await prisma.hypothesisTransition.findMany({
      where: { hypothesisId: hypothesis.id },
      orderBy: { sequence: 'asc' },
    });
    expect(transitions.map((t) => [t.fromState, t.toState])).toEqual([
      [0, 2],
      [2, 3],
    ]);
  }, 90_000);

  it('AC3 (direct): re-applying the same event through the service is an explicit no-op', async () => {
    const orgId = trackOrg('idem-direct');
    const siteId = uniqueSiteId('idem-direct');
    const event = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-x',
      event_type: 'person_detected',
      confidence: 0.5,
      occurred_at: scenarioWindowBase().toISOString(),
    });

    const first = await service.applyEvent(event);
    expect(first.outcome).toBe('applied');

    const second = await service.applyEvent(event);
    expect(second).toEqual({ outcome: 'duplicate', eventId: event.event_id });

    const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(hypothesis.supportingEventIds).toEqual([event.event_id]);
    expect(hypothesis.version).toBe(1);
  }, 45_000);

  it('terminates a malformed payload instead of letting it block the event pipeline', async () => {
    const orgId = trackOrg('malformed');
    const siteId = uniqueSiteId('malformed');
    const base = scenarioWindowBase();

    const nc = await nats.getConnection();
    const js = nc.jetstream();
    // Valid JSON, but not a Normalised Event: redelivering it would fail
    // identically forever.
    await js.publish(`sentinel.events.${orgId}.${siteId}`, codec.encode({ nonsense: true } as unknown as NormalisedEvent), {
      timeout: 5000,
    });

    const good = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-y',
      event_type: 'person_detected',
      confidence: 0.5,
      occurred_at: base.toISOString(),
    });
    await publishEvent(good);

    // The good event that followed still gets through — the poison message
    // did not stall the consumer.
    const processed = await waitUntil(
      async () => (await prisma.fusionAppliedEvent.count({ where: { organisationId: orgId } })) === 1,
      30_000,
    );
    expect(processed).toBe(true);

    const applied = await prisma.fusionAppliedEvent.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(applied.eventId).toBe(good.event_id);
  }, 90_000);
});
