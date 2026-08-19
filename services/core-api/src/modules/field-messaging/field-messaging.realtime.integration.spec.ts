import { randomUUID } from 'node:crypto';
import { canTransition } from '@sentinel/contracts';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { WS_EVENT_FIELD_MESSAGE_UPDATED, WS_PATH } from '../realtime/realtime.constants';
import { FieldMessagingOutboxPublisher } from './field-messaging-outbox.publisher';
import { FieldMessagingRepository } from './field-messaging.repository';

/**
 * WP-18/C8-01 delivery evidence, end to end on the live stack.
 *
 * The rule under test is the one the checkpoint ruling made binding: publishing
 * to NATS proves the internal bus accepted an event; only a socket-level
 * acknowledgement from one of the recipient's OWN authenticated connections is
 * evidence that their transport received it. Nothing else may write DELIVERED.
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://127.0.0.1:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  LOG_LEVEL: 'error',
  DEV_AUTH_ENABLED: 'true',
};

const tag = `wp18rt_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  org: `${tag}_org`,
  site: `${tag}_site`,
  commander: `${tag}_commander`,
  recipient: `${tag}_recipient`,
  silentRecipient: `${tag}_silent`,
  multiRecipient: `${tag}_multi`,
  bystander: `${tag}_bystander`,
  incident: randomUUID(),
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** Polls until `predicate` holds or the deadline passes — never assumes async work already finished. */
async function eventually<T>(read: () => Promise<T>, predicate: (value: T) => boolean, timeoutMs = 6000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let latest = await read();
  while (!predicate(latest) && Date.now() < deadline) {
    await sleep(100);
    latest = await read();
  }
  return latest;
}

describe('WP-18 realtime delivery evidence (live stack, C8-01)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;
  let publisher: FieldMessagingOutboxPublisher;
  let repository: FieldMessagingRepository;
  const openSockets: ClientSocket[] = [];

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  async function sendTo(recipients: string[]): Promise<string> {
    const res = await post(`/api/v1/field-messages/incidents/${fx.incident}`, fx.commander, {
      recipient_user_ids: recipients,
      body: 'transport evidence probe',
      retention_class: 'operational-30d',
      idempotency_key: `send-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  }

  const stateOf = (messageId: string, userId: string) =>
    prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: userId } });

  beforeAll(async () => {
    for (const [k, v] of Object.entries(STACK_ENV)) process.env[k] = v;
    // C13-01: production's sweep cadence is hard-wired and cannot be switched
    // off by configuration. A spec silences only the REPEATING timer, through
    // the DI seam, so the sweeps in flight are exactly the ones it drives.
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PATROL_SWEEP_SCHEDULER)
      .useClass(NoopPatrolSweepScheduler)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    publisher = app.get(FieldMessagingOutboxPublisher);
    repository = app.get(FieldMessagingRepository);

    await prisma.organisation.create({ data: { id: fx.org, name: 'WP-18 RT' } });
    await prisma.site.create({ data: { id: fx.site, organisationId: fx.org, name: 'RT site' } });
    for (const [id, role] of [[fx.commander, 'site.commander'], [fx.recipient, 'dispatcher'], [fx.silentRecipient, 'dispatcher'], [fx.multiRecipient, 'dispatcher'], [fx.bystander, 'dispatcher']] as const) {
      await prisma.user.create({
        data: { id, organisationId: fx.org, email: `${id}@example.invalid`, displayName: id, clearance: 5, roles: { create: [{ role, siteId: fx.site }] } },
      });
    }
    // B11-13: an incident now states its ORIGIN. This fixture is Fusion-shaped,
    // so source_ref IS the hypothesis id, exactly as the WP-21B migration
    // backfills every pre-existing row.
    const fixtureHypothesisId = randomUUID();
    await prisma.incident.create({
      data: {
        id: fx.incident, hypothesisId: fixtureHypothesisId, incidentCandidateId: randomUUID(), sourceKind: 'FUSION_HYPOTHESIS', sourceRef: fixtureHypothesisId,
        organisationId: fx.org, siteId: fx.site, incidentType: 'wp18.rt', severity: 'SEV3',
        threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
      },
    });
  }, 90_000);

  afterEach(() => {
    for (const socket of openSockets.splice(0)) socket.close();
  });

  afterAll(async () => {
    if (!app) return;
    await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: fx.org } } });
    await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: fx.org } } });
    await prisma.incident.deleteMany({ where: { organisationId: fx.org } });
    await prisma.userRole.deleteMany({ where: { user: { organisationId: fx.org } } });
    await prisma.user.deleteMany({ where: { organisationId: fx.org } });
    await prisma.site.deleteMany({ where: { organisationId: fx.org } });
    await prisma.organisation.deleteMany({ where: { id: fx.org } });
    await app.close();
  }, 60_000);

  /** Connects as `userId`; `acknowledge` controls whether the client answers the server's ack request. */
  function connectAs(userId: string, acknowledge: boolean, received?: Array<Record<string, unknown>>): ClientSocket {
    const socket = io(base, { path: WS_PATH, transports: ['websocket'], reconnection: false, forceNew: true, auth: { userId } });
    openSockets.push(socket);
    socket.on(WS_EVENT_FIELD_MESSAGE_UPDATED, (payload: Record<string, unknown>, ack?: (value: unknown) => void) => {
      received?.push(payload);
      if (acknowledge && typeof ack === 'function') ack({ received: true });
    });
    return socket;
  }

  function waitForConnect(socket: ClientSocket): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('socket did not connect')), 8000);
      socket.on('connect', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  it('publishing to NATS alone is not delivery: with no recipient socket the row stays REQUESTED', async () => {
    const messageId = await sendTo([fx.silentRecipient]);
    expect((await stateOf(messageId, fx.silentRecipient)).deliveryState).toBe('REQUESTED');

    // Drain the outbox for real — the signal genuinely reaches NATS and the
    // consumer genuinely runs. There is simply no transport to receive it.
    await publisher.sweep();
    await sleep(2500);

    const outbox = await prisma.incidentFieldMessageOutbox.findFirst({ where: { payload: { path: ['message_id'], equals: messageId } } });
    expect(outbox?.publishedAt).not.toBeNull(); // it WAS published...

    const row = await stateOf(messageId, fx.silentRecipient);
    expect(row.deliveryState).toBe('REQUESTED'); // ...and that changed nothing.
    expect(row.deliveredAt).toBeNull();
  }, 30_000);

  it('a connected recipient that never acknowledges does not advance to DELIVERED', async () => {
    const received: Array<Record<string, unknown>> = [];
    const socket = connectAs(fx.silentRecipient, false, received);
    await waitForConnect(socket);

    const messageId = await sendTo([fx.silentRecipient]);
    await publisher.sweep();
    await sleep(3000);

    // The notification reached the socket...
    expect(received.some((p) => p.message_id === messageId)).toBe(true);
    // ...but without an acknowledgement there is no evidence, so no DELIVERED.
    const row = await stateOf(messageId, fx.silentRecipient);
    expect(row.deliveryState).toBe('REQUESTED');
    expect(row.deliveredAt).toBeNull();
  }, 30_000);

  it('a positive transport receipt advances the row to DELIVERED, and only then may the human acknowledge', async () => {
    const received: Array<Record<string, unknown>> = [];
    const socket = connectAs(fx.recipient, true, received);
    await waitForConnect(socket);

    const messageId = await sendTo([fx.recipient]);
    await publisher.sweep();

    const row = await eventually(() => stateOf(messageId, fx.recipient), (r) => r.deliveryState === 'DELIVERED');
    expect(row.deliveryState).toBe('DELIVERED');
    expect(row.deliveredAt).not.toBeNull();
    expect(row.acknowledgedAt).toBeNull();

    // The socket payload carries identifiers only — never content.
    const payload = received.find((p) => p.message_id === messageId);
    expect(payload).toBeDefined();
    expect(Object.keys(payload ?? {}).sort()).toEqual(['incident_id', 'kind', 'message_id']);
    expect(JSON.stringify(payload)).not.toContain('transport evidence probe');

    // Now, and only now, the human acknowledgement is accepted.
    const ack = await post(`/api/v1/field-messages/mine/${messageId}/acknowledge`, fx.recipient, { idempotency_key: `ack-${randomUUID()}` });
    expect(ack.status).toBe(201);
    const acked = await stateOf(messageId, fx.recipient);
    expect(acked.deliveryState).toBe('ACKNOWLEDGED');
    // The delivery timestamp keeps its own evidence, distinct from the ack.
    expect(acked.deliveredAt).not.toBeNull();
    expect(acked.acknowledgedAt).not.toBeNull();
  }, 30_000);

  // ------------------------------------------------------------- C8-04

  it('C8-04: two sockets for the same recipient, only one acknowledges -> DELIVERED', async () => {
    // The Crucible regression. A single room-wide broadcast ack expects EVERY
    // targeted client to answer, so this exact shape previously reported
    // failure and stranded the row at REQUESTED.
    const acking = connectAs(fx.multiRecipient, true);
    const silent = connectAs(fx.multiRecipient, false);
    await Promise.all([waitForConnect(acking), waitForConnect(silent)]);

    const messageId = await sendTo([fx.multiRecipient]);
    await publisher.sweep();

    const row = await eventually(() => stateOf(messageId, fx.multiRecipient), (r) => r.deliveryState === 'DELIVERED');
    expect(row.deliveryState).toBe('DELIVERED');
    expect(row.deliveredAt).not.toBeNull();
  }, 30_000);

  it('C8-04: two sockets for the same recipient, neither acknowledges -> REQUESTED', async () => {
    const first = connectAs(fx.multiRecipient, false);
    const second = connectAs(fx.multiRecipient, false);
    await Promise.all([waitForConnect(first), waitForConnect(second)]);

    const messageId = await sendTo([fx.multiRecipient]);
    await publisher.sweep();
    await sleep(3500);

    const row = await stateOf(messageId, fx.multiRecipient);
    expect(row.deliveryState).toBe('REQUESTED');
    expect(row.deliveredAt).toBeNull();
  }, 30_000);

  it('C8-04: both sockets acknowledge -> exactly one effective REQUESTED->DELIVERED transition', async () => {
    const a = connectAs(fx.multiRecipient, true);
    const b = connectAs(fx.multiRecipient, true);
    await Promise.all([waitForConnect(a), waitForConnect(b)]);

    const messageId = await sendTo([fx.multiRecipient]);
    await publisher.sweep();

    const row = await eventually(() => stateOf(messageId, fx.multiRecipient), (r) => r.deliveryState === 'DELIVERED');
    const firstDeliveredAt = row.deliveredAt;
    expect(firstDeliveredAt).not.toBeNull();

    // The conditional update is what makes racing evidence safe: a second
    // attempt reports no effective transition and does not restamp the row.
    // Uses the REAL section 76 predicate the consumer passes, and the row's own
    // guard holds even against a permissive caller.
    const realPredicate = (from: string): boolean => canTransition(from as Parameters<typeof canTransition>[0], 'DELIVERED');
    expect(await repository.recordTransportDelivery(fx.org, fx.incident, messageId, fx.multiRecipient, realPredicate)).toBe(false);
    expect(await repository.recordTransportDelivery(fx.org, fx.incident, messageId, fx.multiRecipient, () => true)).toBe(false);
    const after = await stateOf(messageId, fx.multiRecipient);
    expect(after.deliveryState).toBe('DELIVERED');
    expect(after.deliveredAt?.toISOString()).toBe(firstDeliveredAt?.toISOString());
  }, 30_000);

  it("C8-04: another user's acknowledging socket cannot advance this recipient", async () => {
    // A live, authenticated, freely-acknowledging socket belonging to someone
    // else must not become evidence for the actual recipient.
    const bystanderSocket = connectAs(fx.bystander, true);
    await waitForConnect(bystanderSocket);

    const messageId = await sendTo([fx.silentRecipient]);
    await publisher.sweep();
    await sleep(3000);

    expect((await stateOf(messageId, fx.silentRecipient)).deliveryState).toBe('REQUESTED');
    // ...and the bystander was never made a recipient of it.
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId, recipientUserId: fx.bystander } })).toBe(0);
  }, 30_000);

  // ------------------------------------------------------------- C8-06

  it('C8-06: a wrong organisation cannot advance delivery, even with the correct message and recipient', async () => {
    const messageId = await sendTo([fx.silentRecipient]);
    const always = (): boolean => true;

    expect(await repository.recordTransportDelivery(`${fx.org}_other`, fx.incident, messageId, fx.silentRecipient, always)).toBe(false);

    const row = await stateOf(messageId, fx.silentRecipient);
    expect(row.deliveryState).toBe('REQUESTED');
    expect(row.deliveredAt).toBeNull();
  }, 30_000);

  it('C8-06: a wrong incident cannot advance delivery, even within the correct organisation', async () => {
    // The same-tenant integrity gap: a forged internal event pairing a real
    // message_id with a different incident_id must not be accepted.
    const messageId = await sendTo([fx.silentRecipient]);
    const always = (): boolean => true;

    expect(await repository.recordTransportDelivery(fx.org, randomUUID(), messageId, fx.silentRecipient, always)).toBe(false);

    const row = await stateOf(messageId, fx.silentRecipient);
    expect(row.deliveryState).toBe('REQUESTED');
    expect(row.deliveredAt).toBeNull();
  }, 30_000);

  it('C8-06: a wrong recipient cannot advance another recipient row, and the fully bound scope does', async () => {
    const messageId = await sendTo([fx.silentRecipient]);
    const always = (): boolean => true;

    expect(await repository.recordTransportDelivery(fx.org, fx.incident, messageId, fx.bystander, always)).toBe(false);
    expect((await stateOf(messageId, fx.silentRecipient)).deliveryState).toBe('REQUESTED');

    // All four bound values correct -> the normal transition proceeds.
    const realPredicate = (from: string): boolean => canTransition(from as Parameters<typeof canTransition>[0], 'DELIVERED');
    expect(await repository.recordTransportDelivery(fx.org, fx.incident, messageId, fx.silentRecipient, realPredicate)).toBe(true);
    const row = await stateOf(messageId, fx.silentRecipient);
    expect(row.deliveryState).toBe('DELIVERED');
    expect(row.deliveredAt).not.toBeNull();
  }, 30_000);
});
