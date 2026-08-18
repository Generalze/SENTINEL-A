import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { WS_EVENT_FIELD_MESSAGE_UPDATED, WS_PATH } from '../realtime/realtime.constants';
import { FieldMessagingOutboxPublisher } from './field-messaging-outbox.publisher';

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
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    publisher = app.get(FieldMessagingOutboxPublisher);

    await prisma.organisation.create({ data: { id: fx.org, name: 'WP-18 RT' } });
    await prisma.site.create({ data: { id: fx.site, organisationId: fx.org, name: 'RT site' } });
    for (const [id, role] of [[fx.commander, 'site.commander'], [fx.recipient, 'dispatcher'], [fx.silentRecipient, 'dispatcher']] as const) {
      await prisma.user.create({
        data: { id, organisationId: fx.org, email: `${id}@example.invalid`, displayName: id, clearance: 5, roles: { create: [{ role, siteId: fx.site }] } },
      });
    }
    await prisma.incident.create({
      data: {
        id: fx.incident, hypothesisId: randomUUID(), incidentCandidateId: randomUUID(),
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
});
