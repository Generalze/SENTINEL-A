import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * WP-18 merge-blocking acceptance set, driven over real HTTP through the global
 * guard chain (DevAuthGuard -> AccessGuard) against the live stack.
 *
 * These are deliberately adversarial rather than happy-path: the whole point of
 * WP-18's model is who may NOT see a message, so most of the cases below assert
 * a denial and its exact shape.
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

const tag = `wp18_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  commanderA1: `${tag}_commanderA1`,
  commanderOrgWide: `${tag}_commanderOrgWide`,
  senderA1: `${tag}_senderA1`,
  recipientA1: `${tag}_recipientA1`,
  peerA1: `${tag}_peerA1`,
  operativeA2: `${tag}_operativeA2`,
  investigatorA1: `${tag}_investigatorA1`,
  senderB1: `${tag}_senderB1`,
  incidentA1: randomUUID(),
  incidentA2: randomUUID(),
  incidentB1: randomUUID(),
  incidentGhostSite: randomUUID(),
};

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({ data: [{ id: fx.orgA, name: 'WP-18 Org A' }, { id: fx.orgB, name: 'WP-18 Org B' }] });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });

  const users: Array<{ id: string; org: string; role: string; site: string | null }> = [
    { id: fx.commanderA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    // Organisation-wide: the only principal whose scope reaches an incident
    // whose site is not an operational Site row.
    { id: fx.commanderOrgWide, org: fx.orgA, role: 'site.commander', site: null },
    { id: fx.senderA1, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.recipientA1, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.peerA1, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.operativeA2, org: fx.orgA, role: 'field.operative', site: fx.siteA2 },
    // Holds incident.view but NO field-message action at all.
    { id: fx.investigatorA1, org: fx.orgA, role: 'investigator', site: fx.siteA1 },
    { id: fx.senderB1, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  for (const u of users) {
    await prisma.user.create({
      data: {
        id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5,
        roles: { create: [{ role: u.role, siteId: u.site }] },
      },
    });
  }

  const incident = (id: string, org: string, site: string) => ({
    id, hypothesisId: randomUUID(), incidentCandidateId: randomUUID(),
    organisationId: org, siteId: site, incidentType: 'wp18.test', severity: 'SEV3',
    threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
  });
  await prisma.incident.createMany({
    data: [
      incident(fx.incidentA1, fx.orgA, fx.siteA1),
      incident(fx.incidentA2, fx.orgA, fx.siteA2),
      incident(fx.incidentB1, fx.orgB, fx.siteB1),
      // Legacy-shaped incident: real tenant, but its site is not an operational Site row.
      incident(fx.incidentGhostSite, fx.orgA, `${fx.siteA1}_ghost`),
    ],
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: { in: orgs } } } });
  await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
}

describe('WP-18 incident field messaging (live stack)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const get = (path: string, userId: string) => fetch(`${base}${path}`, { headers: { 'x-dev-user-id': userId } });

  function sendBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      recipient_user_ids: [fx.recipientA1],
      body: 'Proceed to the north gate.',
      retention_class: 'operational-30d',
      idempotency_key: `send-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  async function sendMessage(overrides: Record<string, unknown> = {}): Promise<{ id: string }> {
    const res = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody(overrides));
    expect(res.status).toBe(201);
    return (await res.json()) as { id: string };
  }

  beforeAll(async () => {
    for (const [k, v] of Object.entries(STACK_ENV)) process.env[k] = v;
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    await seed(prisma);
  }, 60_000);

  afterAll(async () => {
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 30_000);

  it('a named recipient may read a message addressed to them', async () => {
    const created = await sendMessage();
    const res = await get(`/api/v1/field-messages/mine/${created.id}`, fx.recipientA1);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { body: string; recipients: Array<{ recipient_user_id: string; delivery_state: string }> };
    expect(body.body).toBe('Proceed to the north gate.');
    expect(body.recipients).toEqual([{ recipient_user_id: fx.recipientA1, delivery_state: 'REQUESTED', delivered_at: null, acknowledged_at: null }]);
  });

  it('a same-site peer who is not a recipient gets an indistinguishable 404', async () => {
    const created = await sendMessage();
    const peer = await get(`/api/v1/field-messages/mine/${created.id}`, fx.peerA1);
    const absent = await get(`/api/v1/field-messages/mine/${randomUUID()}`, fx.peerA1);

    expect(peer.status).toBe(404);
    expect(absent.status).toBe(404);
    // Not merely the same status — the same response, so existence cannot be inferred.
    expect(await peer.text()).toBe(await absent.text());
  });

  it('incident.view without an explicit field-message action cannot read content', async () => {
    const created = await sendMessage();
    // The investigator holds incident.view but no field.message.* action.
    expect((await get(`/api/v1/field-messages/mine/${created.id}`, fx.investigatorA1)).status).toBe(403);
    expect((await get(`/api/v1/field-messages/oversight/${created.id}`, fx.investigatorA1)).status).toBe(403);
    expect((await get(`/api/v1/field-messages/incidents/${fx.incidentA1}/mine`, fx.investigatorA1)).status).toBe(403);
  });

  it('a field operative cannot use the oversight route even for a message they can read', async () => {
    const created = await sendMessage();
    expect((await get(`/api/v1/field-messages/mine/${created.id}`, fx.recipientA1)).status).toBe(200);
    expect((await get(`/api/v1/field-messages/oversight/${created.id}`, fx.recipientA1)).status).toBe(403);
  });

  it('site.commander oversight reads without becoming a recipient or creating delivery state', async () => {
    const created = await sendMessage();

    const before = await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } });
    const res = await get(`/api/v1/field-messages/oversight/${created.id}`, fx.commanderA1);
    expect(res.status).toBe(200);
    const list = await get(`/api/v1/field-messages/oversight/incidents/${fx.incidentA1}`, fx.commanderA1);
    expect(list.status).toBe(200);

    // The core invariant: oversight must not manufacture recipient state.
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } })).toBe(before);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id, recipientUserId: fx.commanderA1 } })).toBe(0);

    // ...and cannot acknowledge as a recipient.
    const ack = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.commanderA1, { idempotency_key: `ack-${randomUUID()}` });
    expect(ack.status).toBe(404);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id, deliveryState: 'ACKNOWLEDGED' } })).toBe(0);
  });

  it('recipient membership is frozen: a later participant never sees an earlier message', async () => {
    const earlier = await sendMessage({ recipient_user_ids: [fx.recipientA1] });
    // peerA1 is subsequently addressed on a NEW message — the older one stays hidden.
    const later = await sendMessage({ recipient_user_ids: [fx.recipientA1, fx.peerA1] });

    expect((await get(`/api/v1/field-messages/mine/${later.id}`, fx.peerA1)).status).toBe(200);
    expect((await get(`/api/v1/field-messages/mine/${earlier.id}`, fx.peerA1)).status).toBe(404);

    const mine = (await (await get(`/api/v1/field-messages/incidents/${fx.incidentA1}/mine`, fx.peerA1)).json()) as Array<{ id: string }>;
    expect(mine.some((m) => m.id === later.id)).toBe(true);
    expect(mine.some((m) => m.id === earlier.id)).toBe(false);
  });

  it('the send request cannot choose organisation_id or site_id', async () => {
    // Two independent defences, and both must hold. A body naming ANOTHER
    // tenant is stopped by the global AccessGuard, which answers 404 rather
    // than confirming the other tenant exists...
    const crossTenant = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody({ organisation_id: fx.orgB, site_id: fx.siteB1 }));
    expect(crossTenant.status).toBe(404);

    // ...and a body naming the caller's OWN scope still never reaches the
    // service, because the send schema is .strict() and has no such fields.
    const inScope = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody({ organisation_id: fx.orgA, site_id: fx.siteA1 }));
    expect(inScope.status).toBe(400);

    // Scope is taken from the incident, not the caller's wishes.
    const created = await sendMessage();
    const row = await prisma.incidentFieldMessage.findUniqueOrThrow({ where: { id: created.id } });
    expect(row.organisationId).toBe(fx.orgA);
    expect(row.siteId).toBe(fx.siteA1);
  });

  it('cross-organisation and cross-site sends and reads are refused', async () => {
    const created = await sendMessage();

    // Another tenant cannot read it, and cannot tell it apart from a missing id.
    expect((await get(`/api/v1/field-messages/mine/${created.id}`, fx.senderB1)).status).toBe(404);
    // ...nor send into this tenant's incident.
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderB1, sendBody({ recipient_user_ids: [fx.senderB1] }))).status).toBe(404);
    // A same-tenant operative scoped to another site cannot send into site A1's incident.
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.operativeA2, sendBody({ recipient_user_ids: [fx.operativeA2] }))).status).toBe(404);
  });

  it('recipients outside the tenant are refused without revealing which id was unknown', async () => {
    const res = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody({ recipient_user_ids: [fx.recipientA1, fx.senderB1] }));
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain(fx.senderB1);
  });

  it('a legacy incident whose site does not resolve returns a generic 409', async () => {
    // A site-scoped caller never even reaches the eligibility check: the
    // incident's site is outside their scope, so they get 404 first. That
    // ordering is deliberate — out-of-scope must not reveal ineligibility.
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentGhostSite}`, fx.commanderA1, sendBody())).status).toBe(404);

    // The organisation-wide commander IS in scope, and so sees the integrity
    // refusal itself.
    const res = await post(`/api/v1/field-messages/incidents/${fx.incidentGhostSite}`, fx.commanderOrgWide, sendBody());
    expect(res.status).toBe(409);
    const text = await res.text();
    expect(text).toContain('not eligible for Field messaging');
    // Must not disclose whether the site is missing or belongs elsewhere.
    expect(text).not.toContain(`${fx.siteA1}_ghost`);
    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentGhostSite } })).toBe(0);
  });

  it('the database rejects a message tuple that does not match a real tenant/site/incident', async () => {
    // Cross-tenant site pairing.
    await expect(
      prisma.incidentFieldMessage.create({
        data: {
          organisationId: fx.orgA, siteId: fx.siteB1, incidentId: fx.incidentA1, senderUserId: fx.senderA1,
          body: 'never', retentionClass: 'x', idempotencyKey: `fk-${randomUUID()}`, traceId: 'fk',
        },
      }),
    ).rejects.toThrow();

    // Incident that exists, but not under this site.
    await expect(
      prisma.incidentFieldMessage.create({
        data: {
          organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA2, senderUserId: fx.senderA1,
          body: 'never', retentionClass: 'x', idempotencyKey: `fk-${randomUUID()}`, traceId: 'fk',
        },
      }),
    ).rejects.toThrow();

    expect(await prisma.incidentFieldMessage.count({ where: { siteId: fx.siteB1, organisationId: fx.orgA } })).toBe(0);
  });

  it('acknowledge advances only the acknowledging recipient and is idempotent', async () => {
    const created = await sendMessage({ recipient_user_ids: [fx.recipientA1, fx.peerA1] });
    const key = `ack-${randomUUID()}`;

    const first = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.recipientA1, { idempotency_key: key });
    const second = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.recipientA1, { idempotency_key: key });
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);

    const rows = await prisma.incidentFieldMessageRecipient.findMany({ where: { messageId: created.id }, orderBy: { recipientUserId: 'asc' } });
    const acked = rows.find((r) => r.recipientUserId === fx.recipientA1);
    const other = rows.find((r) => r.recipientUserId === fx.peerA1);
    expect(acked?.deliveryState).toBe('ACKNOWLEDGED');
    // Per-recipient: one acknowledgement must not advance anybody else.
    expect(other?.deliveryState).toBe('REQUESTED');

    // Duplicate wrote no second timeline entry.
    const acks = await prisma.incidentTimelineEntry.count({
      where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGED', payload: { path: ['incident_field_message_id'], equals: created.id } },
    });
    expect(acks).toBe(1);
  });

  it('a non-recipient cannot acknowledge, and duplicate sends are idempotent', async () => {
    const created = await sendMessage();
    expect((await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.peerA1, { idempotency_key: `ack-${randomUUID()}` })).status).toBe(404);

    const key = `send-${randomUUID()}`;
    const one = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody({ idempotency_key: key }));
    const two = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderA1, sendBody({ idempotency_key: key }));
    expect(one.status).toBe(201);
    expect(two.status).toBe(201);
    const idOne = ((await one.json()) as { id: string }).id;
    const idTwo = ((await two.json()) as { id: string }).id;
    expect(idTwo).toBe(idOne);
    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentA1, idempotencyKey: key } })).toBe(1);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { payload: { path: ['message_id'], equals: idOne } } })).toBe(1);
  });

  it('the transactional bundle is written together, and the outbox signal carries no content', async () => {
    const created = await sendMessage({ recipient_user_ids: [fx.recipientA1, fx.peerA1], body: 'sensitive operational detail' });

    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } })).toBe(2);
    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_SENT', payload: { path: ['incident_field_message_id'], equals: created.id } },
      }),
    ).toBe(1);

    const outbox = await prisma.incidentFieldMessageOutbox.findMany({ where: { payload: { path: ['message_id'], equals: created.id } } });
    expect(outbox).toHaveLength(2);
    expect(outbox.map((row) => row.recipientUserId).sort()).toEqual([fx.recipientA1, fx.peerA1].sort());
    for (const row of outbox) {
      const payload = row.payload as Record<string, unknown>;
      expect(Object.keys(payload).sort()).toEqual(['incident_id', 'kind', 'message_id']);
      expect(JSON.stringify(payload)).not.toContain('sensitive operational detail');
      expect(payload).not.toHaveProperty('body');
      expect(payload).not.toHaveProperty('sender_user_id');
      expect(payload).not.toHaveProperty('media_refs');
    }
  });
});
