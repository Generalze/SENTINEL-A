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
 * Deliberately adversarial: the point of WP-18's model is who may NOT see or
 * send a message, so most cases assert a denial and the exact shape of it.
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
  // W22-02: no ambient sweep cadence — this suite drives sweep() itself.
  PATROL_SWEEP_INTERVAL_MS: '0',
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
  dispatcherA1: `${tag}_dispatcherA1`,
  operatorA1: `${tag}_operatorA1`,
  investigatorA1: `${tag}_investigatorA1`,
  // field.operative, assigned to incidentA1 — eligible sender and recipient
  assignedOp: `${tag}_assignedOp`,
  assignedOp2: `${tag}_assignedOp2`,
  // field.operative at the same site, NO assignment — ineligible
  unassignedOp: `${tag}_unassignedOp`,
  // field.operative whose assignment has reached a terminal status — ineligible
  terminalOp: `${tag}_terminalOp`,
  operativeA2: `${tag}_operativeA2`,
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
    { id: fx.commanderOrgWide, org: fx.orgA, role: 'site.commander', site: null },
    { id: fx.dispatcherA1, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
    { id: fx.operatorA1, org: fx.orgA, role: 'operator', site: fx.siteA1 },
    { id: fx.investigatorA1, org: fx.orgA, role: 'investigator', site: fx.siteA1 },
    { id: fx.assignedOp, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.assignedOp2, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.unassignedOp, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.terminalOp, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.operativeA2, org: fx.orgA, role: 'field.operative', site: fx.siteA2 },
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

  // B11-13: an incident now states its ORIGIN. These fixtures are
  // Fusion-shaped, so source_ref IS the hypothesis id, exactly as the WP-21B
  // migration backfills every pre-existing row.
  const incident = (id: string, org: string, site: string) => {
    const hypothesisId = randomUUID();
    return {
      id, hypothesisId, incidentCandidateId: randomUUID(), sourceKind: 'FUSION_HYPOTHESIS', sourceRef: hypothesisId,
      organisationId: org, siteId: site, incidentType: 'wp18.test', severity: 'SEV3',
      threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
    };
  };
  await prisma.incident.createMany({
    data: [
      incident(fx.incidentA1, fx.orgA, fx.siteA1),
      incident(fx.incidentA2, fx.orgA, fx.siteA2),
      incident(fx.incidentB1, fx.orgB, fx.siteB1),
      // Legacy-shaped: real tenant, but its site is not an operational Site row.
      incident(fx.incidentGhostSite, fx.orgA, `${fx.siteA1}_ghost`),
    ],
  });

  // Field assignments are what make an operative eligible for an incident.
  const assignment = (assignee: string, status: string) => ({
    organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, assigneeUserId: assignee,
    assignmentType: 'INCIDENT_RESPONSE', priority: 'SEV3', status, deliveryState: 'REQUESTED',
    needToKnowSummary: 'wp18 fixture', idempotencyKey: `wp18-${assignee}-${status}`,
    createdByUserId: fx.commanderA1, updatedByUserId: fx.commanderA1,
  });
  await prisma.fieldAssignment.createMany({
    data: [
      assignment(fx.assignedOp, 'ACCEPTED'),
      assignment(fx.assignedOp2, 'IN_PROGRESS'),
      // Terminal: must NOT confer eligibility.
      assignment(fx.terminalOp, 'COMPLETED'),
    ],
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: { in: orgs } } } });
  await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId: { in: orgs } } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
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
      recipient_user_ids: [fx.assignedOp],
      body: 'Proceed to the north gate.',
      retention_class: 'operational-30d',
      idempotency_key: `send-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  /** Sent by the commander, whose scope alone qualifies. */
  async function sendMessage(overrides: Record<string, unknown> = {}): Promise<{ id: string }> {
    const res = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody(overrides));
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

  // ---------------------------------------------------------------- reads

  it('a named recipient may read a message addressed to them', async () => {
    const created = await sendMessage();
    const res = await get(`/api/v1/field-messages/mine/${created.id}`, fx.assignedOp);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { body: string; recipients: unknown[] };
    expect(body.body).toBe('Proceed to the north gate.');
    expect(body.recipients).toEqual([{ recipient_user_id: fx.assignedOp, delivery_state: 'REQUESTED', delivered_at: null, acknowledged_at: null }]);
  });

  it('an ELIGIBLE but unnamed operative still gets 404 — eligibility decides who may be named, membership decides who may read', async () => {
    const created = await sendMessage({ recipient_user_ids: [fx.assignedOp] });
    // assignedOp2 is assigned to this very incident, so it could have been
    // named. It was not, so it must not be able to read this message.
    const unnamed = await get(`/api/v1/field-messages/mine/${created.id}`, fx.assignedOp2);
    const absent = await get(`/api/v1/field-messages/mine/${randomUUID()}`, fx.assignedOp2);
    expect(unnamed.status).toBe(404);
    expect(await unnamed.text()).toBe(await absent.text());
  });

  it('incident.view without an explicit field-message action cannot read content', async () => {
    const created = await sendMessage();
    for (const denied of [fx.investigatorA1, fx.operatorA1]) {
      expect((await get(`/api/v1/field-messages/mine/${created.id}`, denied)).status).toBe(403);
      expect((await get(`/api/v1/field-messages/oversight/${created.id}`, denied)).status).toBe(403);
    }
  });

  it('a field operative cannot use the oversight route even for a message they can read', async () => {
    const created = await sendMessage();
    expect((await get(`/api/v1/field-messages/mine/${created.id}`, fx.assignedOp)).status).toBe(200);
    expect((await get(`/api/v1/field-messages/oversight/${created.id}`, fx.assignedOp)).status).toBe(403);
    // Dispatcher holds the ordinary actions but NOT oversight.
    expect((await get(`/api/v1/field-messages/oversight/${created.id}`, fx.dispatcherA1)).status).toBe(403);
  });

  it('site.commander oversight reads without becoming a recipient or creating delivery state', async () => {
    const created = await sendMessage();
    const before = await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } });

    expect((await get(`/api/v1/field-messages/oversight/${created.id}`, fx.commanderA1)).status).toBe(200);
    expect((await get(`/api/v1/field-messages/oversight/incidents/${fx.incidentA1}`, fx.commanderA1)).status).toBe(200);

    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } })).toBe(before);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id, recipientUserId: fx.commanderA1 } })).toBe(0);

    const ack = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.commanderA1, { idempotency_key: `ack-${randomUUID()}` });
    expect(ack.status).toBe(404);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id, deliveryState: 'ACKNOWLEDGED' } })).toBe(0);
  });

  it('recipient membership is frozen: a later participant never sees an earlier message', async () => {
    const earlier = await sendMessage({ recipient_user_ids: [fx.assignedOp] });
    const later = await sendMessage({ recipient_user_ids: [fx.assignedOp, fx.assignedOp2] });

    expect((await get(`/api/v1/field-messages/mine/${later.id}`, fx.assignedOp2)).status).toBe(200);
    expect((await get(`/api/v1/field-messages/mine/${earlier.id}`, fx.assignedOp2)).status).toBe(404);

    const mine = (await (await get(`/api/v1/field-messages/incidents/${fx.incidentA1}/mine`, fx.assignedOp2)).json()) as Array<{ id: string }>;
    expect(mine.some((m) => m.id === later.id)).toBe(true);
    expect(mine.some((m) => m.id === earlier.id)).toBe(false);
  });

  // -------------------------------------------------- C8-03 eligibility

  it('C8-03: same-tenant membership alone does not make somebody nameable', async () => {
    const cases: Array<[string, string]> = [
      ['same-org user with no message role', fx.operatorA1],
      ['same-site operative with no assignment', fx.unassignedOp],
      ['operative whose assignment reached a terminal status', fx.terminalOp],
      ['operative scoped to another site', fx.operativeA2],
      ['foreign-tenant user', fx.senderB1],
      ['nonexistent user', `${tag}_ghost_user`],
    ];

    const bodies: string[] = [];
    for (const [, candidate] of cases) {
      const res = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ recipient_user_ids: [candidate] }));
      expect(res.status).toBe(400);
      const text = await res.text();
      // Never disclose WHICH condition failed, or the id itself.
      expect(text).toContain('not eligible for this incident');
      expect(text).not.toContain(candidate);
      bodies.push(text);
    }
    // Every cause produces the identical outward failure.
    expect(new Set(bodies).size).toBe(1);
    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentA1, senderUserId: fx.commanderA1, body: null } })).toBe(0);
  });

  it('C8-03: an operative assigned to this incident may be named, and a dispatcher may be named on scope alone', async () => {
    const withOperative = await sendMessage({ recipient_user_ids: [fx.assignedOp, fx.assignedOp2] });
    expect((await get(`/api/v1/field-messages/mine/${withOperative.id}`, fx.assignedOp2)).status).toBe(200);

    const withDispatcher = await sendMessage({ recipient_user_ids: [fx.dispatcherA1] });
    expect((await get(`/api/v1/field-messages/mine/${withDispatcher.id}`, fx.dispatcherA1)).status).toBe(200);
  });

  it('C8-03: a site operative not assigned to the incident cannot SEND into it', async () => {
    const denied = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.unassignedOp, sendBody({ recipient_user_ids: [fx.assignedOp] }));
    expect(denied.status).toBe(403);

    // ...while an assigned operative at the same site can.
    const allowed = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.assignedOp, sendBody({ recipient_user_ids: [fx.assignedOp2] }));
    expect(allowed.status).toBe(201);
  });

  it('C8-02: dispatcher may send, read and acknowledge; operator may do none of it', async () => {
    const sent = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.dispatcherA1, sendBody({ recipient_user_ids: [fx.dispatcherA1] }));
    expect(sent.status).toBe(201);
    const id = ((await sent.json()) as { id: string }).id;

    expect((await get(`/api/v1/field-messages/mine/${id}`, fx.dispatcherA1)).status).toBe(200);
    // Acknowledge is reachable for a dispatcher who is a named recipient. It is
    // refused on delivery state (C8-01), not on authorisation — 409, not 403.
    const ack = await post(`/api/v1/field-messages/mine/${id}/acknowledge`, fx.dispatcherA1, { idempotency_key: `ack-${randomUUID()}` });
    expect(ack.status).toBe(409);

    for (const path of [`/api/v1/field-messages/incidents/${fx.incidentA1}`, `/api/v1/field-messages/mine/${id}/acknowledge`]) {
      expect((await post(path, fx.operatorA1, sendBody())).status).toBe(403);
    }
    expect((await get(`/api/v1/field-messages/mine/${id}`, fx.operatorA1)).status).toBe(403);
  });

  // ------------------------------------------------- C8-01 delivery state

  it('C8-01: acknowledging a REQUESTED row is refused and fabricates no delivery evidence', async () => {
    const created = await sendMessage();
    const before = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId: created.id, recipientUserId: fx.assignedOp } });
    expect(before.deliveryState).toBe('REQUESTED');

    const res = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.assignedOp, { idempotency_key: `ack-${randomUUID()}` });
    expect(res.status).toBe(409);

    const after = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { id: before.id } });
    // Zero mutation: no state change, no fabricated delivered_at, no ack stamp.
    expect(after.deliveryState).toBe('REQUESTED');
    expect(after.deliveredAt).toBeNull();
    expect(after.acknowledgedAt).toBeNull();
    expect(await prisma.incidentFieldMessageActionIdempotency.count({ where: { messageId: created.id } })).toBe(0);
    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGED', payload: { path: ['incident_field_message_id'], equals: created.id } },
      }),
    ).toBe(0);
  });

  it('C8-01: once transport evidence exists, acknowledge advances only that recipient and is idempotent', async () => {
    const created = await sendMessage({ recipient_user_ids: [fx.assignedOp, fx.assignedOp2] });

    // Simulate the system-owned transport-evidence step for ONE recipient only.
    await prisma.incidentFieldMessageRecipient.updateMany({
      where: { messageId: created.id, recipientUserId: fx.assignedOp },
      data: { deliveryState: 'DELIVERED', deliveredAt: new Date() },
    });

    const key = `ack-${randomUUID()}`;
    const first = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.assignedOp, { idempotency_key: key });
    const second = await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.assignedOp, { idempotency_key: key });
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);

    const rows = await prisma.incidentFieldMessageRecipient.findMany({ where: { messageId: created.id } });
    expect(rows.find((r) => r.recipientUserId === fx.assignedOp)?.deliveryState).toBe('ACKNOWLEDGED');
    // Per recipient: one acknowledgement must not advance anybody else.
    expect(rows.find((r) => r.recipientUserId === fx.assignedOp2)?.deliveryState).toBe('REQUESTED');

    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGED', payload: { path: ['incident_field_message_id'], equals: created.id } },
      }),
    ).toBe(1);
  });

  // ------------------------------------------------------- scope & tuples

  it('the send request cannot choose organisation_id or site_id', async () => {
    const crossTenant = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ organisation_id: fx.orgB, site_id: fx.siteB1 }));
    expect(crossTenant.status).toBe(404);

    const inScope = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ organisation_id: fx.orgA, site_id: fx.siteA1 }));
    expect(inScope.status).toBe(400);

    const created = await sendMessage();
    const row = await prisma.incidentFieldMessage.findUniqueOrThrow({ where: { id: created.id } });
    expect(row.organisationId).toBe(fx.orgA);
    expect(row.siteId).toBe(fx.siteA1);
  });

  it('cross-organisation and cross-site sends and reads are refused', async () => {
    const created = await sendMessage();
    expect((await get(`/api/v1/field-messages/mine/${created.id}`, fx.senderB1)).status).toBe(404);
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.senderB1, sendBody({ recipient_user_ids: [fx.senderB1] }))).status).toBe(404);
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.operativeA2, sendBody({ recipient_user_ids: [fx.operativeA2] }))).status).toBe(404);
  });

  it('a legacy incident whose site does not resolve returns a generic 409', async () => {
    expect((await post(`/api/v1/field-messages/incidents/${fx.incidentGhostSite}`, fx.commanderA1, sendBody())).status).toBe(404);

    const res = await post(`/api/v1/field-messages/incidents/${fx.incidentGhostSite}`, fx.commanderOrgWide, sendBody());
    expect(res.status).toBe(409);
    const text = await res.text();
    expect(text).toContain('not eligible for Field messaging');
    expect(text).not.toContain(`${fx.siteA1}_ghost`);
    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentGhostSite } })).toBe(0);
  });

  it('the database rejects a message tuple that does not match a real tenant/site/incident', async () => {
    await expect(
      prisma.incidentFieldMessage.create({
        data: {
          organisationId: fx.orgA, siteId: fx.siteB1, incidentId: fx.incidentA1, senderUserId: fx.commanderA1,
          body: 'never', retentionClass: 'x', idempotencyKey: `fk-${randomUUID()}`, traceId: 'fk',
        },
      }),
    ).rejects.toThrow();

    await expect(
      prisma.incidentFieldMessage.create({
        data: {
          organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA2, senderUserId: fx.commanderA1,
          body: 'never', retentionClass: 'x', idempotencyKey: `fk-${randomUUID()}`, traceId: 'fk',
        },
      }),
    ).rejects.toThrow();

    expect(await prisma.incidentFieldMessage.count({ where: { siteId: fx.siteB1, organisationId: fx.orgA } })).toBe(0);
  });

  it('a non-recipient cannot acknowledge, and duplicate sends are idempotent', async () => {
    const created = await sendMessage();
    expect((await post(`/api/v1/field-messages/mine/${created.id}/acknowledge`, fx.assignedOp2, { idempotency_key: `ack-${randomUUID()}` })).status).toBe(404);

    const key = `send-${randomUUID()}`;
    const one = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ idempotency_key: key }));
    const two = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ idempotency_key: key }));
    expect(one.status).toBe(201);
    expect(two.status).toBe(201);
    const idOne = ((await one.json()) as { id: string }).id;
    expect(((await two.json()) as { id: string }).id).toBe(idOne);
    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentA1, idempotencyKey: key } })).toBe(1);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { payload: { path: ['message_id'], equals: idOne } } })).toBe(1);
  });

  it('C8-05: a colliding idempotency key from a DIFFERENT sender never discloses the first message', async () => {
    // The disclosure this closes: with the key scoped only to
    // (organisation, incident, key), B's collision returned A's message —
    // body included — to a caller who was neither its sender nor a recipient.
    const key = 'shared-key-c8-05';

    const aRes = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({
      idempotency_key: key, body: 'A confidential', recipient_user_ids: [fx.assignedOp],
    }));
    expect(aRes.status).toBe(201);
    const m1 = (await aRes.json()) as { id: string; sender_user_id: string; body: string };

    // B is an eligible sender on the same incident, but is neither M1's sender
    // nor one of its named recipients.
    const bRes = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.dispatcherA1, sendBody({
      idempotency_key: key, body: 'B confidential', recipient_user_ids: [fx.dispatcherA1],
    }));
    expect(bRes.status).toBe(201);
    const m2 = (await bRes.json()) as { id: string; sender_user_id: string; body: string };

    expect(m2.id).not.toBe(m1.id);
    expect(m2.sender_user_id).toBe(fx.dispatcherA1);
    expect(m2.body).toBe('B confidential');
    // The decisive assertion: A's content never reached B.
    expect(JSON.stringify(m2)).not.toContain('A confidential');

    // And B still cannot read M1 through the ordinary route.
    expect((await get(`/api/v1/field-messages/mine/${m1.id}`, fx.dispatcherA1)).status).toBe(404);
  });

  it('C8-05: the same sender replaying the same key still gets their own message and no duplicate side effects', async () => {
    const key = `replay-${randomUUID()}`;
    const first = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ idempotency_key: key }));
    expect(first.status).toBe(201);
    const m1 = (await first.json()) as { id: string };

    const recipientsBefore = await prisma.incidentFieldMessageRecipient.count({ where: { messageId: m1.id } });

    const replay = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, sendBody({ idempotency_key: key }));
    expect(replay.status).toBe(201);
    expect(((await replay.json()) as { id: string }).id).toBe(m1.id);

    expect(await prisma.incidentFieldMessage.count({ where: { incidentId: fx.incidentA1, senderUserId: fx.commanderA1, idempotencyKey: key } })).toBe(1);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: m1.id } })).toBe(recipientsBefore);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { payload: { path: ['message_id'], equals: m1.id } } })).toBe(1);
    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_SENT', payload: { path: ['incident_field_message_id'], equals: m1.id } },
      }),
    ).toBe(1);
  });

  it('C8-05: the database itself enforces the sender-scoped identity', async () => {
    const key = `db-idem-${randomUUID()}`;
    const row = (sender: string) => ({
      organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, senderUserId: sender,
      body: 'x', retentionClass: 'r', idempotencyKey: key, traceId: 't',
    });

    // Same key, DIFFERENT senders: permitted.
    const a = await prisma.incidentFieldMessage.create({ data: row(fx.commanderA1) });
    const b = await prisma.incidentFieldMessage.create({ data: row(fx.dispatcherA1) });
    expect(a.id).not.toBe(b.id);

    // Same key, SAME sender: rejected by the unique index.
    await expect(prisma.incidentFieldMessage.create({ data: row(fx.commanderA1) })).rejects.toThrow();
  });

  it('the transactional bundle is written together, and the outbox signal carries no content', async () => {
    const created = await sendMessage({ recipient_user_ids: [fx.assignedOp, fx.assignedOp2], body: 'sensitive operational detail' });

    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: created.id } })).toBe(2);
    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_SENT', payload: { path: ['incident_field_message_id'], equals: created.id } },
      }),
    ).toBe(1);

    const outbox = await prisma.incidentFieldMessageOutbox.findMany({ where: { payload: { path: ['message_id'], equals: created.id } } });
    expect(outbox).toHaveLength(2);
    expect(outbox.map((row) => row.recipientUserId).sort()).toEqual([fx.assignedOp, fx.assignedOp2].sort());
    for (const row of outbox) {
      const payload = row.payload as Record<string, unknown>;
      expect(Object.keys(payload).sort()).toEqual(['incident_id', 'kind', 'message_id']);
      expect(JSON.stringify(payload)).not.toContain('sensitive operational detail');
      expect(payload).not.toHaveProperty('body');
      expect(payload).not.toHaveProperty('sender_user_id');
    }
  });
});
