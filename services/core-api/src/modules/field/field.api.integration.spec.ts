import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * Field REST surface end to end, through the real global guard chain
 * (DevAuthGuard -> AccessGuard) against the live stack.
 *
 * This is WP-16 acceptance criterion 7, which WP-16 did not deliver — it
 * shipped service/repository unit tests against doubles, and a double cannot
 * prove that the guards are bound, that a cross-site create is refused, or
 * that a duplicate action over HTTP writes no second audit row. It is also
 * WP-17 AC6-AC8 (subject-token rejection at the boundary, and the operative's
 * own refetch routes).
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  LOG_LEVEL: 'error',
  DEV_AUTH_ENABLED: 'true',
};

interface Fixture {
  orgA: string;
  orgB: string;
  siteA1: string;
  siteA2: string;
  siteB1: string;
  dispatcherA1: string;
  operativeA1: string;
  otherOperativeA1: string;
  operativeA2: string;
  dispatcherB1: string;
}

const ids = (): Fixture => {
  const tag = `wp17_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
  return {
    orgA: `${tag}_orgA`,
    orgB: `${tag}_orgB`,
    siteA1: `${tag}_siteA1`,
    siteA2: `${tag}_siteA2`,
    siteB1: `${tag}_siteB1`,
    dispatcherA1: `${tag}_dispatcherA1`,
    operativeA1: `${tag}_operativeA1`,
    otherOperativeA1: `${tag}_otherOperativeA1`,
    operativeA2: `${tag}_operativeA2`,
    dispatcherB1: `${tag}_dispatcherB1`,
  };
};

const fx = ids();

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({ data: [{ id: fx.orgA, name: 'WP-17 Org A' }, { id: fx.orgB, name: 'WP-17 Org B' }] });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });
  const users: Array<{ id: string; organisationId: string; role: string; siteId: string }> = [
    { id: fx.dispatcherA1, organisationId: fx.orgA, role: 'dispatcher', siteId: fx.siteA1 },
    { id: fx.operativeA1, organisationId: fx.orgA, role: 'field.operative', siteId: fx.siteA1 },
    { id: fx.otherOperativeA1, organisationId: fx.orgA, role: 'field.operative', siteId: fx.siteA1 },
    { id: fx.operativeA2, organisationId: fx.orgA, role: 'field.operative', siteId: fx.siteA2 },
    { id: fx.dispatcherB1, organisationId: fx.orgB, role: 'dispatcher', siteId: fx.siteB1 },
  ];
  for (const user of users) {
    await prisma.user.create({
      data: {
        id: user.id,
        organisationId: user.organisationId,
        email: `${user.id}@example.invalid`,
        displayName: user.id,
        clearance: 5,
        roles: { create: [{ role: user.role, siteId: user.siteId }] },
      },
    });
  }
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const organisationIds = [fx.orgA, fx.orgB];
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId: { in: organisationIds } } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.fieldStateUpdateIdempotency.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.fieldOperativeStateHistory.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.fieldOperativeCurrentState.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: organisationIds } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: organisationIds } } });
  await prisma.organisation.deleteMany({ where: { id: { in: organisationIds } } });
}

describe('Field REST surface (live stack, WP-16 AC7 / WP-17 AC6-AC8)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;

  // Return types are inferred from `fetch` rather than annotated: the DOM
  // `Response` global is not in this project's eslint environment.
  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  const get = (path: string, userId: string) => fetch(`${base}${path}`, { headers: { 'x-dev-user-id': userId } });

  function newAssignmentBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      site_id: fx.siteA1,
      incident_id: null,
      assignee_user_id: fx.operativeA1,
      assignment_type: 'INCIDENT_RESPONSE',
      priority: 'SEV2',
      need_to_know_summary: 'Proceed to the north gate and report.',
      expires_at: null,
      idempotency_key: `create-${randomUUID()}`,
      ...overrides,
    };
  }

  async function createAssignment(overrides: Record<string, unknown> = {}): Promise<{ id: string }> {
    const res = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody(overrides));
    expect(res.status).toBe(201);
    return (await res.json()) as { id: string };
  }

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
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

  it('a site-scoped dispatcher creates an assignment for an operative at the same site, with audit and outbox in the same write', async () => {
    const created = await createAssignment();

    expect(created).toMatchObject({ organisation_id: fx.orgA, site_id: fx.siteA1, assignee_user_id: fx.operativeA1, status: 'REQUESTED', delivery_state: 'REQUESTED' });
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: created.id } })).toBe(1);
    expect(await prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: created.id } } })).toBe(1);
  });

  it('WP-16 AC7: a dispatcher scoped to site A1 cannot create an assignment at site A2', async () => {
    const res = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody({ site_id: fx.siteA2, assignee_user_id: fx.operativeA2 }));
    expect(res.status).toBe(403);
    expect(await prisma.fieldAssignment.count({ where: { siteId: fx.siteA2 } })).toBe(0);
  });

  it('WP-16 AC7: an assignee who is not a Field operative at the named site is refused', async () => {
    const res = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody({ assignee_user_id: fx.operativeA2 }));
    expect(res.status).toBe(400);
  });

  it('WP-17 AC6: a site_id that is not a safe NATS subject token is rejected before anything is persisted', async () => {
    for (const unsafe of ['site.a1', 'site-a1.>', 'site *', `${fx.siteA1}.evil`]) {
      const res = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody({ site_id: unsafe }));
      // 403 when the guard's site-scope conjunct rejects it first, 400 when it
      // reaches validation — either way it never persists.
      expect([400, 403]).toContain(res.status);
      expect(await prisma.fieldAssignment.count({ where: { siteId: unsafe } })).toBe(0);
    }
  });

  it('WP-17 AC7: an operative lists and reads only their own assignments', async () => {
    const mine = await createAssignment();
    const someoneElses = await createAssignment({ assignee_user_id: fx.otherOperativeA1 });

    const listRes = await get('/api/v1/field/assignments/mine', fx.operativeA1);
    expect(listRes.status).toBe(200);
    const list = (await listRes.json()) as Array<{ id: string; assignee_user_id: string }>;
    expect(list.some((row) => row.id === mine.id)).toBe(true);
    expect(list.some((row) => row.id === someoneElses.id)).toBe(false);
    expect(list.every((row) => row.assignee_user_id === fx.operativeA1)).toBe(true);

    expect((await get(`/api/v1/field/assignments/mine/${mine.id}`, fx.operativeA1)).status).toBe(200);
    // Another operative's assignment is hidden, not merely forbidden.
    expect((await get(`/api/v1/field/assignments/mine/${someoneElses.id}`, fx.operativeA1)).status).toBe(404);
    // And the operative holds no manage authority at all.
    expect((await get(`/api/v1/field/assignments/${mine.id}`, fx.operativeA1)).status).toBe(403);
  });

  it('WP-16 AC7: a cross-organisation read returns 404 rather than revealing the assignment exists', async () => {
    const created = await createAssignment();
    expect((await get(`/api/v1/field/assignments/${created.id}`, fx.dispatcherB1)).status).toBe(404);
    expect((await get('/api/v1/field/assignments', fx.dispatcherB1)).status).toBe(200);
    const otherTenantList = (await (await get('/api/v1/field/assignments', fx.dispatcherB1)).json()) as Array<{ id: string }>;
    expect(otherTenantList.some((row) => row.id === created.id)).toBe(false);
  });

  it('WP-16 AC7: only the assignee may act on an assignment', async () => {
    const created = await createAssignment();
    const res = await post(`/api/v1/field/assignments/${created.id}/accept`, fx.otherOperativeA1, {
      expected_status: 'REQUESTED',
      idempotency_key: `accept-${randomUUID()}`,
    });
    expect(res.status).toBe(403);
    const row = await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: created.id } });
    expect(row.status).toBe('REQUESTED');
  });

  it('WP-16 AC7: duplicate accepts are idempotent over HTTP and append no second audit or outbox row', async () => {
    const created = await createAssignment();
    const key = `accept-${randomUUID()}`;
    const body = { expected_status: 'REQUESTED', idempotency_key: key };

    const first = await post(`/api/v1/field/assignments/${created.id}/accept`, fx.operativeA1, body);
    const second = await post(`/api/v1/field/assignments/${created.id}/accept`, fx.operativeA1, body);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    const firstBody = (await first.json()) as { status: string; delivery_state: string; accepted_at: string | null };
    const secondBody = (await second.json()) as { status: string; accepted_at: string | null };
    expect(firstBody.status).toBe('ACCEPTED');
    // §76: acceptance is the acknowledgement, so the shared delivery state advances with it.
    expect(firstBody.delivery_state).toBe('ACKNOWLEDGED');
    expect(secondBody.accepted_at).toBe(firstBody.accepted_at);

    // create + accept, and nothing more.
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: created.id } })).toBe(2);
    expect(await prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: created.id } } })).toBe(2);
  });

  it('an illegal transition is refused without changing persisted state', async () => {
    const created = await createAssignment();
    await post(`/api/v1/field/assignments/${created.id}/accept`, fx.operativeA1, { expected_status: 'REQUESTED', idempotency_key: `accept-${randomUUID()}` });

    // ACCEPTED -> COMPLETED is not an allowed edge; IN_PROGRESS comes first.
    const res = await post(`/api/v1/field/assignments/${created.id}/complete`, fx.operativeA1, {
      expected_status: 'ACCEPTED',
      idempotency_key: `complete-${randomUUID()}`,
    });

    expect(res.status).toBe(409);
    const row = await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: created.id } });
    expect(row.status).toBe('ACCEPTED');
    expect(row.completedAt).toBeNull();
  });

  it('runs the full accept -> start -> complete lifecycle for the assignee', async () => {
    const created = await createAssignment();
    for (const [action, expected, next] of [
      ['accept', 'REQUESTED', 'ACCEPTED'],
      ['start', 'ACCEPTED', 'IN_PROGRESS'],
      ['complete', 'IN_PROGRESS', 'COMPLETED'],
    ] as const) {
      const res = await post(`/api/v1/field/assignments/${created.id}/${action}`, fx.operativeA1, {
        expected_status: expected,
        idempotency_key: `${action}-${randomUUID()}`,
      });
      expect(res.status).toBe(201);
      expect((await res.json()) as { status: string }).toMatchObject({ status: next });
    }
  });

  it('computes freshness server-side, keeps the client claim as telemetry, and dedupes a replayed state update', async () => {
    const sourceAt = new Date(Date.now() - 45_000).toISOString();
    const key = `state-${randomUUID()}`;
    const body = {
      site_id: fx.siteA1,
      device_id: 'device-wp17',
      state: 'RESPONDING',
      location: null,
      source_at: sourceAt,
      // A client claiming perfect freshness for a 45s-old observation.
      freshness_ms: 0,
      idempotency_key: key,
      trace_id: `trace-${randomUUID()}`,
    };

    const first = await post('/api/v1/field/state', fx.operativeA1, body);
    expect(first.status).toBe(201);
    const state = (await first.json()) as { client_freshness_ms: number; authoritative_freshness_ms: number; state: string };
    expect(state.state).toBe('RESPONDING');
    expect(state.client_freshness_ms).toBe(0);
    expect(state.authoritative_freshness_ms).toBeGreaterThanOrEqual(45_000);

    const historyAfterFirst = await prisma.fieldOperativeStateHistory.count({ where: { userId: fx.operativeA1 } });
    expect(await post('/api/v1/field/state', fx.operativeA1, body)).toMatchObject({ status: 201 });
    expect(await prisma.fieldOperativeStateHistory.count({ where: { userId: fx.operativeA1 } })).toBe(historyAfterFirst);

    // WP-17/D5: the operative can read its own state back without holding
    // `field.state.read` (which is the authority over *other* operatives).
    const own = await get('/api/v1/field/state/mine', fx.operativeA1);
    expect(own.status).toBe(200);
    expect((await own.json()) as { user_id: string }).toMatchObject({ user_id: fx.operativeA1, site_id: fx.siteA1 });
  });

  it('WP-16 AC7 / WP-17 AC6: a state write is refused for a site outside the operative scope and for an unsafe site token', async () => {
    const baseBody = {
      device_id: 'device-wp17',
      state: 'AVAILABLE',
      location: null,
      source_at: new Date().toISOString(),
      freshness_ms: 0,
      trace_id: `trace-${randomUUID()}`,
    };

    const crossSite = await post('/api/v1/field/state', fx.operativeA1, { ...baseBody, site_id: fx.siteA2, idempotency_key: `state-${randomUUID()}` });
    expect(crossSite.status).toBe(403);

    const unsafe = await post('/api/v1/field/state', fx.operativeA1, { ...baseBody, site_id: 'site.a1', idempotency_key: `state-${randomUUID()}` });
    expect([400, 403]).toContain(unsafe.status);
    expect(await prisma.fieldOperativeCurrentState.count({ where: { userId: fx.operativeA1, siteId: { not: fx.siteA1 } } })).toBe(0);
  });

  it('WP-17A/C7-07: a Field write naming a nonexistent site and one naming another tenant real site are refused identically', async () => {
    // The dispatcher is org-wide-capable at the API level here only because
    // `site_id` is in the body; what must not happen is either request being
    // told which of the two failure modes it hit.
    const nonexistent = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody({ site_id: `${fx.siteA1}_ghost` }));
    const otherTenant = await post('/api/v1/field/assignments', fx.dispatcherA1, newAssignmentBody({ site_id: fx.siteB1 }));

    expect([403, 404]).toContain(nonexistent.status);
    expect(otherTenant.status).toBe(nonexistent.status);
    expect(await otherTenant.text()).toBe(await nonexistent.text());

    expect(await prisma.fieldAssignment.count({ where: { siteId: { in: [`${fx.siteA1}_ghost`, fx.siteB1] } } })).toBe(0);
  });

  it('WP-17A/C7-07: an operative state write for a nonexistent site is refused and persists nothing', async () => {
    const res = await post('/api/v1/field/state', fx.operativeA1, {
      site_id: `${fx.siteA1}_ghost`,
      device_id: 'device-wp17a',
      state: 'AVAILABLE',
      location: null,
      source_at: new Date().toISOString(),
      freshness_ms: 0,
      idempotency_key: `state-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });

    expect([403, 404]).toContain(res.status);
    expect(await prisma.fieldOperativeCurrentState.count({ where: { siteId: `${fx.siteA1}_ghost` } })).toBe(0);
    // The whole transactional bundle is absent, not just the live row.
    expect(await prisma.fieldOperativeStateHistory.count({ where: { siteId: `${fx.siteA1}_ghost` } })).toBe(0);
    expect(await prisma.fieldAuditLog.count({ where: { siteId: `${fx.siteA1}_ghost` } })).toBe(0);
    expect(await prisma.fieldOutbox.count({ where: { siteId: `${fx.siteA1}_ghost` } })).toBe(0);
  });

  it('WP-17A: the database itself rejects a live Field row pairing one organisation with another tenant site', async () => {
    // Defence in depth below the service layer: even a direct write that
    // bypasses FieldService cannot create the cross-tenant pair, because the
    // foreign key references (id, organisation_id) together rather than id.
    await expect(
      prisma.fieldAssignment.create({
        data: {
          organisationId: fx.orgA,
          siteId: fx.siteB1, // a real Site — but org B's
          assigneeUserId: fx.operativeA1,
          assignmentType: 'INCIDENT_RESPONSE',
          priority: 'SEV2',
          needToKnowSummary: 'should never persist',
          idempotencyKey: `fk-probe-${randomUUID()}`,
          createdByUserId: fx.dispatcherA1,
          updatedByUserId: fx.dispatcherA1,
        },
      }),
    ).rejects.toThrow();

    expect(await prisma.fieldAssignment.count({ where: { organisationId: fx.orgA, siteId: fx.siteB1 } })).toBe(0);
  });

  it('WP-17A: historical Field rows keep no Site foreign key, so audit history is never cascade-deletable', async () => {
    // The ruling in field.prisma: live state is constrained, recorded history
    // is not. This pins that the four historical/reliability tables have no
    // FK to sites — a future Site lifecycle must not be able to erase them.
    const constrained = await prisma.$queryRawUnsafe<Array<{ table_name: string }>>(
      `SELECT DISTINCT tc.table_name::text AS table_name
       FROM information_schema.table_constraints tc
       JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
       WHERE tc.constraint_type = 'FOREIGN KEY'
         AND ccu.table_name = 'sites'
         AND tc.table_name LIKE 'field_%'`,
    );
    const names = constrained.map((row) => row.table_name).sort();

    expect(names).toEqual(['field_assignments', 'field_operative_current_states']);
    for (const historical of ['field_operative_state_history', 'field_state_update_idempotency', 'field_audit_log', 'field_outbox']) {
      expect(names).not.toContain(historical);
    }
  });

  it('WP-16 AC7: a dispatcher cannot act on an assignment, and an operative cannot cancel one', async () => {
    const created = await createAssignment();
    const dispatcherAccept = await post(`/api/v1/field/assignments/${created.id}/accept`, fx.dispatcherA1, {
      expected_status: 'REQUESTED',
      idempotency_key: `accept-${randomUUID()}`,
    });
    expect(dispatcherAccept.status).toBe(403);

    const operativeCancel = await post(`/api/v1/field/assignments/${created.id}/cancel`, fx.operativeA1, {
      expected_status: 'REQUESTED',
      idempotency_key: `cancel-${randomUUID()}`,
    });
    expect(operativeCancel.status).toBe(403);

    // The dispatcher's own authority — cancel — does work.
    const dispatcherCancel = await post(`/api/v1/field/assignments/${created.id}/cancel`, fx.dispatcherA1, {
      expected_status: 'REQUESTED',
      idempotency_key: `cancel-${randomUUID()}`,
    });
    expect(dispatcherCancel.status).toBe(201);
    expect((await dispatcherCancel.json()) as { status: string }).toMatchObject({ status: 'CANCELLED' });
  });
});
