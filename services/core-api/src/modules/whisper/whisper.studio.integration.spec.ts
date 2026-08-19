import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { WhisperAuditPayloadSchema } from '@sentinel/contracts';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { ROLE_ACTIONS, roleHasAction } from '../identity/roles';
import { WhisperRepository } from './whisper.repository';

/**
 * WP-21B Whisper STUDIO acceptance, through the real guard chain against the
 * live stack.
 *
 * Everything here goes over HTTP with `x-dev-user-id`, because the properties
 * under test are AUTHORITY properties: who may read, edit, advance and approve
 * a silent-duress trigger, and what a refusal is allowed to disclose. Asserting
 * those against the service directly would skip the very guards that enforce
 * them. The runtime half — signatures, replay, the SILENT hand-off — lives in
 * whisper.runtime.integration.spec.ts, which needs a deterministic key
 * registry and therefore its own bootstrap.
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
  // W22-02: no ambient sweep cadence — this suite drives sweep() itself.
  PATROL_SWEEP_INTERVAL_MS: '0',
};

const tag = `wp21bs_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  /** site.commander @ siteA1 — the author in almost every test. */
  commanderA1: `${tag}_commanderA1`,
  /** site.commander @ siteA1 — the DISTINCT approver W21-12 requires. */
  approverA1: `${tag}_approverA1`,
  /** site.commander @ siteA2 — in the tenant, out of scope for siteA1. */
  commanderA2: `${tag}_commanderA2`,
  /** site.commander, organisation-wide (site_id null) — W21-03 org scope. */
  commanderOrgA: `${tag}_commanderOrgA`,
  /** A second org-wide commander, so an org-wide signal can also be approved. */
  approverOrgA: `${tag}_approverOrgA`,
  operativeA1: `${tag}_operativeA1`,
  dispatcherA1: `${tag}_dispatcherA1`,
  operatorA1: `${tag}_operatorA1`,
  investigatorA1: `${tag}_investigatorA1`,
  custodianA1: `${tag}_custodianA1`,
  adminA1: `${tag}_adminA1`,
  commanderB1: `${tag}_commanderB1`,
  operativeB1: `${tag}_operativeB1`,
};

/** Every §62 role EXCEPT site.commander, which is the only Studio authority. */
const NON_COMMANDER_ROLES: ReadonlyArray<{ user: string; role: string }> = [
  { user: fx.operativeA1, role: 'field.operative' },
  { user: fx.dispatcherA1, role: 'dispatcher' },
  { user: fx.operatorA1, role: 'operator' },
  { user: fx.investigatorA1, role: 'investigator' },
  { user: fx.custodianA1, role: 'evidence.custodian' },
  { user: fx.adminA1, role: 'admin' },
];

/** The §14.5 stages a version walks before it can be approved. */
const LIFECYCLE_TO_APPROVAL = ['SIMULATION', 'FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL'] as const;

interface VersionView {
  whisper_signal_id: string;
  organisation_id: string;
  site_id: string | null;
  name: string;
  signal_version: number;
  status: string;
  device_action_id: string;
  authorised_user_ids: string[];
  minimum_confidence: number;
  response_protocol_id: string | null;
  configuration_fingerprint: string;
  activated_at: string | null;
  rotated_at: string | null;
  retired_at: string | null;
}

interface FamilyView {
  whisper_signal_id: string;
  site_id: string | null;
  versions: VersionView[];
}

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-21B Studio Org A' },
      { id: fx.orgB, name: 'WP-21B Studio Org B' },
    ],
  });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });

  const users: Array<{ id: string; org: string; role: string; site: string | null }> = [
    { id: fx.commanderA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.approverA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.commanderA2, org: fx.orgA, role: 'site.commander', site: fx.siteA2 },
    { id: fx.commanderOrgA, org: fx.orgA, role: 'site.commander', site: null },
    { id: fx.approverOrgA, org: fx.orgA, role: 'site.commander', site: null },
    { id: fx.operativeA1, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.dispatcherA1, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
    { id: fx.operatorA1, org: fx.orgA, role: 'operator', site: fx.siteA1 },
    { id: fx.investigatorA1, org: fx.orgA, role: 'investigator', site: null },
    { id: fx.custodianA1, org: fx.orgA, role: 'evidence.custodian', site: null },
    { id: fx.adminA1, org: fx.orgA, role: 'admin', site: null },
    { id: fx.commanderB1, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.operativeB1, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  // Receipts and approvals hold Restrict relations to the version, so they go
  // first; the audit log has no foreign key at all but is a history artefact,
  // so it is removed last of the Whisper tables.
  await prisma.whisperRecognitionReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperActivationApproval.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperSignalVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
}

describe('WP-21B Whisper Studio and authority (live stack)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;
  let repository: WhisperRepository;

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const patch = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'PATCH', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const get = (path: string, userId: string) => fetch(`${base}${path}`, { headers: { 'x-dev-user-id': userId } });

  /**
   * The six semantic fields plus a trace id — the shape a DRAFT edit and a
   * version publish both take. Neither may name a site: scope belongs to the
   * family, so both schemas are `.strict()` without a `site_id` field.
   */
  function configurationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      name: 'Duress tap',
      device_action_id: 'triple-tap-power',
      authorised_user_ids: [fx.operativeA1],
      context_requirements: {},
      minimum_confidence: 0.5,
      response_protocol_id: 'SILENT_INCIDENT_RESPONSE',
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  function signalBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return { site_id: fx.siteA1, ...configurationBody(overrides) };
  }

  async function createSignal(userId = fx.commanderA1, overrides: Record<string, unknown> = {}): Promise<VersionView> {
    const res = await post('/api/v1/whisper/signals', userId, signalBody(overrides));
    expect(res.status).toBe(201);
    return (await res.json()) as VersionView;
  }

  const transition = (id: string, version: number, to: string, userId = fx.commanderA1) =>
    post(`/api/v1/whisper/signals/${id}/versions/${version}/transitions`, userId, { to, trace_id: `trace-${randomUUID()}` });

  async function advanceToApproval(id: string, version: number, userId = fx.commanderA1): Promise<void> {
    for (const to of LIFECYCLE_TO_APPROVAL) {
      const res = await transition(id, version, to, userId);
      expect(res.status).toBe(201);
    }
  }

  const activate = (id: string, version: number, userId: string) =>
    post(`/api/v1/whisper/signals/${id}/versions/${version}/activate`, userId, { trace_id: `trace-${randomUUID()}` });

  /** A family whose version 1 is ACTIVE, authored by commanderA1 and approved by approverA1. */
  async function activeSignal(overrides: Record<string, unknown> = {}): Promise<VersionView> {
    const created = await createSignal(fx.commanderA1, overrides);
    await advanceToApproval(created.whisper_signal_id, 1);
    const res = await activate(created.whisper_signal_id, 1, fx.approverA1);
    expect(res.status).toBe(201);
    return (await res.json()) as VersionView;
  }

  /** Publishes a successor version and walks it to APPROVAL. */
  async function publishToApproval(id: string, overrides: Record<string, unknown> = {}): Promise<VersionView> {
    const res = await post(`/api/v1/whisper/signals/${id}/versions`, fx.commanderA1, configurationBody({ minimum_confidence: 0.6, ...overrides }));
    expect(res.status).toBe(201);
    const published = (await res.json()) as VersionView;
    await advanceToApproval(id, published.signal_version);
    return published;
  }

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    repository = app.get(WhisperRepository);
    await seed(prisma);
  }, 120_000);

  afterAll(async () => {
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 60_000);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ==========================================================================
  // W21-12/B11-02 authority matrix
  // ==========================================================================

  it('only site.commander holds whisper signal read, manage and approve; every other role is refused on all three', async () => {
    const signal = await createSignal();

    for (const { user, role } of NON_COMMANDER_ROLES) {
      // manage
      expect((await post('/api/v1/whisper/signals', user, signalBody())).status, `${role} manage`).toBe(403);
      expect(
        (await patch(`/api/v1/whisper/signals/${signal.whisper_signal_id}/versions/1`, user, configurationBody())).status,
        `${role} manage (edit)`,
      ).toBe(403);
      // read
      expect((await get('/api/v1/whisper/signals', user)).status, `${role} read (list)`).toBe(403);
      expect((await get(`/api/v1/whisper/signals/${signal.whisper_signal_id}`, user)).status, `${role} read (detail)`).toBe(403);
      // approve
      expect((await activate(signal.whisper_signal_id, 1, user)).status, `${role} approve`).toBe(403);
    }

    // The same three calls succeed for the one role that does hold them.
    expect((await get('/api/v1/whisper/signals', fx.commanderA1)).status).toBe(200);
    expect((await get(`/api/v1/whisper/signals/${signal.whisper_signal_id}`, fx.commanderA1)).status).toBe(200);
    expect((await post('/api/v1/whisper/signals', fx.commanderA1, signalBody())).status).toBe(201);
  });

  it('only field.operative holds whisper.device-action.invoke, and holding it grants no Studio authority', async () => {
    // There is deliberately no invoke route (W21-05), so the capability itself
    // is asserted against the §62 registry that the runtime gate consults.
    for (const role of Object.keys(ROLE_ACTIONS)) {
      expect(roleHasAction(role, 'whisper.device-action.invoke'), role).toBe(role === 'field.operative');
    }
    expect(ROLE_ACTIONS['field.operative']).toContain('whisper.device-action.invoke');

    // And the invoke holder gets nothing in Studio from it.
    for (const action of ['whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve']) {
      expect(roleHasAction('field.operative', action)).toBe(false);
    }
    expect((await get('/api/v1/whisper/signals', fx.operativeA1)).status).toBe(403);
  });

  it('a foreign organisation and an out-of-scope site are refused without disclosing that the signal exists', async () => {
    const signal = await createSignal();
    const fictional = `${tag}_no_such_family`;

    const foreign = await get(`/api/v1/whisper/signals/${signal.whisper_signal_id}`, fx.commanderB1);
    const outOfScope = await get(`/api/v1/whisper/signals/${signal.whisper_signal_id}`, fx.commanderA2);
    const missing = await get(`/api/v1/whisper/signals/${fictional}`, fx.commanderA1);

    // A real-but-foreign family, a real-but-out-of-scope family and a family
    // that does not exist are the SAME answer, byte for byte.
    expect(foreign.status).toBe(404);
    expect(outOfScope.status).toBe(404);
    expect(missing.status).toBe(404);
    const [foreignBody, outOfScopeBody, missingBody] = await Promise.all([foreign.json(), outOfScope.json(), missing.json()]);
    expect(foreignBody).toEqual(missingBody);
    expect(outOfScopeBody).toEqual(missingBody);

    // Nothing about the configuration leaks through the refusal.
    for (const body of [foreignBody, outOfScopeBody]) {
      const text = JSON.stringify(body);
      expect(text).not.toContain(signal.whisper_signal_id);
      expect(text).not.toContain('triple-tap-power');
      expect(text).not.toContain(fx.operativeA1);
      expect(text).not.toContain('Duress tap');
    }

    // Nor through the list, which is the other way a roster could surface.
    const foreignList = (await (await get('/api/v1/whisper/signals', fx.commanderB1)).json()) as VersionView[];
    const outOfScopeList = (await (await get('/api/v1/whisper/signals', fx.commanderA2)).json()) as VersionView[];
    expect(foreignList.some((row) => row.whisper_signal_id === signal.whisper_signal_id)).toBe(false);
    expect(outOfScopeList.some((row) => row.whisper_signal_id === signal.whisper_signal_id)).toBe(false);
  });

  it('a site-scoped commander cannot administer an organisation-wide signal; an organisation-wide grant can', async () => {
    // W21-03: site_id null means "recognisable at every site in the tenant",
    // so authoring one is an organisation-wide power.
    const refused = await post('/api/v1/whisper/signals', fx.commanderA1, signalBody({ site_id: null }));
    expect(refused.status).toBe(403);

    const orgWide = await createSignal(fx.commanderOrgA, { site_id: null });
    expect(orgWide.site_id).toBeNull();

    // And an org-wide signal is invisible to a site-scoped grant, because
    // `site_id IN (...)` is never true for a NULL.
    expect((await get(`/api/v1/whisper/signals/${orgWide.whisper_signal_id}`, fx.commanderA1)).status).toBe(404);
    expect((await patch(`/api/v1/whisper/signals/${orgWide.whisper_signal_id}/versions/1`, fx.commanderA1, configurationBody({ minimum_confidence: 0.9 }))).status).toBe(404);
    expect((await get(`/api/v1/whisper/signals/${orgWide.whisper_signal_id}`, fx.commanderOrgA)).status).toBe(200);
  });

  it('a foreign-tenant authorised_user_id is refused without naming which id failed', async () => {
    const res = await post('/api/v1/whisper/signals', fx.commanderA1, signalBody({ authorised_user_ids: [fx.operativeA1, fx.operativeB1] }));
    expect(res.status).toBe(400);
    const text = JSON.stringify(await res.json());
    // Naming the failing id would turn signal authoring into a cross-tenant
    // user-existence oracle (B11-05).
    expect(text).not.toContain(fx.operativeB1);
    expect(text).toContain('authorised_user_ids');

    // A wholly fictional id is refused identically.
    const fictional = await post('/api/v1/whisper/signals', fx.commanderA1, signalBody({ authorised_user_ids: [`${tag}_ghost_user`] }));
    expect(fictional.status).toBe(400);
    expect(JSON.stringify(await fictional.json())).not.toContain(`${tag}_ghost_user`);
  });

  // ==========================================================================
  // W21-02 configuration freeze
  // ==========================================================================

  it('a DRAFT semantic edit succeeds and re-fingerprints the configuration', async () => {
    const created = await createSignal();
    const res = await patch(`/api/v1/whisper/signals/${created.whisper_signal_id}/versions/1`, fx.commanderA1, configurationBody({ minimum_confidence: 0.85 }));
    expect(res.status).toBe(200);
    const edited = (await res.json()) as VersionView;

    expect(edited.status).toBe('DRAFT');
    expect(edited.signal_version).toBe(1);
    expect(edited.minimum_confidence).toBe(0.85);
    expect(edited.configuration_fingerprint).not.toBe(created.configuration_fingerprint);

    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({
      where: { organisationId: fx.orgA, whisperSignalId: created.whisper_signal_id, signalVersion: 1 },
    });
    expect(stored.minimumConfidence).toBe(0.85);
    expect(stored.configurationFingerprint).toBe(edited.configuration_fingerprint);
  });

  it('a non-DRAFT semantic edit is refused with 409 and requires a new version', async () => {
    const created = await createSignal();
    expect((await transition(created.whisper_signal_id, 1, 'SIMULATION')).status).toBe(201);

    const res = await patch(`/api/v1/whisper/signals/${created.whisper_signal_id}/versions/1`, fx.commanderA1, configurationBody({ minimum_confidence: 0.95 }));
    expect(res.status).toBe(409);
    expect(JSON.stringify(await res.json())).toContain('publish a new version');

    // The stored configuration did not move.
    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({
      where: { organisationId: fx.orgA, whisperSignalId: created.whisper_signal_id, signalVersion: 1 },
    });
    expect(stored.minimumConfidence).toBe(0.5);
    expect(stored.configurationFingerprint).toBe(created.configuration_fingerprint);

    // A no-op re-submission of the SAME configuration is not an edit, so it is
    // not refused — an idempotent retry that already succeeded must not 409.
    const unchanged = await patch(`/api/v1/whisper/signals/${created.whisper_signal_id}/versions/1`, fx.commanderA1, configurationBody({ minimum_confidence: 0.5 }));
    expect(unchanged.status).toBe(200);

    // The remedy the 409 names actually works, and starts again at DRAFT.
    const published = await post(`/api/v1/whisper/signals/${created.whisper_signal_id}/versions`, fx.commanderA1, configurationBody({ minimum_confidence: 0.95 }));
    expect(published.status).toBe(201);
    const next = (await published.json()) as VersionView;
    expect(next.signal_version).toBe(2);
    expect(next.status).toBe('DRAFT');
  });

  // ==========================================================================
  // §14.5 lifecycle
  // ==========================================================================

  it('lifecycle stages cannot be skipped', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;

    // Every stage other than the single legal successor is refused.
    for (const to of ['FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL', 'ROTATED', 'RETIRED']) {
      const res = await transition(id, 1, to);
      expect(res.status, `DRAFT -> ${to}`).toBe(409);
    }
    // And a DRAFT cannot be activated straight to ACTIVE either.
    const shortcut = await activate(id, 1, fx.approverA1);
    expect(shortcut.status).toBe(409);
    expect(JSON.stringify(await shortcut.json())).toContain('APPROVAL');

    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    expect(stored.status).toBe('DRAFT');
    expect(stored.activatedAt).toBeNull();
  });

  it('a ROTATED or RETIRED version cannot be resurrected into any status', async () => {
    // ROTATED: activate a successor over an incumbent.
    const active = await activeSignal();
    const id = active.whisper_signal_id;
    const successor = await publishToApproval(id);
    expect((await activate(id, successor.signal_version, fx.approverA1)).status).toBe(201);

    const rotated = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    expect(rotated.status).toBe('ROTATED');

    for (const to of ['DRAFT', 'SIMULATION', 'APPROVAL', 'RETIRED']) {
      expect((await transition(id, 1, to)).status, `ROTATED -> ${to}`).toBe(409);
    }
    expect((await activate(id, 1, fx.approverA1)).status).toBe(409);

    // RETIRED: withdraw the incumbent and prove the same.
    expect((await transition(id, successor.signal_version, 'RETIRED')).status).toBe(201);
    for (const to of ['DRAFT', 'SIMULATION', 'APPROVAL', 'ROTATED']) {
      expect((await transition(id, successor.signal_version, to)).status, `RETIRED -> ${to}`).toBe(409);
    }
    expect((await activate(id, successor.signal_version, fx.approverA1)).status).toBe(409);

    const final = await prisma.whisperSignalVersion.findMany({ where: { organisationId: fx.orgA, whisperSignalId: id }, orderBy: { signalVersion: 'asc' } });
    expect(final.map((row) => row.status)).toEqual(['ROTATED', 'RETIRED']);
  });

  it('the generic transitions endpoint refuses to: ACTIVE even where the lifecycle table allows it', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;
    await advanceToApproval(id, 1);

    // APPROVAL -> ACTIVE is legal in the contract's table, and is still refused
    // here: activation needs a distinct approver and a fingerprint binding, so
    // it must not have a second door (W21-12/W21-13).
    const res = await transition(id, 1, 'ACTIVE');
    expect(res.status).toBe(409);
    expect(JSON.stringify(await res.json())).toContain('activate');

    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    expect(stored.status).toBe('APPROVAL');
    expect(await prisma.whisperActivationApproval.count({ where: { signalVersionId: stored.id } })).toBe(0);
  });

  // ==========================================================================
  // W21-12/W21-13 activation
  // ==========================================================================

  it('the creator of a version cannot activate it; a distinct approver can', async () => {
    const created = await createSignal(fx.commanderA1);
    const id = created.whisper_signal_id;
    await advanceToApproval(id, 1);

    const selfApproval = await activate(id, 1, fx.commanderA1);
    expect(selfApproval.status).toBe(409);
    expect(JSON.stringify(await selfApproval.json())).toContain('distinct');
    const draftRow = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    expect(await prisma.whisperActivationApproval.count({ where: { signalVersionId: draftRow.id } })).toBe(0);

    const res = await activate(id, 1, fx.approverA1);
    expect(res.status).toBe(201);
    const activated = (await res.json()) as VersionView;
    expect(activated.status).toBe('ACTIVE');
    expect(activated.activated_at).not.toBeNull();

    const approval = await prisma.whisperActivationApproval.findFirstOrThrow({ where: { signalVersionId: draftRow.id } });
    expect(approval.createdByUserId).toBe(fx.commanderA1);
    expect(approval.approvedByUserId).toBe(fx.approverA1);
  });

  it('activation binds the CURRENT persisted configuration fingerprint', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;

    // A DRAFT edit moves the fingerprint; the approval must bind the value that
    // is actually stored at activation time, not the one that was authored.
    const edited = (await (await patch(`/api/v1/whisper/signals/${id}/versions/1`, fx.commanderA1, configurationBody({ minimum_confidence: 0.75 }))).json()) as VersionView;
    expect(edited.configuration_fingerprint).not.toBe(created.configuration_fingerprint);
    await advanceToApproval(id, 1);

    expect((await activate(id, 1, fx.approverA1)).status).toBe(201);
    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    const approval = await prisma.whisperActivationApproval.findFirstOrThrow({ where: { signalVersionId: stored.id } });
    expect(approval.configurationFingerprint).toBe(stored.configurationFingerprint);
    expect(approval.configurationFingerprint).toBe(edited.configuration_fingerprint);
  });

  it('an activation whose expected fingerprint no longer matches the stored configuration is refused', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;
    await advanceToApproval(id, 1);

    // Simulate the configuration moving between the service's read and the
    // repository's compare-and-set: the CAS is what makes W21-13 durable, so it
    // must refuse rather than promote something the approver never saw.
    const real = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    vi.spyOn(repository, 'findVersion').mockResolvedValueOnce({ ...real, configurationFingerprint: 'a'.repeat(64) });

    const res = await activate(id, 1, fx.approverA1);
    expect(res.status).toBe(409);
    expect(JSON.stringify(await res.json())).toContain('changed configuration');

    const after = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { id: real.id } });
    expect(after.status).toBe('APPROVAL');
    expect(await prisma.whisperActivationApproval.count({ where: { signalVersionId: real.id } })).toBe(0);
  });

  it('activating a successor rotates the incumbent atomically, leaving exactly one ACTIVE version', async () => {
    const active = await activeSignal();
    const id = active.whisper_signal_id;
    const successor = await publishToApproval(id);

    const res = await activate(id, successor.signal_version, fx.approverA1);
    expect(res.status).toBe(201);

    const versions = await prisma.whisperSignalVersion.findMany({ where: { organisationId: fx.orgA, whisperSignalId: id }, orderBy: { signalVersion: 'asc' } });
    expect(versions.filter((row) => row.status === 'ACTIVE')).toHaveLength(1);
    expect(versions[0]?.status).toBe('ROTATED');
    expect(versions[0]?.rotatedAt).not.toBeNull();
    expect(versions[1]?.status).toBe('ACTIVE');
    expect(versions[1]?.activatedAt).not.toBeNull();

    // The rotation is audited against the version it rotated.
    expect(
      await prisma.whisperAuditLog.count({ where: { organisationId: fx.orgA, whisperSignalId: id, kind: 'WHISPER_ROTATED', signalVersion: 1 } }),
    ).toBe(1);
  });

  it('concurrent successor activations leave exactly one ACTIVE version of the family', async () => {
    const active = await activeSignal();
    const id = active.whisper_signal_id;
    const second = await publishToApproval(id);
    const third = await publishToApproval(id);

    // Two successors of one family, activated at the same instant. The family
    // lock serialises them; whatever the order, the invariant is the same.
    const [a, b] = await Promise.all([activate(id, second.signal_version, fx.approverA1), activate(id, third.signal_version, fx.approverA1)]);
    expect([a.status, b.status].every((status) => status === 201 || status === 409)).toBe(true);

    const versions = await prisma.whisperSignalVersion.findMany({ where: { organisationId: fx.orgA, whisperSignalId: id } });
    expect(versions.filter((row) => row.status === 'ACTIVE')).toHaveLength(1);
    // Everything that was ever ACTIVE and is no longer is ROTATED, never left behind.
    expect(versions.filter((row) => row.status === 'APPROVAL' && row.activatedAt !== null)).toHaveLength(0);
    expect(await prisma.whisperActivationApproval.count({ where: { signalVersionId: { in: versions.filter((r) => r.status === 'ACTIVE').map((r) => r.id) } } })).toBe(1);
  });

  it('concurrent activations of the SAME version produce exactly one activation approval', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;
    await advanceToApproval(id, 1);

    const results = await Promise.all([activate(id, 1, fx.approverA1), activate(id, 1, fx.approverA1)]);
    const statuses = results.map((res) => res.status).sort((x, y) => x - y);
    expect(statuses).toEqual([201, 409]);

    const stored = await prisma.whisperSignalVersion.findFirstOrThrow({ where: { organisationId: fx.orgA, whisperSignalId: id, signalVersion: 1 } });
    expect(stored.status).toBe('ACTIVE');
    expect(await prisma.whisperActivationApproval.count({ where: { signalVersionId: stored.id } })).toBe(1);
  });

  // ==========================================================================
  // W21-14 audit
  // ==========================================================================

  it('every persisted Whisper audit payload parses through WhisperAuditPayloadSchema', async () => {
    const active = await activeSignal();
    await publishToApproval(active.whisper_signal_id);

    const rows = await prisma.whisperAuditLog.findMany({ where: { organisationId: { in: [fx.orgA, fx.orgB] } } });
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(() => WhisperAuditPayloadSchema.parse(row.payload), `${row.kind} ${row.id}`).not.toThrow();
    }
  });

  it('the Whisper audit log is append-only', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;
    const before = await prisma.whisperAuditLog.findMany({ where: { organisationId: fx.orgA }, orderBy: { id: 'asc' } });

    await advanceToApproval(id, 1);
    expect((await activate(id, 1, fx.approverA1)).status).toBe(201);
    expect((await transition(id, 1, 'RETIRED')).status).toBe(201);

    const after = await prisma.whisperAuditLog.findMany({ where: { organisationId: fx.orgA }, orderBy: { id: 'asc' } });
    expect(after.length).toBeGreaterThan(before.length);

    // Every row that existed before is still there, unchanged in every column.
    const afterById = new Map(after.map((row) => [row.id, row]));
    for (const row of before) {
      expect(afterById.get(row.id)).toEqual(row);
    }
  });

  it('no Studio audit payload discloses the authorised-user roster or the configuration itself', async () => {
    const active = await activeSignal({ authorised_user_ids: [fx.operativeA1], device_action_id: 'silent-long-press' });

    const rows = await prisma.whisperAuditLog.findMany({ where: { organisationId: fx.orgA, whisperSignalId: active.whisper_signal_id } });
    expect(rows.length).toBeGreaterThan(0);
    const text = JSON.stringify(rows.map((row) => row.payload));
    // The roster and the discreet action are the two things a leaked audit row
    // would hand an attacker; only the DIGEST of the configuration may appear.
    expect(text).not.toContain(fx.operativeA1);
    expect(text).not.toContain('silent-long-press');
    expect(text).toContain(active.configuration_fingerprint);
  });

  // ==========================================================================
  // B11-04 Studio reads
  // ==========================================================================

  it('a family detail lists its whole version history newest first', async () => {
    const created = await createSignal();
    const id = created.whisper_signal_id;
    await advanceToApproval(id, 1);
    expect((await activate(id, 1, fx.approverA1)).status).toBe(201);
    await publishToApproval(id);

    const family = (await (await get(`/api/v1/whisper/signals/${id}`, fx.commanderA1)).json()) as FamilyView;
    expect(family.whisper_signal_id).toBe(id);
    expect(family.site_id).toBe(fx.siteA1);
    expect(family.versions.map((row) => row.signal_version)).toEqual([2, 1]);
    expect(family.versions.map((row) => row.status)).toEqual(['APPROVAL', 'ACTIVE']);
  });
});
