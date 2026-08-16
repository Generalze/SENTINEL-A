import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { io, type Socket } from 'socket.io-client';
import { randomUUID } from 'node:crypto';
import { AppModule } from '../../services/core-api/src/app.module';
import { PrismaService } from '../../services/core-api/src/prisma/prisma.service';
import { LedgerService } from '../../services/core-api/src/modules/ledger/ledger.service';
import { IncidentsService } from '../../services/core-api/src/modules/incidents/incidents.service';
import { ConstitutionService, PLATFORM_ORGANISATION_ID } from '../../services/core-api/src/modules/constitution/constitution.service';
import { SENTINEL_BASELINE_POLICY } from '../../services/core-api/src/modules/constitution/constitution.policy';
import { seedIdentity, type IdentitySeedFixture } from '../../services/core-api/src/modules/identity/seed';
import { runScenario } from '../../packages/simulator/src/runner';
import { proofAIntrusionV1, proofAIntrusionContradictionV1, duplicateDeliveryV1, singleSourceNoiseV1 } from '../../packages/simulator/src/scenarios';

const live = process.env.PROOF_A_LIVE === '1';
const describeLive = live ? describe : describe.skip;
const suffix = `${Date.now()}_${process.pid}`;
const org = `proof_a_${suffix}`;
const otherOrg = `proof_a_other_${suffix}`;
const site = `proof_site_${suffix}`;
const operator = `proof_operator_${suffix}`;
const field = `proof_field_${suffix}`;
const investigator = `proof_investigator_${suffix}`;
const otherOperator = `proof_other_operator_${suffix}`;
const commanderOne = `proof_commander_one_${suffix}`;
const commanderTwo = `proof_commander_two_${suffix}`;
let app: NestExpressApplication;
let prisma: PrismaService;
let baseUrl: string;
let commandSocket: Socket;
let otherSocket: Socket;
interface HypothesisPayload { hypothesis_id: string; state: number; source_diversity: number; operational_severity: string; }
interface IncidentTask { id: string; task_type: string; delivery_state: string; }
interface IncidentPayload { id: string; severity: string; timeline: Array<{ kind: string }>; tasks: IncidentTask[]; }
const wsUpdates: unknown[] = [];
const otherUpdates: unknown[] = [];

async function waitFor(check: () => Promise<boolean>, timeout = 20_000): Promise<void> {
  const deadline = Date.now() + timeout;
  while (!(await check())) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for live Proof-A condition');
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
async function api(path: string, user: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${baseUrl}${path}`, { ...init, headers: { 'x-dev-user-id': user, ...(init.headers ?? {}) } });
}
async function connect(user: string, received: unknown[]): Promise<Socket> {
  const socket = io(baseUrl, { path: '/ws', transports: ['websocket'], auth: { userId: user } });
  socket.on('incident.updated', (payload) => received.push(payload));
  await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('connect_error', reject); });
  return socket;
}
function isIncidentUpdate(value: unknown, incidentId: string): boolean {
  return typeof value === 'object' && value !== null && 'id' in value && (value as { id?: unknown }).id === incidentId;
}

describeLive('WP-13 Proof A (live compose + booted core-api)', () => {
  beforeAll(async () => {
    app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address() as { port: number };
    baseUrl = `http://127.0.0.1:${address.port}`;
    prisma = app.get(PrismaService);
    const constitution = app.get(ConstitutionService);
    if (constitution.activePolicy.version !== SENTINEL_BASELINE_POLICY.version) {
      await constitution.createDraft(SENTINEL_BASELINE_POLICY, 'proof-a-platform-admin').catch((error: unknown) => {
        if (!(error instanceof Error) || !error.message.includes('Unique constraint')) throw error;
      });
      const upgraded = await constitution.activatePolicy({
        version: SENTINEL_BASELINE_POLICY.version,
        actor: { userId: 'proof-a-platform-steward', roles: ['constitution.steward'], organisationId: PLATFORM_ORGANISATION_ID, clearance: 5, purpose: 'proof-a policy upgrade', deviceTrust: 'TRUSTED' },
        approvals: [{ userId: 'proof-a-admin-approval', role: 'platform.admin', at: new Date().toISOString() }, { userId: 'proof-a-security', role: 'security.officer', at: new Date().toISOString() }],
        approver_roles: { 'proof-a-admin-approval': ['platform.admin'], 'proof-a-security': ['security.officer'] }, traceId: `proof-a-policy-upgrade-${suffix}`,
      });
      expect(upgraded.decision.decision).toBe('ALLOW');
      expect(upgraded.active.version).toBe(SENTINEL_BASELINE_POLICY.version);
    }
    const proofFixture: IdentitySeedFixture = {
      organisation: { id: org, name: 'Proof A' },
      site: { id: site, name: 'Proof Site' },
      zones: [{ id: `${site}_vault`, name: 'Vault' }, { id: `${site}_lobby`, name: 'Lobby' }, { id: `${site}_perimeter`, name: 'Perimeter' }],
      users: [
        { id: operator, email: `${operator}@test`, displayName: 'Operator', clearance: 5, role: 'operator', siteScoped: true },
        { id: field, email: `${field}@test`, displayName: 'Field', clearance: 5, role: 'field.operative', siteScoped: true },
        { id: investigator, email: `${investigator}@test`, displayName: 'Investigator', clearance: 5, role: 'investigator', siteScoped: false },
        { id: commanderOne, email: `${commanderOne}@test`, displayName: 'Commander One', clearance: 5, role: 'site.commander', siteScoped: true },
        { id: commanderTwo, email: `${commanderTwo}@test`, displayName: 'Commander Two', clearance: 5, role: 'site.commander', siteScoped: true },
      ],
    };
    const otherFixture: IdentitySeedFixture = {
      organisation: { id: otherOrg, name: 'Proof A Other' },
      site: { id: `${otherOrg}_site`, name: 'Other Site' },
      zones: [],
      users: [{ id: otherOperator, email: `${otherOperator}@test`, displayName: 'Other', clearance: 5, role: 'operator', siteScoped: false }],
    };
    await seedIdentity(prisma, proofFixture);
    await seedIdentity(prisma, otherFixture);
    commandSocket = await connect(operator, wsUpdates);
    otherSocket = await connect(otherOperator, otherUpdates);
  }, 45_000);

  afterAll(async () => {
    commandSocket?.disconnect(); otherSocket?.disconnect();
    await app?.close();
  });

  it('runs every Proof-A acceptance assertion end to end', async () => {
    const now = new Date(Math.floor(Date.now() / 900_000) * 900_000 + 60_000);
    const initial = await runScenario(proofAIntrusionV1, { baseUrl, orgId: org, siteId: site, zoneIds: { vault_corridor: `${site}_vault`, lobby: `${site}_lobby`, perimeter_west: `${site}_perimeter` }, apiHeaders: { 'x-dev-user-id': operator }, speed: Infinity, now: () => now, traceId: `proof-a-${suffix}` });
    expect(initial.results.every((r) => r.ok)).toBe(true);
    await waitFor(async () => (await prisma.incident.count({ where: { organisationId: org } })) === 1);
    await waitFor(async () => (await prisma.hypothesis.findFirst({ where: { organisationId: org } }))?.state >= 3);
    const hypotheses = await (await api('/api/v1/hypotheses', operator)).json() as { items: HypothesisPayload[] };
    expect(hypotheses.items).toHaveLength(1);
    const hypothesis = hypotheses.items[0];
    expect(hypothesis.state).toBeGreaterThanOrEqual(3); expect(hypothesis.source_diversity).toBeGreaterThanOrEqual(2);
    expect(hypothesis).toMatchObject({ detection_confidence: expect.any(Number), threat_probability: expect.any(Number), potential_impact: expect.any(String), operational_severity: expect.any(String) });
    const hypothesisDetail = await (await api(`/api/v1/hypotheses/${hypothesis.hypothesis_id}`, operator)).json() as { transitions: unknown[] };
    expect(hypothesisDetail.transitions.length).toBeGreaterThan(0);
    await waitFor(async () => (await prisma.responseTask.count({ where: { incident: { organisationId: org } } })) === 3);
    await waitFor(async () => (await prisma.responseTask.findFirst({ where: { taskType: 'dispatch-field', incident: { organisationId: org } } }))?.deliveryState === 'DELIVERED');
    const incidents = await (await api('/api/v1/incidents', operator)).json() as Array<{ id: string }>;
    expect(incidents).toHaveLength(1); const incident = await (await api(`/api/v1/incidents/${incidents[0].id}`, operator)).json() as IncidentPayload; expect(incident.severity).toBe(hypothesis.operational_severity); expect(incident.timeline.length).toBeGreaterThan(0);
    await waitFor(async () => wsUpdates.length > 0);
    const dispatch = incident.tasks.find((t) => t.task_type === 'dispatch-field'); expect(dispatch?.delivery_state).toBe('DELIVERED');
    const ledger = app.get(LedgerService); const chain = await ledger.verifyChain(org); expect(chain.valid).toBe(true);
    const ledgerRows = await prisma.decisionLedgerEntry.findMany({ where: { organisationId: org, actionTaken: 'ALLOW', policyVersion: SENTINEL_BASELINE_POLICY.version } });
    expect(ledgerRows.length).toBeGreaterThan(0); expect(ledgerRows[0].policyVersion).toBeTruthy(); expect(ledgerRows[0].contentHash).toBeTruthy();
    const evidence = await prisma.evidence.findFirstOrThrow({ where: { organisationId: org, incidentId: incident.id } });
    const verify = await api(`/api/v1/evidence/${evidence.id}/verify`, investigator, { method: 'POST' }); expect(verify.ok).toBe(true);
    const content = await api(`/api/v1/evidence/${evidence.id}/content`, investigator, { headers: { 'x-purpose': 'proof-a' } }); expect(content.headers.get('x-evidence-content-hash')).toBe(evidence.contentHash);
    expect((await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id } })).map((x) => x.action)).toEqual(expect.arrayContaining(['INGESTED', 'VIEWED']));
    const wsBeforeAck = wsUpdates.length;
    const ack = await api(`/api/v1/incidents/${incident.id}/tasks/${dispatch!.id}/ack`, field, { method: 'POST' }); expect(ack.ok).toBe(true);
    const acked = await ack.json() as IncidentPayload; expect(acked.tasks.find((t) => t.id === dispatch!.id)?.delivery_state).toBe('ACKNOWLEDGED'); expect(acked.timeline.some((t) => t.kind === 'FIELD_DISPATCH_ACKNOWLEDGED')).toBe(true);
    await waitFor(async () => wsUpdates.slice(wsBeforeAck).some((payload) => isIncidentUpdate(payload, incident.id)));
    const contradiction = await runScenario(proofAIntrusionContradictionV1, { baseUrl, orgId: org, siteId: site, zoneIds: { vault_corridor: `${site}_vault` }, apiHeaders: { 'x-dev-user-id': operator }, speed: Infinity, now: () => now });
    expect(contradiction.results.at(-1)?.ok).toBe(true);
    await waitFor(async () => (await prisma.hypothesis.findFirstOrThrow({ where: { id: hypothesis.hypothesis_id } })).contradictingEventIds.length > 0);
    const lowered = await (await api(`/api/v1/hypotheses/${hypothesis.hypothesis_id}`, operator)).json() as { state: number; contradicting_event_ids: string[] }; expect(lowered.state).toBeLessThan(hypothesis.state); expect(lowered.contradicting_event_ids.length).toBeGreaterThan(0);
    const duplicate = await runScenario(duplicateDeliveryV1, { baseUrl, orgId: org, siteId: site, zoneIds: { lobby: `${site}_lobby` }, apiHeaders: { 'x-dev-user-id': operator }, speed: Infinity, now: () => now }); expect(duplicate.results.filter((r) => r.duplicate).length).toBe(2);
    const noise = await runScenario(singleSourceNoiseV1, { baseUrl, orgId: org, siteId: site, zoneIds: { perimeter_west: `${site}_perimeter` }, apiHeaders: { 'x-dev-user-id': operator }, speed: Infinity, now: () => now }); expect(noise.results.every((r) => r.ok)).toBe(true);
    await waitFor(async () => (await prisma.hypothesis.findFirst({ where: { organisationId: org, zoneId: `${site}_perimeter` } })) !== null);
    expect((await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: org, zoneId: `${site}_perimeter` } })).state).toBeLessThanOrEqual(2);
    expect(await (await api('/api/v1/incidents', otherOperator)).json()).toEqual([]); expect((await (await api('/api/v1/hypotheses', otherOperator)).json() as { items: unknown[] }).items).toEqual([]);
    expect(otherUpdates).toEqual([]);

    const silentHypothesis = randomUUID();
    const silentCandidate = await app.get(IncidentsService).handleCandidate({
      schema_version: 1, incident_candidate_id: randomUUID(), hypothesis_id: silentHypothesis, organisation_id: org, site_id: site, zone_id: null,
      threat_state: 4, detection_confidence: 0.9, threat_probability: 0.9, potential_impact: 'HIGH', operational_severity: 'SEV1',
      supporting_event_ids: [], contradicting_event_ids: [], confidence_explanation: 'isolated silent approval proof', rule_or_model_versions: ['fusion-rules-1.0.0', 'duress'],
      re_escalation: false, emission_number: 1, triggering_event_id: `silent-${suffix}`, emitted_at: new Date().toISOString(),
      hypothesis_version: 1,
    });
    const silentDispatch = silentCandidate.tasks.find((task) => task.task_type === 'dispatch-field');
    expect(silentDispatch?.delivery_state).toBe('REQUESTED');
    const afterFirstApproval = await api(`/api/v1/incidents/${silentCandidate.id}/tasks/${silentDispatch!.id}/silent-approvals`, commanderOne, { method: 'POST' });
    expect(afterFirstApproval.ok).toBe(true);
    expect((await afterFirstApproval.json() as IncidentPayload).tasks.find((task) => task.id === silentDispatch!.id)?.delivery_state).toBe('REQUESTED');
    const afterSecondApproval = await api(`/api/v1/incidents/${silentCandidate.id}/tasks/${silentDispatch!.id}/silent-approvals`, commanderTwo, { method: 'POST' });
    expect(afterSecondApproval.ok).toBe(true);
    expect((await afterSecondApproval.json() as IncidentPayload).tasks.find((task) => task.id === silentDispatch!.id)?.delivery_state).toBe('DELIVERED');
    const silentLedger = await prisma.decisionLedgerEntry.findMany({ where: { organisationId: org, policyVersion: SENTINEL_BASELINE_POLICY.version } });
    expect(silentLedger.some((entry) => entry.actionTaken === 'REQUIRE_TWO_PERSON')).toBe(true);
    expect(silentLedger.some((entry) => entry.actionTaken === 'ALLOW')).toBe(true);
  }, 90_000);
});
