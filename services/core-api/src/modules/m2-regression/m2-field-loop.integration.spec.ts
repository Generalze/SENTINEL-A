import { generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import {
  canonicalWhisperSignedStatement,
  FIELD_OFFLINE_OPERATION_KINDS,
  FieldOfflineOperationV2Schema,
  WHISPER_SIGNATURE_ALGORITHM,
  whisperConfigurationFingerprint,
  whisperRecognitionFingerprint,
  type AuthenticatedFieldDeviceContext,
  type AuthenticatedWhisperDeviceContext,
  type DeviceActionWhisperResult,
  type OfflineOperationResult,
  type OfflineReplayConflict,
} from '@sentinel/contracts';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { PrismaService } from '../../prisma/prisma.service';
import { TIMELINE_MESSAGE_ACKNOWLEDGED, TIMELINE_MESSAGE_SENT } from '../field-messaging/field-messaging.constants';
import { FieldOutboxPublisher } from '../field/field-outbox.publisher';
import { FieldOfflineReplayService } from '../field-offline/field-offline.service';
import type { OfflineSubmissionOutcome } from '../field-offline/field-offline.types';
import { PatrolMissedSweeper } from '../patrol/patrol-missed.sweeper';
import { WS_EVENT_FIELD_UPDATED, WS_PATH } from '../realtime/realtime.constants';
import { WHISPER_DEVICE_KEY_RESOLVER, type WhisperDeviceKeyResolver } from '../whisper/whisper-key.resolver';
import { WhisperSignatureVerifier } from '../whisper/whisper-signature.verifier';
import { ACTION_WHISPER_DEVICE_ACTION_INVOKE } from '../whisper/whisper.constants';
import { WhisperRepository } from '../whisper/whisper.repository';
import { WhisperService } from '../whisper/whisper.service';

/**
 * WP-22 MILESTONE 2 INTEGRATED LIVE REGRESSION.
 *
 * Every Milestone 2 work package has its own acceptance suite, and each proves
 * its own module against the live stack. None of them proves that the modules
 * still hold their promises WHEN COMPOSED — that one operative, on one
 * incident, at one site, can be assigned, report state, be messaged, walk a
 * patrol, reconnect from offline and raise a silent duress signal without any
 * one of those surfaces weakening another's boundary.
 *
 * That is what this file is. It is deliberately ONE narrative over ONE tenant
 * fixture, in declaration order, plus the adversaries who must be refused at
 * every step:
 *
 *   W22-03  the integrated Field loop (assignment -> state -> message ->
 *           patrol -> offline replay -> Whisper).
 *   W22-04  isolation and need-to-know across the whole loop at once.
 *   W22-05  effectively-once, integrated: the same duplicate rules the offline
 *           and Whisper suites prove in isolation, asserted over shared state
 *           that other tests have already written to.
 *   W22-06  the Whisper Crucible, integrated: the four properties that make a
 *           silent duress channel safe to have at all.
 *
 * WHAT THIS SUITE DOES NOT DO
 * ---------------------------
 * It does not re-prove a module's internal truth table — WP-16..WP-21B own
 * those, and duplicating them here would only mean two places to update. Every
 * assertion below is about a SEAM: an authority granted in one module being
 * honoured (or refused) in another, or a boundary that would only fail once
 * the modules share a tenant, an incident and an operative.
 *
 * W22-02 NOTE. `PATROL_SWEEP_INTERVAL_MS` is '0', so no background sweep timer
 * exists and `PatrolMissedSweeper.sweep()` is driven explicitly. The Field
 * outbox publisher is likewise driven explicitly where a socket assertion
 * depends on it, rather than waited on.
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  // 127.0.0.1, not localhost: this suite opens a socket and needs NATS, and on
  // Windows `localhost` resolves to ::1 first and stalls the nats client for
  // ~27s (documented in realtime/test-integration-support.ts).
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

const tag = `m2_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  /** Creator of routes and signals; first of the two distinct silent approvers. */
  commanderA1: `${tag}_commanderA1`,
  /** The SECOND distinct site.commander — W21-12 activation and the two-approver silent dispatch both need one. */
  commanderA1b: `${tag}_commanderA1b`,
  dispatcherA1: `${tag}_dispatcherA1`,
  /** The operative the whole narrative follows. */
  opAlpha: `${tag}_opAlpha`,
  /** Same site, same role, NOT assigned and NOT named: the insider adversary. */
  opBravo: `${tag}_opBravo`,
  /** Right tenant, wrong site. */
  operativeA2: `${tag}_operativeA2`,
  commanderB1: `${tag}_commanderB1`,
  opB1: `${tag}_opB1`,
  deviceAlpha: `${tag}_deviceAlpha`,
  keyAlpha: `${tag}_keyAlpha`,
  incidentA1: randomUUID(),
};

const DEVICE_ACTION = 'triple-tap-power';
const LIFECYCLE_TO_APPROVAL = ['SIMULATION', 'FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL'] as const;

type UnsignedResult = Omit<DeviceActionWhisperResult, 'signature'>;

/**
 * The deterministic stand-in for the device-identity facility WP-21B does not
 * ship, keyed by (organisation, key id) exactly as the real seam must. The
 * shipped resolver resolves nothing, so without this override every
 * recognition here would refuse with SIGNATURE_INVALID and prove nothing.
 */
class TestDeviceKeyRegistry implements WhisperDeviceKeyResolver {
  private readonly keys = new Map<string, KeyObject>();

  register(organisationId: string, verificationKeyId: string, publicKey: KeyObject): void {
    this.keys.set(`${organisationId} ${verificationKeyId}`, publicKey);
  }

  async resolveVerificationKey(organisationId: string, verificationKeyId: string): Promise<KeyObject | null> {
    return this.keys.get(`${organisationId} ${verificationKeyId}`) ?? null;
  }
}

const keyAlpha = generateKeyPairSync('ed25519');
/** Never registered anywhere: the "wrong key" every forgery assertion signs with. */
const unregisteredKey = generateKeyPairSync('ed25519');

const keyRegistry = new TestDeviceKeyRegistry();
keyRegistry.register(fx.orgA, fx.keyAlpha, keyAlpha.publicKey);

/** Signs EXACTLY the canonical statement, unpadded base64url, as W21-06 requires. */
function signResult(unsigned: UnsignedResult, privateKey: KeyObject): DeviceActionWhisperResult {
  const statement = canonicalWhisperSignedStatement(unsigned);
  return { ...unsigned, signature: cryptoSign(null, Buffer.from(statement, 'utf8'), privateKey).toString('base64url') };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** The Prisma error code, or a description of why there was no error to read. */
async function prismaErrorCode(operation: Promise<unknown>): Promise<string> {
  try {
    await operation;
    return 'NO_ERROR: the database accepted the write';
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) return error.code;
    return `UNEXPECTED: ${String(error)}`;
  }
}

const SEEDED_ROLES: ReadonlyArray<{ id: string; org: string; role: string; site: string }> = [
  { id: fx.commanderA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
  { id: fx.commanderA1b, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
  { id: fx.dispatcherA1, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
  { id: fx.opAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
  { id: fx.opBravo, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
  { id: fx.operativeA2, org: fx.orgA, role: 'field.operative', site: fx.siteA2 },
  { id: fx.commanderB1, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
  { id: fx.opB1, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
];

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-22 M2 Org A' },
      { id: fx.orgB, name: 'WP-22 M2 Org B' },
    ],
  });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });
  await prisma.user.createMany({
    data: SEEDED_ROLES.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: SEEDED_ROLES.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });

  // B11-13: an incident states its ORIGIN. This fixture is Fusion-shaped, so
  // source_ref IS the hypothesis id — which is exactly what makes the Whisper
  // incident later in the narrative distinguishable from it by origin alone.
  const fixtureHypothesisId = randomUUID();
  await prisma.incident.create({
    data: {
      id: fx.incidentA1,
      hypothesisId: fixtureHypothesisId,
      incidentCandidateId: randomUUID(),
      sourceKind: 'FUSION_HYPOTHESIS',
      sourceRef: fixtureHypothesisId,
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      incidentType: 'm2.integrated',
      severity: 'SEV3',
      threatState: 2,
      confidence: 0.9,
      responseMode: 'STANDARD',
    },
  });
}

/**
 * Everything this suite can touch, deleted child-first, with foreign-key
 * pointers nulled before the rows they point at (the patrol and whisper suites'
 * ordering, merged).
 */
async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];

  // --- patrol: the run checkpoint points AT a verification, so break that
  // pointer before the verification rows go.
  await prisma.patrolRunActionIdempotency.deleteMany({ where: { run: { organisationId: { in: orgs } } } });
  await prisma.patrolRunCheckpoint.updateMany({ where: { organisationId: { in: orgs } }, data: { verificationId: null } });
  await prisma.patrolCheckpointVerification.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRunCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRun.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRouteVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRoute.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- offline: receipts carry no foreign key; cursors hold a Restrict
  // relation to Site and so must precede the sites.
  await prisma.fieldOfflineOperationReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOfflineDeviceCursor.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- field messaging
  await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: { in: orgs } } } });
  await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- field
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId: { in: orgs } } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldStateUpdateIdempotency.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOperativeStateHistory.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOperativeCurrentState.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- incidents and the SILENT response chain
  await prisma.responseDispatchHandoff.deleteMany({ where: { task: { incident: { organisationId: { in: orgs } } } } });
  await prisma.responseTaskSilentApproval.deleteMany({ where: { task: { incident: { organisationId: { in: orgs } } } } });
  await prisma.responseTask.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incidentUpdateOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- whisper: receipts and approvals hold Restrict relations to the version.
  await prisma.whisperRecognitionReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperActivationApproval.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperSignalVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });

  // --- identity
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
}

interface AssignmentView {
  id: string;
  status: string;
  delivery_state: string;
}

interface RouteResponse {
  id: string;
  route_version: number;
  checkpoints: Array<{ id: string; sequence_number: number }>;
}

interface RunResponse {
  id: string;
  status: string;
  started_at: string | null;
  checkpoints: Array<{ id: string; sequence_number: number; state: string }>;
}

interface VerifyResponse {
  verification: { id: string; timing_outcome: string };
  run_checkpoint: { id: string; state: string };
  run_status: string;
}

interface SignalVersionView {
  whisper_signal_id: string;
  signal_version: number;
  status: string;
}

/** The V2 envelope as a device would queue it, before it is parsed. */
interface OperationDraft {
  schema_version: 2;
  offline_operation_id: string;
  organisation_id: string;
  site_id: string;
  device_id: string;
  device_sequence: number;
  idempotency_key: string;
  operation_kind: string;
  payload: Record<string, unknown>;
  created_at: string;
  trace_id: string;
}

describe('WP-22 Milestone 2 integrated Field loop (live stack)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;
  let whisper: WhisperService;
  let whisperRepository: WhisperRepository;
  let verifier: WhisperSignatureVerifier;
  let offline: FieldOfflineReplayService;
  let sweeper: PatrolMissedSweeper;
  let fieldOutbox: FieldOutboxPublisher;

  /** The ordered narrative's shared state. Each step hands the next what it made. */
  let narrativeAssignmentId = '';
  let narrativeMessageId = '';
  let narrativeRunId = '';
  let narrativeSignalId = '';
  let narrativeWhisperIncidentId = '';

  const openSockets: ClientSocket[] = [];
  let fixtureSeq = 0;

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const get = (path: string, userId: string) => fetch(`${base}${path}`, { headers: { 'x-dev-user-id': userId } });

  // -------------------------------------------------------------- principals

  /** The principal as the DevAuthGuard builds it — read LIVE, so a revoked role really disappears. */
  async function principalFor(userId: string): Promise<Principal> {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, include: { roles: true } });
    return buildPrincipal({
      user: { id: user.id, clearance: user.clearance },
      organisation_id: user.organisationId,
      roles: user.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
    });
  }

  // ----------------------------------------------------------------- offline

  /** The C10-02 seam: TRUSTED identity, never derived from the envelope. */
  function deviceContext(userId: string, deviceId: string, siteIds: string[] = [fx.siteA1]): AuthenticatedFieldDeviceContext {
    return { organisationId: fx.orgA, userId, deviceId, authorisedSiteIds: siteIds };
  }

  function makeOperation(overrides: Partial<OperationDraft> = {}): OperationDraft {
    return {
      schema_version: 2,
      offline_operation_id: randomUUID(),
      organisation_id: fx.orgA,
      site_id: fx.siteA1,
      device_id: `${tag}_device`,
      device_sequence: 0,
      idempotency_key: `client-idem-${randomUUID()}`,
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      payload: {},
      created_at: new Date().toISOString(),
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  function expectResult(outcome: OfflineSubmissionOutcome): OfflineOperationResult {
    expect(outcome.kind, JSON.stringify(outcome)).toBe('result');
    if (outcome.kind !== 'result') throw new Error('unreachable: outcome is not a result');
    return outcome.result;
  }

  function expectConflict(outcome: OfflineSubmissionOutcome): OfflineReplayConflict {
    expect(outcome.kind, JSON.stringify(outcome)).toBe('conflict');
    if (outcome.kind !== 'conflict') throw new Error('unreachable: outcome is not a conflict');
    return outcome.conflict;
  }

  /** A fresh assignment written straight at the table, so its only audit rows are the ones under test. */
  async function newAssignment(assignee: string, status = 'REQUESTED'): Promise<string> {
    const row = await prisma.fieldAssignment.create({
      data: {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        incidentId: fx.incidentA1,
        assigneeUserId: assignee,
        assignmentType: 'INCIDENT_RESPONSE',
        priority: 'SEV3',
        status,
        deliveryState: 'REQUESTED',
        needToKnowSummary: 'm2 fixture',
        idempotencyKey: `${tag}-assignment-${fixtureSeq++}`,
        createdByUserId: fx.dispatcherA1,
        updatedByUserId: fx.dispatcherA1,
      },
      select: { id: true },
    });
    return row.id;
  }

  // ------------------------------------------------------------------ patrol

  /** offsets: [window_open, late_after, missed_after] per checkpoint, in ms. */
  async function createRoute(offsets: Array<[number, number, number]>): Promise<RouteResponse> {
    const res = await post('/api/v1/patrol/routes', fx.commanderA1, {
      site_id: fx.siteA1,
      name: `Perimeter walk ${fixtureSeq++}`,
      checkpoints: offsets.map(([open, late, missed], index) => ({
        name: `Checkpoint ${index + 1}`,
        zone_id: null,
        location: null,
        window_open_offset_ms: open,
        late_after_offset_ms: late,
        missed_after_offset_ms: missed,
      })),
      idempotency_key: `route-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(res.status).toBe(201);
    return (await res.json()) as RouteResponse;
  }

  const verify = (runId: string, runCheckpointId: string, userId: string) =>
    post(`/api/v1/patrol/runs/${runId}/checkpoints/${runCheckpointId}/verify`, userId, {
      device_id: fx.deviceAlpha,
      verification_method: 'manual',
      source_at: new Date().toISOString(),
      idempotency_key: `verify-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });

  // ----------------------------------------------------------------- whisper

  /**
   * A family created and driven to ACTIVE through the REAL Studio HTTP surface,
   * activated by a commander DISTINCT from its author (W21-12).
   */
  async function activeSignalViaStudio(overrides: Record<string, unknown> = {}): Promise<{ id: string; version: number }> {
    const created = await post('/api/v1/whisper/signals', fx.commanderA1, {
      site_id: fx.siteA1,
      name: 'Duress tap',
      device_action_id: DEVICE_ACTION,
      authorised_user_ids: [fx.opAlpha],
      context_requirements: {},
      minimum_confidence: 0.5,
      response_protocol_id: 'SILENT_INCIDENT_RESPONSE',
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    });
    expect(created.status).toBe(201);
    const view = (await created.json()) as SignalVersionView;
    expect(view.status).toBe('DRAFT');

    for (const to of LIFECYCLE_TO_APPROVAL) {
      const step = await post(`/api/v1/whisper/signals/${view.whisper_signal_id}/versions/1/transitions`, fx.commanderA1, {
        to,
        trace_id: `trace-${randomUUID()}`,
      });
      expect(step.status, `transition to ${to}`).toBe(201);
    }

    // The DISTINCT approver. commanderA1 authored it, so W21-12 forbids
    // commanderA1 from attesting that their own configuration is safe.
    const activated = await post(`/api/v1/whisper/signals/${view.whisper_signal_id}/versions/1/activate`, fx.commanderA1b, {
      trace_id: `trace-${randomUUID()}`,
    });
    expect(activated.status).toBe(201);
    expect(((await activated.json()) as SignalVersionView).status).toBe('ACTIVE');

    return { id: view.whisper_signal_id, version: 1 };
  }

  function unsignedResult(signal: { id: string; version: number }, overrides: Partial<UnsignedResult> = {}): UnsignedResult {
    return {
      schema_version: 1,
      whisper_result_id: `result-${randomUUID()}`,
      whisper_signal_id: signal.id,
      whisper_signal_version: signal.version,
      organisation_id: fx.orgA,
      site_id: fx.siteA1,
      actor_user_id: fx.opAlpha,
      device_id: fx.deviceAlpha,
      device_action_id: DEVICE_ACTION,
      recognised_at: new Date().toISOString(),
      confidence: 0.95,
      // A device asserting its own trustworthiness. The platform's judgement
      // lives on the context and this field is not even signed (W21-05).
      device_trust: 'TRUSTED',
      context: {},
      freshness_ms: 0,
      anti_replay_nonce: `nonce-${randomUUID()}${randomUUID()}`,
      signature_algorithm: WHISPER_SIGNATURE_ALGORITHM,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  function whisperContext(overrides: Partial<AuthenticatedWhisperDeviceContext> = {}): AuthenticatedWhisperDeviceContext {
    return {
      organisationId: fx.orgA,
      actorUserId: fx.opAlpha,
      deviceId: fx.deviceAlpha,
      authorisedSiteIds: [fx.siteA1],
      deviceTrust: 'TRUSTED',
      verificationKeyId: fx.keyAlpha,
      ...overrides,
    };
  }

  const whisperIncidentsFor = (fingerprint: string) =>
    prisma.incident.findMany({ where: { organisationId: fx.orgA, sourceKind: 'WHISPER_RECOGNITION', sourceRef: fingerprint } });

  /** Receipts matching the SEVEN-COLUMN replay identity of one signed result. */
  const receiptsForIdentity = (result: DeviceActionWhisperResult) =>
    prisma.whisperRecognitionReceipt.findMany({
      where: {
        organisationId: result.organisation_id,
        siteId: result.site_id,
        actorUserId: result.actor_user_id,
        deviceId: result.device_id,
        whisperSignalId: result.whisper_signal_id,
        whisperSignalVersion: result.whisper_signal_version,
        antiReplayNonce: result.anti_replay_nonce,
      },
    });

  // ---------------------------------------------------------------- realtime

  function connectSocket(userId: string): ClientSocket {
    const socket = io(base, { path: WS_PATH, transports: ['websocket'], reconnection: false, forceNew: true, auth: { userId } });
    openSockets.push(socket);
    return socket;
  }

  function waitForConnect(socket: ClientSocket, timeoutMs = 8000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`socket did not connect within ${timeoutMs}ms`));
      }, timeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        resolve();
      });
      socket.once('connect_error', (error: Error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  // ------------------------------------------------------------- bootstrap

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(WHISPER_DEVICE_KEY_RESOLVER)
      .useValue(keyRegistry)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;

    prisma = app.get(PrismaService);
    whisper = app.get(WhisperService);
    whisperRepository = app.get(WhisperRepository);
    verifier = app.get(WhisperSignatureVerifier);
    offline = app.get(FieldOfflineReplayService);
    sweeper = app.get(PatrolMissedSweeper);
    fieldOutbox = app.get(FieldOutboxPublisher);

    await seed(prisma);
  }, 180_000);

  afterAll(async () => {
    for (const socket of openSockets.splice(0)) socket.close();
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 120_000);

  afterEach(() => {
    // Every spy here is a deliberately injected observation or fault; leaving
    // one installed would silently corrupt the next step of the narrative.
    vi.restoreAllMocks();
  });

  // ==========================================================================
  // W22-03 — the integrated Field loop
  // ==========================================================================

  it('W22-03/1: an assignment moves REQUESTED -> ACCEPTED -> IN_PROGRESS through the real guard chain, one audit row per transition', async () => {
    const created = await post('/api/v1/field/assignments', fx.dispatcherA1, {
      site_id: fx.siteA1,
      incident_id: fx.incidentA1,
      assignee_user_id: fx.opAlpha,
      assignment_type: 'INCIDENT_RESPONSE',
      priority: 'SEV2',
      need_to_know_summary: 'Proceed to the north gate and report.',
      expires_at: null,
      idempotency_key: `create-${randomUUID()}`,
    });
    expect(created.status).toBe(201);
    const assignment = (await created.json()) as AssignmentView;
    narrativeAssignmentId = assignment.id;
    expect(assignment).toMatchObject({ status: 'REQUESTED', delivery_state: 'REQUESTED' });

    // Only the ASSIGNEE may act. The dispatcher who created it may not, and a
    // same-site peer operative may not — that is the boundary every later
    // isolation test builds on.
    const byDispatcher = await post(`/api/v1/field/assignments/${assignment.id}/accept`, fx.dispatcherA1, {
      expected_status: 'REQUESTED',
      idempotency_key: `accept-${randomUUID()}`,
    });
    expect(byDispatcher.status).toBe(403);

    const accepted = await post(`/api/v1/field/assignments/${assignment.id}/accept`, fx.opAlpha, {
      expected_status: 'REQUESTED',
      idempotency_key: `accept-${randomUUID()}`,
    });
    expect(accepted.status).toBe(201);
    // §76: acceptance IS the acknowledgement, so delivery advances with it.
    expect((await accepted.json()) as AssignmentView).toMatchObject({ status: 'ACCEPTED', delivery_state: 'ACKNOWLEDGED' });

    const started = await post(`/api/v1/field/assignments/${assignment.id}/start`, fx.opAlpha, {
      expected_status: 'ACCEPTED',
      idempotency_key: `start-${randomUUID()}`,
    });
    expect(started.status).toBe(201);
    expect((await started.json()) as AssignmentView).toMatchObject({ status: 'IN_PROGRESS' });

    // Exactly one audit row per transition, and nothing extra: the refused
    // dispatcher attempt left no trace at all.
    const auditKind = (kind: string) => prisma.fieldAuditLog.count({ where: { assignmentId: assignment.id, kind } });
    expect(await auditKind('FIELD_ASSIGNMENT_CREATED')).toBe(1);
    expect(await auditKind('FIELD_ASSIGNMENT_ACCEPTED')).toBe(1);
    expect(await auditKind('FIELD_ASSIGNMENT_IN_PROGRESS')).toBe(1);
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: assignment.id } })).toBe(3);
    expect(await prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: assignment.id } } })).toBe(3);

    const row = await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignment.id } });
    expect(row.incidentId).toBe(fx.incidentA1);
    expect(row.acceptedAt).not.toBeNull();
    expect(row.startedAt).not.toBeNull();
  }, 60_000);

  it('W22-03/2: the operative posts authoritative Field state and reads it back; the current row is upserted and history is appended', async () => {
    const historyBefore = await prisma.fieldOperativeStateHistory.count({ where: { organisationId: fx.orgA, userId: fx.opAlpha } });

    const sourceAt = new Date(Date.now() - 30_000).toISOString();
    const res = await post('/api/v1/field/state', fx.opAlpha, {
      site_id: fx.siteA1,
      device_id: fx.deviceAlpha,
      state: 'ON_SCENE',
      location: null,
      source_at: sourceAt,
      // A client claiming perfect freshness for a 30s-old observation.
      freshness_ms: 0,
      idempotency_key: `state-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(res.status).toBe(201);
    const view = (await res.json()) as { state: string; client_freshness_ms: number; authoritative_freshness_ms: number };
    expect(view.state).toBe('ON_SCENE');
    // C10-06 applied to live telemetry: the client's claim is kept as a claim,
    // and the server computes the number anyone is allowed to rely on.
    expect(view.client_freshness_ms).toBe(0);
    expect(view.authoritative_freshness_ms).toBeGreaterThanOrEqual(30_000);

    const own = await get('/api/v1/field/state/mine', fx.opAlpha);
    expect(own.status).toBe(200);
    expect((await own.json()) as { user_id: string; site_id: string; state: string }).toMatchObject({
      user_id: fx.opAlpha,
      site_id: fx.siteA1,
      state: 'ON_SCENE',
    });

    const current = await prisma.fieldOperativeCurrentState.findUniqueOrThrow({
      where: { organisationId_siteId_userId: { organisationId: fx.orgA, siteId: fx.siteA1, userId: fx.opAlpha } },
    });
    expect(current.state).toBe('ON_SCENE');
    expect(current.deviceId).toBe(fx.deviceAlpha);
    // CURRENT state is a single upserted row; HISTORY is the append-only record.
    expect(await prisma.fieldOperativeCurrentState.count({ where: { organisationId: fx.orgA, userId: fx.opAlpha } })).toBe(1);
    expect(await prisma.fieldOperativeStateHistory.count({ where: { organisationId: fx.orgA, userId: fx.opAlpha } })).toBe(historyBefore + 1);
  }, 60_000);

  it('W22-03/3: a named recipient reads and acknowledges an incident message; an unnamed same-site operative gets the 404 a nonexistent message would produce', async () => {
    const sent = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderA1, {
      recipient_user_ids: [fx.opAlpha],
      body: 'Hold the north gate until relieved.',
      retention_class: 'operational-30d',
      idempotency_key: `send-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(sent.status).toBe(201);
    narrativeMessageId = ((await sent.json()) as { id: string }).id;

    const named = await get(`/api/v1/field-messages/mine/${narrativeMessageId}`, fx.opAlpha);
    expect(named.status).toBe(200);
    expect((await named.json()) as { body: string }).toMatchObject({ body: 'Hold the north gate until relieved.' });

    // opBravo is a field.operative at the same site holding field.message.read.
    // Membership, not role, decides who may read — and the refusal must be
    // indistinguishable from "no such message".
    const unnamed = await get(`/api/v1/field-messages/mine/${narrativeMessageId}`, fx.opBravo);
    const absent = await get(`/api/v1/field-messages/mine/${randomUUID()}`, fx.opBravo);
    expect(unnamed.status).toBe(404);
    expect(absent.status).toBe(404);
    expect(await unnamed.text()).toBe(await absent.text());

    // C8-01: acknowledge needs TRANSPORT evidence, and there is deliberately no
    // route that manufactures it — so the fixture writes DELIVERED directly.
    const early = await post(`/api/v1/field-messages/mine/${narrativeMessageId}/acknowledge`, fx.opAlpha, { idempotency_key: `ack-${randomUUID()}` });
    expect(early.status).toBe(409);

    await prisma.incidentFieldMessageRecipient.updateMany({
      where: { messageId: narrativeMessageId, recipientUserId: fx.opAlpha },
      data: { deliveryState: 'DELIVERED', deliveredAt: new Date() },
    });

    const acknowledged = await post(`/api/v1/field-messages/mine/${narrativeMessageId}/acknowledge`, fx.opAlpha, { idempotency_key: `ack-${randomUUID()}` });
    expect(acknowledged.status).toBe(201);

    const recipient = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({
      where: { messageId: narrativeMessageId, recipientUserId: fx.opAlpha },
    });
    expect(recipient.deliveryState).toBe('ACKNOWLEDGED');
    expect(recipient.acknowledgedAt).not.toBeNull();

    const timelineWhere = (kind: string) => ({
      incidentId: fx.incidentA1,
      kind,
      payload: { path: ['incident_field_message_id'], equals: narrativeMessageId },
    });
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere(TIMELINE_MESSAGE_SENT) })).toBe(1);
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere(TIMELINE_MESSAGE_ACKNOWLEDGED) })).toBe(1);
  }, 60_000);

  it('W22-03/4: an incident-linked patrol verifies in window, refuses a verification past the deadline, and the explicit sweep alone stamps MISSED exactly once', async () => {
    // Checkpoint 1 has a live window; checkpoint 2's deadline is the start
    // instant itself, so it is already overdue the moment the run begins.
    const route = await createRoute([
      [0, 60_000, 120_000],
      [0, 0, 0],
    ]);
    expect(route.route_version).toBe(1);

    const scheduled = await post('/api/v1/patrol/runs', fx.dispatcherA1, {
      patrol_route_id: route.id,
      assigned_operative_user_id: fx.opAlpha,
      // C9-05: an incident-linked run is only schedulable because opAlpha holds
      // a live assignment on this incident — the seam back to step 1.
      incident_id: fx.incidentA1,
      scheduled_start_at: new Date().toISOString(),
      idempotency_key: `run-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(scheduled.status).toBe(201);
    narrativeRunId = ((await scheduled.json()) as RunResponse).id;

    const startRes = await post(`/api/v1/patrol/runs/${narrativeRunId}/start`, fx.opAlpha, {
      idempotency_key: `start-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(startRes.status).toBe(201);
    const started = (await startRes.json()) as RunResponse;
    expect(started.status).toBe('IN_PROGRESS');
    expect(started.started_at).not.toBeNull();
    expect(started.checkpoints).toHaveLength(2);
    const [first, second] = started.checkpoints;

    const verified = await verify(narrativeRunId, first.id, fx.opAlpha);
    expect(verified.status).toBe(201);
    const verifyView = (await verified.json()) as VerifyResponse;
    expect(verifyView.verification.timing_outcome).toBe('VERIFIED');
    expect(verifyView.run_checkpoint.state).toBe('VERIFIED');
    // Checkpoint 2 is still PENDING, so the run has not completed.
    expect(verifyView.run_status).toBe('IN_PROGRESS');

    // W22-02 determinism, asserted inside the integrated suite: the deadline
    // has passed, and the VERIFY path may never stamp MISSED. It refuses.
    const expired = await verify(narrativeRunId, second.id, fx.opAlpha);
    expect(expired.status).toBe(409);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: narrativeRunId } })).toBe(1);

    // MISSED is the sweep's judgement alone, and the sweep is DRIVEN here — no
    // timer exists to race it (PATROL_SWEEP_INTERVAL_MS=0).
    await Promise.all([sweeper.sweep(), sweeper.sweep()]);
    await sweeper.sweep();

    const missedRow = await prisma.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: second.id } });
    expect(missedRow.state).toBe('MISSED');
    expect(missedRow.resolvedAt).toBeNull();
    expect(missedRow.verificationId).toBeNull();
    expect(
      await prisma.fieldAuditLog.count({
        where: { kind: 'PATROL_CHECKPOINT_MISSED', payload: { path: ['patrol_run_checkpoint_id'], equals: second.id } },
      }),
    ).toBe(1);

    // C9-08: every checkpoint resolved -> the system completes the run.
    const runRow = await prisma.patrolRun.findUniqueOrThrow({ where: { id: narrativeRunId } });
    expect(runRow.status).toBe('COMPLETED');
    expect(runRow.endedAt).not.toBeNull();

    // A verification after MISSED remains refused, and the incident-linked run
    // wrote its evidence onto the incident's own timeline.
    expect((await verify(narrativeRunId, second.id, fx.opAlpha)).status).toBe(409);
    for (const kind of ['PATROL_RUN_SCHEDULED', 'PATROL_RUN_STARTED', 'PATROL_CHECKPOINT_VERIFIED', 'PATROL_RUN_COMPLETED']) {
      expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind } }), kind).toBe(1);
    }
  }, 120_000);

  it('W22-03/5: offline replay applies the admitted kinds exactly once, and patrol/field-state kinds still fail to parse the V2 contract', async () => {
    const device = `${tag}_device_narrative`;
    const context = deviceContext(fx.opAlpha, device);
    const alpha = await principalFor(fx.opAlpha);

    // --- an admitted ASSIGNMENT transition, at the contiguous start position.
    const queuedAssignment = await newAssignment(fx.opAlpha);
    const acceptOperation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      payload: { assignment_id: queuedAssignment, expected_status: 'REQUESTED' },
    });
    const accepted = expectResult(await offline.submit(alpha, context, acceptOperation));
    expect(accepted.outcome).toBe('APPLIED');
    expect(accepted.replayed).toBe(false);
    expect(accepted.next_expected_sequence).toBe(1);

    // Exactly ONE domain effect. The assignment was written straight at the
    // table, so the transition is the only audit row it can possibly have.
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: queuedAssignment } })).status).toBe('ACCEPTED');
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: queuedAssignment } })).toBe(1);
    expect(await prisma.fieldAssignmentActionIdempotency.count({ where: { assignmentId: queuedAssignment } })).toBe(1);

    // --- an admitted MESSAGE SEND at the next contiguous position. opAlpha may
    // send into this incident only because of the live assignment from step 1.
    const offlineBody = `m2-offline-body-${randomUUID()}`;
    const sendOperation = makeOperation({
      device_id: device,
      device_sequence: 1,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      payload: {
        incident_id: fx.incidentA1,
        recipient_user_ids: [fx.dispatcherA1],
        body: offlineBody,
        retention_class: 'operational-30d',
      },
    });
    const sentResult = expectResult(await offline.submit(alpha, context, sendOperation));
    expect(sentResult.outcome).toBe('APPLIED');
    const offlineMessageId = sentResult.result_ref ?? '';
    expect(offlineMessageId).not.toBe('');
    expect(await prisma.incidentFieldMessage.count({ where: { id: offlineMessageId } })).toBe(1);
    expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA, body: offlineBody } })).toBe(1);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: offlineMessageId } })).toBe(1);
    // R6: the receipt carries a COUNT, never a recipient or a body.
    expect(sentResult.result_snapshot).toEqual({ incident_field_message_id: offlineMessageId, incident_id: fx.incidentA1, recipient_count: 1 });

    // --- C10-05: the allowlist was NOT widened for the convenience of this
    // suite. A patrol or field-state operation is not merely refused at
    // runtime; it cannot be EXPRESSED in the executable replay contract.
    expect([...FIELD_OFFLINE_OPERATION_KINDS]).toEqual([
      'FIELD_ASSIGNMENT_ACCEPT',
      'FIELD_ASSIGNMENT_DECLINE',
      'FIELD_ASSIGNMENT_START',
      'FIELD_ASSIGNMENT_COMPLETE',
      'INCIDENT_FIELD_MESSAGE_SEND',
      'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
    ]);

    const inadmissible: Array<[string, Record<string, unknown>]> = [
      ['PATROL_CHECKPOINT_VERIFY', { patrol_run_id: narrativeRunId, run_checkpoint_id: randomUUID(), verification_method: 'manual' }],
      ['PATROL_RUN_START', { patrol_run_id: narrativeRunId }],
      ['FIELD_STATE_UPDATE', { site_id: fx.siteA1, state: 'ON_SCENE', device_id: device }],
    ];
    const rejectionDevice = `${tag}_device_inadmissible`;
    const rejectionContext = deviceContext(fx.opAlpha, rejectionDevice);
    for (const [kind, payload] of inadmissible) {
      const draft = makeOperation({ device_id: rejectionDevice, device_sequence: 0, operation_kind: kind, payload });
      expect(FieldOfflineOperationV2Schema.safeParse(draft).success, `${kind} must not parse`).toBe(false);

      const outcome = await offline.submit(alpha, rejectionContext, draft);
      expect(outcome.kind, `${kind} submit`).toBe('invalid');
    }
    // An unparseable envelope leaves NO trace: no receipt, and no cursor that
    // could later be mistaken for a consumed queue position.
    expect(await prisma.fieldOfflineOperationReceipt.count({ where: { organisationId: fx.orgA, deviceId: rejectionDevice } })).toBe(0);
    expect(await prisma.fieldOfflineDeviceCursor.count({ where: { organisationId: fx.orgA, deviceId: rejectionDevice } })).toBe(0);
  }, 120_000);

  it('W22-03/6: an activated Whisper signal INITIATES a SILENT incident without approving it, and two distinct commanders produce exactly one handoff', async () => {
    const signal = await activeSignalViaStudio();
    narrativeSignalId = signal.id;

    // Activation attested that a TESTED CONFIGURATION IS SAFE TO RECOGNISE
    // (W21-13) — exactly one approval row, and it is not an operational one.
    expect(await prisma.whisperActivationApproval.count({ where: { organisationId: fx.orgA } })).toBe(1);

    const signed = signResult(unsignedResult(signal), keyAlpha.privateKey);
    const fingerprint = whisperRecognitionFingerprint(signed);
    const outcome = await whisper.recognise(whisperContext(), signed, await principalFor(fx.opAlpha));

    expect(outcome).toMatchObject({ kind: 'accepted', replayed: false });
    if (outcome.kind !== 'accepted') return;
    expect(outcome.recognition_fingerprint).toBe(fingerprint);

    const incidents = await whisperIncidentsFor(fingerprint);
    expect(incidents).toHaveLength(1);
    const incident = incidents[0]!;
    narrativeWhisperIncidentId = incident.id;
    expect(incident.id).toBe(outcome.incident_id);
    expect(incident.sourceKind).toBe('WHISPER_RECOGNITION');
    expect(incident.sourceRef).toBe(fingerprint);
    expect(incident.siteId).toBe(fx.siteA1);
    // A Whisper incident fabricates no Fusion identifiers.
    expect(incident.hypothesisId).toBeNull();
    expect(incident.incidentCandidateId).toBeNull();
    // SEV2 / threat state 2 / SILENT: a duress signal REPORTS a situation, it
    // does not corroborate one (4 is VERIFIED_THREAT).
    expect(incident.severity).toBe('SEV2');
    expect(incident.threatState).toBe(2);
    expect(incident.responseMode).toBe('SILENT');

    // THE POINT OF THE WHOLE STEP: the recognition initiated a response and
    // approved nothing. Zero silent approvals, and the dispatch task has not
    // been handed off to anybody.
    expect(await prisma.responseTaskSilentApproval.count({ where: { task: { incidentId: incident.id } } })).toBe(0);
    const dispatch = await prisma.responseTask.findFirstOrThrow({ where: { incidentId: incident.id, taskType: 'dispatch-field' } });
    expect(dispatch.deliveryState).toBe('REQUESTED');
    expect(await prisma.responseDispatchHandoff.count({ where: { taskId: dispatch.id } })).toBe(0);

    // Two DISTINCT commanders, over the existing silent-approval route.
    const route = `/api/v1/incidents/${incident.id}/tasks/${dispatch.id}/silent-approvals`;
    const firstApproval = await post(route, fx.commanderA1, {});
    expect(firstApproval.status).toBe(201);
    expect((await prisma.responseTask.findUniqueOrThrow({ where: { id: dispatch.id } })).deliveryState).toBe('REQUESTED');
    expect(await prisma.responseDispatchHandoff.count({ where: { taskId: dispatch.id } })).toBe(0);
    expect(await prisma.responseTaskSilentApproval.count({ where: { taskId: dispatch.id } })).toBe(1);

    const secondApproval = await post(route, fx.commanderA1b, {});
    expect(secondApproval.status).toBe(201);
    expect((await prisma.responseTask.findUniqueOrThrow({ where: { id: dispatch.id } })).deliveryState).toBe('DELIVERED');
    expect(await prisma.responseTaskSilentApproval.count({ where: { taskId: dispatch.id } })).toBe(2);
    // EXACTLY one handoff: Whisper initiated the response, two distinct
    // commanders authorised it, and it left the platform once.
    const handoffs = await prisma.responseDispatchHandoff.findMany({ where: { taskId: dispatch.id } });
    expect(handoffs).toHaveLength(1);
  }, 180_000);

  // ==========================================================================
  // W22-04 — isolation and need-to-know
  // ==========================================================================

  it('W22-04/7: a foreign tenant is refused on the assignment, the message, the patrol run and the Whisper signal, each indistinguishably from nonexistence', async () => {
    expect(narrativeAssignmentId).not.toBe('');
    expect(narrativeMessageId).not.toBe('');
    expect(narrativeRunId).not.toBe('');
    expect(narrativeSignalId).not.toBe('');
    expect(narrativeWhisperIncidentId).not.toBe('');

    const ghost = randomUUID();
    const probes: Array<[string, string, string, string]> = [
      // [label, actor, real path, same-shaped nonexistent path]
      ['assignment', fx.commanderB1, `/api/v1/field/assignments/${narrativeAssignmentId}`, `/api/v1/field/assignments/${ghost}`],
      ['message', fx.opB1, `/api/v1/field-messages/mine/${narrativeMessageId}`, `/api/v1/field-messages/mine/${ghost}`],
      ['patrol run', fx.commanderB1, `/api/v1/patrol/runs/${narrativeRunId}`, `/api/v1/patrol/runs/${ghost}`],
      ['whisper signal', fx.commanderB1, `/api/v1/whisper/signals/${narrativeSignalId}`, `/api/v1/whisper/signals/${ghost}`],
      // The silent incident the recognition raised is the most sensitive object
      // in the whole narrative, and a foreign commander holds `incident.view`
      // in their OWN tenant — so this is the probe that matters most.
      ['whisper incident', fx.commanderB1, `/api/v1/incidents/${narrativeWhisperIncidentId}`, `/api/v1/incidents/${ghost}`],
    ];

    for (const [label, actor, realPath, ghostPath] of probes) {
      const real = await get(realPath, actor);
      const absent = await get(ghostPath, actor);
      // Fail closed, and fail IDENTICALLY: a different status or a different
      // body between "yours" and "does not exist" is itself the disclosure.
      expect([403, 404], `${label} status`).toContain(real.status);
      expect(real.status, `${label} status parity`).toBe(absent.status);
      const realText = await real.text();
      expect(realText, `${label} body parity`).toBe(await absent.text());
      // And never a detail: not the id, not the site, not the operative.
      for (const secret of [narrativeAssignmentId, narrativeMessageId, narrativeRunId, fx.siteA1, fx.opAlpha]) {
        expect(realText, `${label} leaks ${secret}`).not.toContain(secret);
      }
    }

    // Writes are refused on the same terms.
    const foreignAccept = await post(`/api/v1/field/assignments/${narrativeAssignmentId}/accept`, fx.opB1, {
      expected_status: 'REQUESTED',
      idempotency_key: `accept-${randomUUID()}`,
    });
    expect([403, 404]).toContain(foreignAccept.status);

    const foreignSend = await post(`/api/v1/field-messages/incidents/${fx.incidentA1}`, fx.commanderB1, {
      recipient_user_ids: [fx.opB1],
      body: 'should never land',
      retention_class: 'operational-30d',
      idempotency_key: `send-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(foreignSend.status).toBe(404);

    const foreignStart = await post(`/api/v1/patrol/runs/${narrativeRunId}/start`, fx.opB1, {
      idempotency_key: `start-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect([403, 404]).toContain(foreignStart.status);

    // Nothing the foreign tenant did left a row anywhere in tenant A.
    expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA, senderUserId: fx.commanderB1 } })).toBe(0);
    expect(await prisma.fieldAuditLog.count({ where: { organisationId: fx.orgA, actorUserId: { in: [fx.opB1, fx.commanderB1] } } })).toBe(0);
  }, 60_000);

  it('W22-04/8: a wrong-site operative and an unassigned same-site peer are both refused on the run and on the message', async () => {
    for (const [label, outsider] of [
      ['wrong site', fx.operativeA2],
      ['unassigned peer', fx.opBravo],
    ] as const) {
      const ghost = randomUUID();

      const run = await get(`/api/v1/patrol/runs/${narrativeRunId}`, outsider);
      const runAbsent = await get(`/api/v1/patrol/runs/${ghost}`, outsider);
      expect(run.status, `${label} run`).toBe(404);
      expect(await run.text(), `${label} run parity`).toBe(await runAbsent.text());

      const runStart = await post(`/api/v1/patrol/runs/${narrativeRunId}/start`, outsider, {
        idempotency_key: `start-${randomUUID()}`,
        trace_id: `trace-${randomUUID()}`,
      });
      expect(runStart.status, `${label} run start`).toBe(404);

      const message = await get(`/api/v1/field-messages/mine/${narrativeMessageId}`, outsider);
      const messageAbsent = await get(`/api/v1/field-messages/mine/${ghost}`, outsider);
      expect(message.status, `${label} message`).toBe(404);
      expect(await message.text(), `${label} message parity`).toBe(await messageAbsent.text());

      const acknowledge = await post(`/api/v1/field-messages/mine/${narrativeMessageId}/acknowledge`, outsider, {
        idempotency_key: `ack-${randomUUID()}`,
      });
      expect(acknowledge.status, `${label} acknowledge`).toBe(404);
    }

    // The listing surfaces agree with the point reads: neither outsider's own
    // list can be made to contain what their point read hid.
    const bravoRuns = (await (await get('/api/v1/patrol/runs', fx.opBravo)).json()) as Array<{ id: string }>;
    expect(bravoRuns.some((run) => run.id === narrativeRunId)).toBe(false);

    const bravoMessages = (await (await get(`/api/v1/field-messages/incidents/${fx.incidentA1}/mine`, fx.opBravo)).json()) as Array<{ id: string }>;
    expect(bravoMessages.some((message) => message.id === narrativeMessageId)).toBe(false);

    // Nothing they attempted mutated the objects they could not see.
    expect((await prisma.patrolRun.findUniqueOrThrow({ where: { id: narrativeRunId } })).status).toBe('COMPLETED');
    const recipients = await prisma.incidentFieldMessageRecipient.findMany({ where: { messageId: narrativeMessageId } });
    expect(recipients).toHaveLength(1);
    expect(recipients[0]?.recipientUserId).toBe(fx.opAlpha);
  }, 60_000);

  it('W22-04/9: C7-08 — a same-site peer socket receives Field notifications carrying only kind, organisation_id and site_id', async () => {
    const peer = connectSocket(fx.opBravo);
    await waitForConnect(peer);
    // handleConnection joins the Field site room after the client's `connect`
    // fires; a short settle is cheaper than a race.
    await sleep(750);

    const received: Array<Record<string, unknown>> = [];
    peer.on(WS_EVENT_FIELD_UPDATED, (payload: Record<string, unknown>) => {
      received.push(payload);
    });

    // REAL domain traffic from two different Field surfaces at this site.
    const created = await post('/api/v1/field/assignments', fx.dispatcherA1, {
      site_id: fx.siteA1,
      incident_id: fx.incidentA1,
      assignee_user_id: fx.opAlpha,
      assignment_type: 'INCIDENT_RESPONSE',
      priority: 'SEV3',
      need_to_know_summary: 'realtime projection probe',
      expires_at: null,
      idempotency_key: `create-${randomUUID()}`,
    });
    expect(created.status).toBe(201);
    const probeAssignmentId = ((await created.json()) as AssignmentView).id;

    const stateRes = await post('/api/v1/field/state', fx.opAlpha, {
      site_id: fx.siteA1,
      device_id: fx.deviceAlpha,
      state: 'RESPONDING',
      location: null,
      source_at: new Date().toISOString(),
      freshness_ms: 0,
      idempotency_key: `state-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(stateRes.status).toBe(201);

    // The outbox publisher is driven explicitly rather than waited on.
    const deadline = Date.now() + 25_000;
    while (received.length === 0 && Date.now() < deadline) {
      await fieldOutbox.sweep();
      await sleep(250);
    }
    expect(received.length, 'no Field notification reached the same-site peer socket').toBeGreaterThan(0);

    for (const payload of received) {
      // Scope and the kind of change. Nothing else — the client refetches over
      // REST, where need-to-know is actually enforced.
      expect(Object.keys(payload).sort()).toEqual(['kind', 'organisation_id', 'site_id']);
      expect(payload.organisation_id).toBe(fx.orgA);
      expect(payload.site_id).toBe(fx.siteA1);
      expect(typeof payload.kind).toBe('string');
    }

    // The decisive assertion: no object identity of ANY Field surface ever rode
    // the shared site channel, including the ids REST hides behind a 404.
    const wire = JSON.stringify(received);
    for (const identifier of [probeAssignmentId, narrativeAssignmentId, narrativeMessageId, narrativeRunId, fx.opAlpha]) {
      expect(wire, `socket disclosed ${identifier}`).not.toContain(identifier);
    }
    for (const forbidden of ['assignment_id', 'message_id', 'patrol_run_id', 'user_id', 'state', 'need_to_know_summary']) {
      expect(wire, `socket disclosed ${forbidden}`).not.toContain(forbidden);
    }

    peer.close();
  }, 120_000);

  // ==========================================================================
  // W22-05 — effectively-once, integrated
  // ==========================================================================

  it('W22-05/10: an exact duplicate offline submission produces one domain effect and returns the STORED outcome', async () => {
    const device = `${tag}_device_duplicate`;
    const context = deviceContext(fx.opAlpha, device);
    const alpha = await principalFor(fx.opAlpha);
    const assignmentId = await newAssignment(fx.opAlpha);

    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      payload: { assignment_id: assignmentId, expected_status: 'REQUESTED' },
    });

    const first = expectResult(await offline.submit(alpha, context, operation));
    expect(first).toMatchObject({ outcome: 'APPLIED', replayed: false });

    const replay = expectResult(await offline.submit(alpha, context, operation));
    expect(replay).toMatchObject({ outcome: 'APPLIED', replayed: true });
    // The STORED outcome, not a re-evaluation: same finalisation instant, same
    // reference, same bounded snapshot.
    expect(replay.finalized_at).toBe(first.finalized_at);
    expect(replay.result_ref).toBe(first.result_ref);
    expect(replay.result_snapshot).toEqual(first.result_snapshot);

    // Exactly one domain effect survives the duplicate.
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('ACCEPTED');
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId } })).toBe(1);
    expect(await prisma.fieldAssignmentActionIdempotency.count({ where: { assignmentId } })).toBe(1);
    expect(await prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: assignmentId } } })).toBe(1);
    expect(await prisma.fieldOfflineOperationReceipt.count({ where: { organisationId: fx.orgA, deviceId: device } })).toBe(1);
  }, 60_000);

  it('W22-05/11: the same sequence carrying a CHANGED request is refused as SEQUENCE_REUSED, with zero second effect', async () => {
    const device = `${tag}_device_reuse`;
    const context = deviceContext(fx.opAlpha, device);
    const alpha = await principalFor(fx.opAlpha);
    const applied = await newAssignment(fx.opAlpha);
    const untouched = await newAssignment(fx.opAlpha);

    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      payload: { assignment_id: applied, expected_status: 'REQUESTED' },
    });
    expect(expectResult(await offline.submit(alpha, context, operation)).outcome).toBe('APPLIED');

    // Position 0 again, but a DIFFERENT semantic request. A changed request may
    // never hide behind a consumed queue position, even though the client
    // idempotency key and the offline operation id are unchanged.
    const changed = { ...operation, payload: { assignment_id: untouched, expected_status: 'REQUESTED' } };
    const conflict = expectConflict(await offline.submit(alpha, context, changed));
    expect(conflict.conflict_code).toBe('SEQUENCE_REUSED');
    expect(conflict.device_sequence).toBe(0);

    // Zero second effect: the second assignment never moved, and no second
    // receipt appeared under this device's namespace.
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: untouched } })).status).toBe('REQUESTED');
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: untouched } })).toBe(0);
    expect(await prisma.fieldAssignmentActionIdempotency.count({ where: { assignmentId: untouched } })).toBe(0);
    expect(await prisma.fieldOfflineOperationReceipt.count({ where: { organisationId: fx.orgA, deviceId: device } })).toBe(1);
    // ...and the first effect is still exactly one.
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId: applied } })).toBe(1);
  }, 60_000);

  it('W22-05/12: a duplicate Whisper recognition creates no second incident, task or handoff', async () => {
    const signal = await activeSignalViaStudio();
    const signed = signResult(unsignedResult(signal), keyAlpha.privateKey);
    const fingerprint = whisperRecognitionFingerprint(signed);
    const principal = await principalFor(fx.opAlpha);

    const first = await whisper.recognise(whisperContext(), signed, principal);
    expect(first).toMatchObject({ kind: 'accepted', replayed: false });
    if (first.kind !== 'accepted') return;

    const incidentId = first.incident_id ?? '';
    expect(incidentId).not.toBe('');
    const dispatch = await prisma.responseTask.findFirstOrThrow({ where: { incidentId, taskType: 'dispatch-field' } });
    const route = `/api/v1/incidents/${incidentId}/tasks/${dispatch.id}/silent-approvals`;
    expect((await post(route, fx.commanderA1, {})).status).toBe(201);
    expect((await post(route, fx.commanderA1b, {})).status).toBe(201);
    expect(await prisma.responseDispatchHandoff.count({ where: { taskId: dispatch.id } })).toBe(1);

    // The SAME identity and the SAME fingerprint, re-presented after the
    // response is already under way.
    const replayed = await whisper.recognise(whisperContext(), signed, principal);
    expect(replayed).toMatchObject({ kind: 'accepted', replayed: true });
    if (replayed.kind === 'accepted') {
      expect(replayed.incident_id).toBe(incidentId);
      expect(replayed.recognition_fingerprint).toBe(fingerprint);
    }

    expect(await whisperIncidentsFor(fingerprint)).toHaveLength(1);
    expect(await receiptsForIdentity(signed)).toHaveLength(1);
    expect(await prisma.responseTask.count({ where: { incidentId } })).toBe(3);
    expect(await prisma.responseTaskSilentApproval.count({ where: { taskId: dispatch.id } })).toBe(2);
    expect(await prisma.responseDispatchHandoff.count({ where: { taskId: dispatch.id } })).toBe(1);
  }, 180_000);

  // ==========================================================================
  // W22-06 — the Whisper Crucible, integrated
  // ==========================================================================

  it('W22-06/13: an invalid signature consumes no replay identity, and the SAME nonce then succeeds with a valid one', async () => {
    const signal = await activeSignalViaStudio();
    const nonce = `nonce-${randomUUID()}${randomUUID()}`;
    const unsigned = unsignedResult(signal, { anti_replay_nonce: nonce });
    const principal = await principalFor(fx.opAlpha);

    const forged = signResult(unsigned, unregisteredKey.privateKey);
    expect(await whisper.recognise(whisperContext(), forged, principal)).toMatchObject({
      kind: 'refused',
      conflict_code: 'SIGNATURE_INVALID',
    });

    // The one-shot identity is a resource a GENUINE operative still needs: a
    // forgery that burned it would be a denial-of-duress attack.
    expect(await receiptsForIdentity(forged)).toHaveLength(0);
    expect(await whisperIncidentsFor(whisperRecognitionFingerprint(forged))).toHaveLength(0);

    const genuine = signResult(unsigned, keyAlpha.privateKey);
    const accepted = await whisper.recognise(whisperContext(), genuine, principal);
    expect(accepted).toMatchObject({ kind: 'accepted', replayed: false });
    expect(await receiptsForIdentity(genuine)).toHaveLength(1);
    expect(await whisperIncidentsFor(whisperRecognitionFingerprint(genuine))).toHaveLength(1);
  }, 180_000);

  it('W22-06/14: a substituted principal cannot lend invoke authority, and the refusal precedes the verifier and the signal lookup', async () => {
    // The roster names the DISPATCHER, who does not hold invoke. The only thing
    // between them and a silent dispatch is the principal binding.
    const signal = await activeSignalViaStudio({ authorised_user_ids: [fx.dispatcherA1] });

    const borrower = await principalFor(fx.dispatcherA1);
    const lender = await principalFor(fx.opAlpha);
    // Non-vacuity: without this the test could pass for the wrong reason.
    expect(borrower.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(false);
    expect(lender.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(true);

    // Context and signed statement are BOTH the dispatcher's and both valid.
    // Only the principal is somebody else's.
    const signed = signResult(unsignedResult(signal, { actor_user_id: fx.dispatcherA1 }), keyAlpha.privateKey);
    const context = whisperContext({ actorUserId: fx.dispatcherA1 });

    const verifySpy = vi.spyOn(verifier, 'verify');
    const lookupSpy = vi.spyOn(whisperRepository, 'findVersionForRuntime');

    const outcome = await whisper.recognise(context, signed, lender);

    expect(outcome).toMatchObject({ kind: 'refused', conflict_code: 'DEVICE_CONTEXT_MISMATCH', replayed: false });
    // The ORDERING is the disclosure argument: a binding failure must not be
    // able to reach the verifier or the lookup, or it could be timed to probe
    // whether a signal exists at all.
    expect(verifySpy).not.toHaveBeenCalled();
    expect(lookupSpy).not.toHaveBeenCalled();

    // The refusal precedes the replay boundary, so the one-shot identity is
    // untouched and still spendable — and nobody was ever going to be sent.
    expect(await receiptsForIdentity(signed)).toHaveLength(0);
    expect(await whisperIncidentsFor(whisperRecognitionFingerprint(signed))).toHaveLength(0);
  }, 180_000);

  it('W22-06/15: PostgreSQL itself refuses a second ACTIVE version of one family when the service is bypassed', async () => {
    const signal = await activeSignalViaStudio();
    const active = await prisma.whisperSignalVersion.findFirstOrThrow({
      where: { organisationId: fx.orgA, whisperSignalId: signal.id, status: 'ACTIVE' },
    });
    expect(active.signalVersion).toBe(1);

    const configuration = {
      modality: 'DEVICE_ACTION',
      device_action_id: DEVICE_ACTION,
      authorised_user_ids: [fx.opAlpha],
      context_requirements: {},
      minimum_confidence: 0.5,
      response_protocol_id: 'SILENT_INCIDENT_RESPONSE',
    } as const;
    const directRow = (overrides: Partial<Prisma.WhisperSignalVersionUncheckedCreateInput>): Prisma.WhisperSignalVersionUncheckedCreateInput => ({
      whisperSignalId: signal.id,
      signalVersion: 2,
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      name: 'Direct write',
      status: 'ACTIVE',
      modality: configuration.modality,
      deviceActionId: configuration.device_action_id,
      authorisedUserIds: [...configuration.authorised_user_ids],
      contextRequirements: configuration.context_requirements,
      minimumConfidence: configuration.minimum_confidence,
      responseProtocolId: configuration.response_protocol_id,
      configurationFingerprint: whisperConfigurationFingerprint(configuration),
      createdByUserId: fx.commanderA1,
      traceId: `trace-${randomUUID()}`,
      ...overrides,
    });

    // A straight INSERT of a second ACTIVE version of the same family.
    expect(await prismaErrorCode(prisma.whisperSignalVersion.create({ data: directRow({}) }))).toBe('P2002');

    // ...and the UPDATE route to the same end. A DRAFT successor is entirely
    // legitimate; promoting it while the incumbent is still ACTIVE is not.
    const draft = await prisma.whisperSignalVersion.create({ data: directRow({ signalVersion: 3, status: 'DRAFT' }) });
    expect(await prismaErrorCode(prisma.whisperSignalVersion.update({ where: { id: draft.id }, data: { status: 'ACTIVE' } }))).toBe('P2002');

    // The tenant is left with exactly one answer to "which configuration is
    // live", which is the only state in which a duress signal is unambiguous.
    const stillActive = await prisma.whisperSignalVersion.findMany({
      where: { organisationId: fx.orgA, whisperSignalId: signal.id, status: 'ACTIVE' },
    });
    expect(stillActive).toHaveLength(1);
    expect(stillActive[0]?.id).toBe(active.id);
  }, 180_000);

  it('W22-06/16: there is no public Whisper recognition HTTP route', async () => {
    // W21-05: the runtime's whole safety argument rests on
    // AuthenticatedWhisperDeviceContext being SERVER-established. An invoke
    // endpoint would mean accepting that context from a JSON body — the exact
    // C10-02 trust hole, on the one channel whose consequence is a silent
    // duress dispatch. These are the paths a future convenience commit would
    // most plausibly add.
    const plausible = ['/api/v1/whisper/recognitions', '/api/v1/whisper/invoke', '/api/v1/whisper/signals/recognise'];
    const signal = await activeSignalViaStudio();
    const body = signResult(unsignedResult(signal), keyAlpha.privateKey);

    for (const path of plausible) {
      // Posted by an operative who genuinely HOLDS whisper.device-action.invoke
      // and a perfectly valid signed statement: the route must still not exist.
      const res = await post(path, fx.opAlpha, body);
      expect(res.status, `${path} must not be routable`).toBe(404);
      expect([200, 201], `${path} must never succeed`).not.toContain(res.status);
    }

    // Nothing was recognised, so no receipt and no incident came of it.
    expect(await receiptsForIdentity(body)).toHaveLength(0);
    expect(await whisperIncidentsFor(whisperRecognitionFingerprint(body))).toHaveLength(0);

    // The Studio surface that DOES exist is unaffected.
    expect((await get(`/api/v1/whisper/signals/${signal.id}`, fx.commanderA1)).status).toBe(200);
  }, 180_000);
});
