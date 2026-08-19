import { randomUUID } from 'node:crypto';
import { BadRequestException, type INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
  deriveOfflineDownstreamIdempotencyKey,
  MAX_OFFLINE_DEVICE_SEQUENCE,
  type AuthenticatedFieldDeviceContext,
  type FieldOfflineOperationKind,
  type OfflineOperationResult,
  type OfflineReplayConflict,
  type OfflineReplayNamespace,
} from '@sentinel/contracts';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { PrismaService } from '../../prisma/prisma.service';
import { TIMELINE_MESSAGE_ACKNOWLEDGED } from '../field-messaging/field-messaging.constants';
import { FieldMessagingService } from '../field-messaging/field-messaging.service';
import { FieldService } from '../field/field.service';
import { intersectSiteScope } from '../identity/list-pagination';
import {
  ACTION_MESSAGE_SEND,
  AUDIT_OFFLINE_OPERATION_FINALIZED,
  AUDIT_OFFLINE_OPERATION_RECEIVED,
  OFFLINE_PROCESSING_LEASE_MS,
} from './field-offline.constants';
import { FieldOfflineRepository } from './field-offline.repository';
import { FieldOfflineReplayService } from './field-offline.service';
import type { OfflineSubmissionOutcome } from './field-offline.types';

/**
 * WP-20 Checkpoint B acceptance suite — the locked replay rules, exercised
 * against the live stack through the REAL module graph (AppModule), the real
 * domain services and the real Postgres constraints.
 *
 * The module deliberately publishes no HTTP surface (C10-02: `device_id` from
 * a JSON body is not authenticated device identity), so these tests call
 * `FieldOfflineReplayService.submit` directly with a `Principal` built exactly
 * as the global DevAuthGuard builds it — the same `buildPrincipal`, so
 * `hasAction` is derived from the §62 role table and no test can assert an
 * authority the seeded roles do not grant.
 *
 * THE INVARIANT UNDER TEST
 * ------------------------
 * A reconnect may DELAY an authorised operation. It must never duplicate it,
 * reorder it, weaken its authorization, backdate server authority, or let a
 * changed request hide behind an old idempotency identity.
 *
 * A NOTE ON ISOLATION: one `(organisation, site, user, device)` namespace is a
 * STATEFUL queue, so every test uses its own device id and its own freshly
 * created assignment. Nothing here depends on execution order.
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

const tag = `wp20_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

/**
 * R10 fixture: enough ELIGIBLE recipients that a send can pass every
 * individual bound and still blow the 64 KiB aggregate. They are dispatchers
 * because a command role is eligible on scope alone (WP-18/C8-03), so the
 * fixture needs no assignment per recipient — and their ids are deliberately
 * long (but inside the 256-char contract bound) so the recipient array alone
 * contributes ~22 KiB to the canonical serialization.
 */
const BULK_RECIPIENT_COUNT = 120;
const bulkRecipients = Array.from({ length: BULK_RECIPIENT_COUNT }, (_, index) => `${tag}_bulk_${index}_${'r'.repeat(150)}`);

const fx = {
  orgA: `${tag}_orgA`,
  /** Never persisted: used only for identity-binding refusals that never touch the database. */
  orgGhost: `${tag}_orgGhost`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  opAlpha: `${tag}_opAlpha`,
  opBravo: `${tag}_opBravo`,
  /**
   * B10-02: an operative with NO standing eligibility fixture. Every other
   * operative here is depended on by the locked 17, so the drift regression
   * needs a recipient whose incident eligibility it can break and restore
   * without touching a fixture another test reads.
   */
  opCharlie: `${tag}_opCharlie`,
  dispatcherA1: `${tag}_dispatcherA1`,
  incidentA1: randomUUID(),
};

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.create({ data: { id: fx.orgA, name: 'WP-20 Org A' } });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
    ],
  });

  const users: Array<{ id: string; role: string; site: string }> = [
    { id: fx.opAlpha, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opBravo, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opCharlie, role: 'field.operative', site: fx.siteA1 },
    { id: fx.dispatcherA1, role: 'dispatcher', site: fx.siteA1 },
    ...bulkRecipients.map((id) => ({ id, role: 'dispatcher', site: fx.siteA1 })),
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: fx.orgA, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });

  // B11-13: an incident now states its ORIGIN. This fixture is Fusion-shaped,
  // so source_ref IS the hypothesis id, exactly as the WP-21B migration
  // backfills every pre-existing row.
  const fixtureHypothesisId = randomUUID();
  await prisma.incident.create({
    data: {
      id: fx.incidentA1, hypothesisId: fixtureHypothesisId, incidentCandidateId: randomUUID(), sourceKind: 'FUSION_HYPOTHESIS', sourceRef: fixtureHypothesisId,
      organisationId: fx.orgA, siteId: fx.siteA1, incidentType: 'wp20.test', severity: 'SEV3',
      threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
    },
  });

  // WP-18/C8-03 eligibility: a field.operative may only send into, or be named
  // on, an incident they hold an OPERATIONAL assignment for. These two are the
  // standing fixtures; every transition test creates its own fresh assignment.
  await prisma.fieldAssignment.createMany({
    data: [fx.opAlpha, fx.opBravo].map((assignee) => ({
      organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, assigneeUserId: assignee,
      assignmentType: 'INCIDENT_RESPONSE', priority: 'SEV3', status: 'ACCEPTED', deliveryState: 'REQUESTED',
      needToKnowSummary: 'wp20 eligibility fixture', idempotencyKey: `${tag}-eligibility-${assignee}`,
      createdByUserId: fx.dispatcherA1, updatedByUserId: fx.dispatcherA1,
    })),
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA];
  // Receipts first (no foreign keys — a reliability artefact), then cursors,
  // which hold a Restrict relation to Site and so must go before the sites do.
  await prisma.fieldOfflineOperationReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOfflineDeviceCursor.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: { in: orgs } } } });
  await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId: { in: orgs } } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
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
  operation_kind: FieldOfflineOperationKind;
  payload: Record<string, unknown>;
  created_at: string;
  trace_id: string;
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

function acceptOp(assignmentId: string, overrides: Partial<OperationDraft> = {}): OperationDraft {
  return makeOperation({
    operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
    payload: { assignment_id: assignmentId, expected_status: 'REQUESTED' },
    ...overrides,
  });
}

/** The C10-02 seam: TRUSTED identity, never derived from the envelope. */
function makeContext(
  userId: string,
  deviceId: string,
  siteIds: string[] = [fx.siteA1],
  organisationId: string = fx.orgA,
): AuthenticatedFieldDeviceContext {
  return { organisationId, userId, deviceId, authorisedSiteIds: siteIds };
}

/** Semantically identical to what the global DevAuthGuard attaches to a request. */
function principalFor(userId: string, role: string, siteId: string | null = fx.siteA1, organisationId: string = fx.orgA): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 5 }, organisation_id: organisationId, roles: [{ role, site_id: siteId }] });
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

function expectInvalid(outcome: OfflineSubmissionOutcome): string[] {
  expect(outcome.kind, JSON.stringify(outcome)).toBe('invalid');
  if (outcome.kind !== 'invalid') throw new Error('unreachable: outcome is not invalid');
  return outcome.issues;
}

/** `device_sequence` is BIGINT, so a plain JSON.stringify of a receipt row throws. */
function jsonWithBigInt(value: unknown): string {
  return JSON.stringify(value, (_key, entry: unknown) => (typeof entry === 'bigint' ? entry.toString() : entry));
}

describe('WP-20 offline replay acceptance (live stack)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let service: FieldOfflineReplayService;
  let repository: FieldOfflineRepository;
  let field: FieldService;
  let messaging: FieldMessagingService;

  const alpha = (): Principal => principalFor(fx.opAlpha, 'field.operative');
  const bravo = (): Principal => principalFor(fx.opBravo, 'field.operative');

  let fixtureSeq = 0;

  /** A fresh REQUESTED assignment, so each transition test starts from a clean CAS. */
  async function newAssignment(assignee: string, status: string = 'REQUESTED'): Promise<string> {
    const row = await prisma.fieldAssignment.create({
      data: {
        organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, assigneeUserId: assignee,
        assignmentType: 'INCIDENT_RESPONSE', priority: 'SEV3', status, deliveryState: 'REQUESTED',
        needToKnowSummary: 'wp20 fixture', idempotencyKey: `${tag}-assignment-${fixtureSeq++}`,
        createdByUserId: fx.dispatcherA1, updatedByUserId: fx.dispatcherA1,
      },
      select: { id: true },
    });
    return row.id;
  }

  /**
   * A message whose recipient row already carries TRANSPORT evidence. WP-18's
   * ACKNOWLEDGE_REQUIRES_STATE is DELIVERED and there is deliberately no route
   * that manufactures it, so the fixture writes it directly.
   */
  async function newDeliveredMessage(recipient: string): Promise<string> {
    const row = await prisma.incidentFieldMessage.create({
      data: {
        organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, senderUserId: fx.dispatcherA1,
        body: 'wp20 seeded message', mediaRefs: [], retentionClass: 'standard',
        idempotencyKey: `${tag}-message-${fixtureSeq++}`, traceId: `${tag}-seed`,
        recipients: {
          create: [{ organisationId: fx.orgA, siteId: fx.siteA1, recipientUserId: recipient, deliveryState: 'DELIVERED', deliveredAt: new Date() }],
        },
      },
      select: { id: true },
    });
    return row.id;
  }

  const receiptsFor = (userId: string, deviceId: string, siteId: string = fx.siteA1) =>
    prisma.fieldOfflineOperationReceipt.findMany({
      where: { organisationId: fx.orgA, siteId, userId, deviceId },
      orderBy: { deviceSequence: 'asc' },
    });

  const cursorFor = (userId: string, deviceId: string, siteId: string = fx.siteA1) =>
    prisma.fieldOfflineDeviceCursor.findUnique({
      where: { organisationId_siteId_userId_deviceId: { organisationId: fx.orgA, siteId, userId, deviceId } },
    });

  /** Offline-executor audit rows: identity and disposition only (C10-11). */
  const offlineAuditCount = (offlineOperationId: string, disposition: string) =>
    prisma.fieldAuditLog.count({
      where: {
        organisationId: fx.orgA,
        kind: AUDIT_OFFLINE_OPERATION_FINALIZED,
        AND: [
          { payload: { path: ['offline_operation_id'], equals: offlineOperationId } },
          { payload: { path: ['disposition'], equals: disposition } },
        ],
      },
    });

  /** DOMAIN evidence. Offline audit rows carry no assignment id, so this counts only WP-16's own trail. */
  const assignmentAuditCount = (assignmentId: string) => prisma.fieldAuditLog.count({ where: { assignmentId } });
  const assignmentOutboxCount = (assignmentId: string) =>
    prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: assignmentId } } });
  const assignmentIdempotencyCount = (assignmentId: string) => prisma.fieldAssignmentActionIdempotency.count({ where: { assignmentId } });
  const assignmentStatus = async (assignmentId: string): Promise<string> =>
    (await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId }, select: { status: true } })).status;

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    prisma = app.get(PrismaService);
    service = app.get(FieldOfflineReplayService);
    repository = app.get(FieldOfflineRepository);
    field = app.get(FieldService);
    messaging = app.get(FieldMessagingService);
    await seed(prisma);
  }, 120_000);

  afterAll(async () => {
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 60_000);

  /**
   * Every spy in this file is a deliberately injected fault. Leaving one
   * installed would silently corrupt the next test, and the B10 regressions
   * below install faults from inside mock implementations where an explicit
   * `mockRestore` is easy to miss — so restoration is unconditional.
   */
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // B10 shared recipe helpers
  // ---------------------------------------------------------------------------

  /**
   * The recipe every B10-01/B10-02 test starts from: a REAL submit whose
   * downstream effect commits and whose FINALIZATION then faults. It leaves the
   * receipt in UNKNOWN with claim generation 1 consumed, the cursor held, and
   * the domain effect durably committed — the exact "we do not know what
   * happened" state both rules exist to recover from.
   */
  async function submitWithFaultedFinalize(
    principal: Principal,
    context: AuthenticatedFieldDeviceContext,
    operation: OperationDraft,
  ): Promise<OfflineSubmissionOutcome> {
    const fault = vi.spyOn(repository, 'finalizeAndAdvance').mockRejectedValueOnce(new Error('simulated finalization fault'));
    try {
      return await service.submit(principal, context, operation);
    } finally {
      fault.mockRestore();
    }
  }

  /** Claims the receipt and asserts which generation the claim established. */
  async function claimAt(receiptId: string, expectedGeneration: number): Promise<number> {
    const generation = await repository.claimForProcessing(receiptId);
    expect(generation, 'the claim was refused').toBe(expectedGeneration);
    if (generation === null) throw new Error('unreachable: claim was lost');
    return generation;
  }

  /**
   * Ages a claim past the C10-08 recovery lease, so the next claim is a LEGAL
   * steal rather than a race. Deterministic by construction: the stall is
   * expressed as a timestamp, never as elapsed wall-clock time.
   */
  async function ageLeasePastExpiry(receiptId: string): Promise<void> {
    await prisma.fieldOfflineOperationReceipt.update({
      where: { id: receiptId },
      data: { processingClaimedAt: new Date(Date.now() - 2 * OFFLINE_PROCESSING_LEASE_MS) },
    });
  }

  const namespaceFor = (userId: string, deviceId: string, siteId: string = fx.siteA1): OfflineReplayNamespace => ({
    organisation_id: fx.orgA, site_id: siteId, user_id: userId, device_id: deviceId,
  });

  /** The identity half of a fenced repository write, read back off the stored receipt. */
  function fenceIdentity(
    row: { id: string; offlineOperationId: string; deviceSequence: bigint; operationKind: string; requestFingerprint: string },
    namespace: OfflineReplayNamespace,
    traceId: string,
    claimGeneration: number,
  ) {
    return {
      namespace,
      receiptId: row.id,
      offlineOperationId: row.offlineOperationId,
      deviceSequence: Number(row.deviceSequence),
      operationKind: row.operationKind,
      requestFingerprint: row.requestFingerprint,
      traceId,
      claimGeneration,
    };
  }

  /** EVERY finalization audit row for one operation, whatever disposition it carries. */
  const finalizedAuditCount = (offlineOperationId: string) =>
    prisma.fieldAuditLog.count({
      where: {
        organisationId: fx.orgA,
        kind: AUDIT_OFFLINE_OPERATION_FINALIZED,
        payload: { path: ['offline_operation_id'], equals: offlineOperationId },
      },
    });

  // --- 1. concurrency ------------------------------------------------------

  it('R3/C10-08: two CONCURRENT submissions of the identical operation at the same sequence produce exactly one domain effect', async () => {
    const device = `${tag}_dev_concurrent`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });
    const context = makeContext(fx.opAlpha, device);

    const outcomes = await Promise.all([service.submit(alpha(), context, operation), service.submit(alpha(), context, operation)]);

    // Exactly one submission may execute the effect; the other must be told so
    // without firing a second one.
    const executed = outcomes.filter((outcome) => outcome.kind === 'result' && outcome.result.replayed === false);
    expect(executed).toHaveLength(1);
    expect(expectResult(executed[0]).outcome).toBe('APPLIED');

    const others = outcomes.filter((outcome) => !executed.includes(outcome));
    expect(others).toHaveLength(1);
    const other = others[0];
    const isReplayOfTheSameOutcome = other.kind === 'result' && other.result.replayed && other.result.outcome === 'APPLIED';
    const isInProgress = other.kind === 'conflict' && other.conflict.conflict_code === 'OPERATION_IN_PROGRESS';
    expect(isReplayOfTheSameOutcome || isInProgress, jsonWithBigInt(other)).toBe(true);

    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await assignmentAuditCount(assignmentId)).toBe(1);
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
    expect(await offlineAuditCount(operation.offline_operation_id, 'APPLIED')).toBe(1);
  });

  // --- 2. changed request under a consumed position ------------------------

  it('C10-04: the same sequence carrying a CHANGED request is SEQUENCE_REUSED and produces no second effect', async () => {
    const device = `${tag}_dev_reused`;
    const applied = await newAssignment(fx.opAlpha);
    const untouched = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);

    const operation = acceptOp(applied, { device_id: device, device_sequence: 0 });
    expect(expectResult(await service.submit(alpha(), context, operation)).outcome).toBe('APPLIED');

    // Same envelope identity, same sequence, DIFFERENT payload: a changed
    // request may never hide behind an identity an earlier one established.
    const changed: OperationDraft = { ...operation, payload: { assignment_id: untouched, expected_status: 'REQUESTED' } };
    const conflict = expectConflict(await service.submit(alpha(), context, changed));

    expect(conflict.conflict_code).toBe('SEQUENCE_REUSED');
    expect(conflict.device_sequence).toBe(0);
    expect(await assignmentStatus(untouched)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(untouched)).toBe(0);

    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    expect(Number(receipts[0].deviceSequence)).toBe(0);
    expect(receipts[0].status).toBe('APPLIED');
  });

  // --- 3. gap --------------------------------------------------------------

  it('C10-03: a sequence GAP is refused with the expected and received positions, and writes no receipt', async () => {
    const device = `${tag}_dev_gap`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 2 });

    const conflict = expectConflict(await service.submit(alpha(), makeContext(fx.opAlpha, device), operation));

    expect(conflict.conflict_code).toBe('SEQUENCE_GAP');
    expect(conflict.expected_sequence).toBe(0);
    expect(conflict.received_sequence).toBe(2);
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(0);
    expect(await assignmentStatus(assignmentId)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(0);
  });

  // --- 4. two devices, one user --------------------------------------------

  it('C10-02/R2: two devices of the SAME user each own sequence 0, and both apply independently', async () => {
    const deviceA = `${tag}_dev_two_a`;
    const deviceB = `${tag}_dev_two_b`;
    const assignmentA = await newAssignment(fx.opAlpha);
    const assignmentB = await newAssignment(fx.opAlpha);

    const resultA = expectResult(
      await service.submit(alpha(), makeContext(fx.opAlpha, deviceA), acceptOp(assignmentA, { device_id: deviceA, device_sequence: 0 })),
    );
    const resultB = expectResult(
      await service.submit(alpha(), makeContext(fx.opAlpha, deviceB), acceptOp(assignmentB, { device_id: deviceB, device_sequence: 0 })),
    );

    expect(resultA.outcome).toBe('APPLIED');
    expect(resultB.outcome).toBe('APPLIED');
    expect(await assignmentStatus(assignmentA)).toBe('ACCEPTED');
    expect(await assignmentStatus(assignmentB)).toBe('ACCEPTED');
    expect(Number((await cursorFor(fx.opAlpha, deviceA))?.lastFinalizedSequence)).toBe(0);
    expect(Number((await cursorFor(fx.opAlpha, deviceB))?.lastFinalizedSequence)).toBe(0);
    expect(await receiptsFor(fx.opAlpha, deviceA)).toHaveLength(1);
    expect(await receiptsFor(fx.opAlpha, deviceB)).toHaveLength(1);
  });

  // --- 5. same device string, different user -------------------------------

  it('C10-02: the SAME device string under another user gets its own fresh cursor and cannot inherit the first user receipts', async () => {
    const device = `${tag}_dev_shared_string`;
    const assignmentId = await newAssignment(fx.opAlpha);

    const applied = expectResult(
      await service.submit(alpha(), makeContext(fx.opAlpha, device), acceptOp(assignmentId, { device_id: device, device_sequence: 0 })),
    );
    expect(applied.outcome).toBe('APPLIED');
    const alphaReceiptsBefore = await receiptsFor(fx.opAlpha, device);
    expect(alphaReceiptsBefore).toHaveLength(1);

    // opBravo, identical device id string, sequence 0. The namespace includes
    // the AUTHENTICATED user, so this is a fresh queue — never a replay of
    // opAlpha's receipt.
    const bravoOutcome = await service.submit(
      bravo(),
      makeContext(fx.opBravo, device),
      acceptOp(assignmentId, { device_id: device, device_sequence: 0 }),
    );

    // The domain refuses it (the assignment is opAlpha's), and that refusal is
    // itself proof the submission was classified FRESH and executed rather
    // than answered from opAlpha's stored outcome.
    const bravoResult = expectResult(bravoOutcome);
    expect(bravoResult.outcome).toBe('REJECTED');
    expect(bravoResult.replayed).toBe(false);
    expect(bravoResult.result_snapshot).toEqual({ http_status: 403 });

    const bravoReceipts = await receiptsFor(fx.opBravo, device);
    expect(bravoReceipts).toHaveLength(1);
    expect(bravoReceipts[0].userId).toBe(fx.opBravo);
    expect(Number(bravoReceipts[0].deviceSequence)).toBe(0);
    expect(bravoReceipts[0].requestFingerprint).not.toBe(alphaReceiptsBefore[0].requestFingerprint);

    expect(await receiptsFor(fx.opAlpha, device)).toEqual(alphaReceiptsBefore);
    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
  });

  // --- 6. site scope -------------------------------------------------------

  it('C10-02: a site outside the authenticated DEVICE scope is refused before any persistence', async () => {
    const device = `${tag}_dev_cross_site`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const operation = acceptOp(assignmentId, { device_id: device, site_id: fx.siteA2 });

    const conflict = expectConflict(await service.submit(alpha(), makeContext(fx.opAlpha, device, [fx.siteA1]), operation));

    expect(conflict.conflict_code).toBe('SITE_SCOPE_MISMATCH');
    // Fails BEFORE the replay machinery: no cursor, no receipt at either site.
    expect(await prisma.fieldOfflineOperationReceipt.count({ where: { organisationId: fx.orgA, deviceId: device } })).toBe(0);
    expect(await prisma.fieldOfflineDeviceCursor.count({ where: { organisationId: fx.orgA, deviceId: device } })).toBe(0);
    expect(await assignmentStatus(assignmentId)).toBe('REQUESTED');
  });

  // --- 7. N+1 may not leapfrog an unresolved N (also locked test 13) --------

  it('C10-08/C10-07: an UNKNOWN outcome does not advance the cursor, and N+1 cannot leapfrog the unresolved N', async () => {
    const device = `${tag}_dev_unresolved`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);

    // Simulate a crash between the committed domain effect and finalization.
    const crash = vi.spyOn(repository, 'finalizeAndAdvance').mockRejectedValueOnce(new Error('simulated crash before finalization'));
    const crashed = await service.submit(alpha(), context, acceptOp(assignmentId, { device_id: device, device_sequence: 0 }));
    crash.mockRestore();

    expect(expectConflict(crashed).conflict_code).toBe('UNKNOWN_OUTCOME');
    // The downstream effect DID commit — that is exactly why the outcome is unknown.
    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');

    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].status).toBe('UNKNOWN');
    expect(receipts[0].finalizedAt).toBeNull();
    expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();

    const leapfrog = acceptOp(await newAssignment(fx.opAlpha), { device_id: device, device_sequence: 1 });
    const gap = expectConflict(await service.submit(alpha(), context, leapfrog));
    expect(gap.conflict_code).toBe('SEQUENCE_GAP');
    expect(gap.expected_sequence).toBe(0);
    expect(gap.received_sequence).toBe(1);

    // Still exactly one receipt: the leapfrog wrote nothing at all.
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
    expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();
  });

  // --- 8. crash after commit, before finalization: retry converges ---------

  it('C10-08/C10-09: a retry after a crash reclaims the receipt, converges on the SAME downstream identity and applies exactly once', async () => {
    const device = `${tag}_dev_converge`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    const crash = vi.spyOn(repository, 'finalizeAndAdvance').mockRejectedValueOnce(new Error('simulated crash after downstream commit'));
    expect(expectConflict(await service.submit(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    crash.mockRestore();

    // The SAME operation, same fingerprint. UNKNOWN admits reclaim.
    const converged = expectResult(await service.submit(alpha(), context, operation));
    expect(converged.outcome).toBe('APPLIED');
    expect(converged.replayed).toBe(false);
    expect(converged.next_expected_sequence).toBe(1);
    expect(converged.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });

    // EXACTLY ONE domain effect across both attempts.
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await assignmentAuditCount(assignmentId)).toBe(1);
    expect(await assignmentOutboxCount(assignmentId)).toBe(1);

    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].status).toBe('APPLIED');
    expect(receipts[0].attemptCount).toBe(2);
    // C10-09: the retry re-invoked the domain with the SERVER-derived key the
    // first attempt stored, which is what let the domain converge.
    expect(receipts[0].downstreamIdempotencyKey).toBe(
      deriveOfflineDownstreamIdempotencyKey(
        { organisation_id: fx.orgA, site_id: fx.siteA1, user_id: fx.opAlpha, device_id: device },
        operation.offline_operation_id,
        'FIELD_ASSIGNMENT_ACCEPT',
      ),
    );
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);
  });

  // --- 9. assignment replay ------------------------------------------------

  it('C10-11/R7: replaying an APPLIED assignment transition returns the stored outcome and duplicates no domain evidence', async () => {
    const device = `${tag}_dev_replay_assignment`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    const first = expectResult(await service.submit(alpha(), context, operation));
    expect(first.outcome).toBe('APPLIED');
    expect(first.replayed).toBe(false);

    const auditBefore = await assignmentAuditCount(assignmentId);
    const outboxBefore = await assignmentOutboxCount(assignmentId);

    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toBe('APPLIED');
    expect(replay.finalized_at).toBe(first.finalized_at);
    expect(replay.result_ref).toBe(assignmentId);

    expect(await assignmentAuditCount(assignmentId)).toBe(auditBefore);
    expect(await assignmentOutboxCount(assignmentId)).toBe(outboxBefore);
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
  });

  // --- 10. message send replay --------------------------------------------

  it('C10-11/R6: a replayed message send creates no second message, and the snapshot carries a COUNT rather than recipients or a body', async () => {
    const device = `${tag}_dev_send_replay`;
    const context = makeContext(fx.opAlpha, device);
    const body = `wp20-body-${randomUUID()}`;
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      payload: { incident_id: fx.incidentA1, recipient_user_ids: [fx.opBravo], body, retention_class: 'standard' },
    });

    const sent = expectResult(await service.submit(alpha(), context, operation));
    expect(sent.outcome).toBe('APPLIED');
    const messageId = sent.result_ref ?? '';
    expect(messageId).not.toBe('');
    expect(sent.result_snapshot).toEqual({ incident_field_message_id: messageId, incident_id: fx.incidentA1, recipient_count: 1 });
    expect(await prisma.incidentFieldMessage.count({ where: { id: messageId } })).toBe(1);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId } })).toBe(1);

    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    expect(replay.result_ref).toBe(messageId);
    expect(replay.finalized_at).toBe(sent.finalized_at);

    // Still exactly one message from this send, and one recipient row.
    expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA, senderUserId: fx.opAlpha, traceId: operation.trace_id } })).toBe(1);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId } })).toBe(1);

    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    const snapshotJson = jsonWithBigInt(receipts[0].resultSnapshot);
    expect(snapshotJson).toContain('recipient_count');
    expect(snapshotJson).not.toContain(body);
    expect(snapshotJson).not.toContain(fx.opBravo);
  });

  // --- 11. acknowledge replay ---------------------------------------------

  it('C10-06/C8-01: a replayed acknowledgement does not restamp acknowledged_at or append a second timeline entry', async () => {
    const device = `${tag}_dev_ack_replay`;
    const context = makeContext(fx.opAlpha, device);
    const messageId = await newDeliveredMessage(fx.opAlpha);
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
      payload: { message_id: messageId },
    });

    const acknowledged = expectResult(await service.submit(alpha(), context, operation));
    expect(acknowledged.outcome).toBe('APPLIED');

    const timelineWhere = {
      incidentId: fx.incidentA1,
      kind: TIMELINE_MESSAGE_ACKNOWLEDGED,
      payload: { path: ['incident_field_message_id'], equals: messageId },
    };
    const before = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.opAlpha } });
    expect(before.deliveryState).toBe('ACKNOWLEDGED');
    expect(before.acknowledgedAt).not.toBeNull();
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere })).toBe(1);

    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toBe('APPLIED');

    const after = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.opAlpha } });
    expect(after.acknowledgedAt?.toISOString()).toBe(before.acknowledgedAt?.toISOString());
    expect(after.deliveryState).toBe('ACKNOWLEDGED');
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere })).toBe(1);
  });

  // --- 12. finalized rejection --------------------------------------------

  it('C10-07/C10-11: a deterministic rejection advances the cursor exactly once and replays as the SAME stored rejection', async () => {
    const device = `${tag}_dev_rejection`;
    const context = makeContext(fx.opAlpha, device);
    // opAlpha acting on an assignment that belongs to opBravo: WP-16 refuses it.
    const foreignAssignment = await newAssignment(fx.opBravo);
    const operation = acceptOp(foreignAssignment, { device_id: device, device_sequence: 0 });

    const rejected = expectResult(await service.submit(alpha(), context, operation));
    expect(rejected.outcome).toBe('REJECTED');
    expect(rejected.replayed).toBe(false);
    // R6: the status code and NOTHING else — no domain error text.
    expect(rejected.result_snapshot).toEqual({ http_status: 403 });
    expect(rejected.result_ref).toBeNull();
    expect(rejected.next_expected_sequence).toBe(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);

    // The stored rejection is RETURNED, not re-evaluated.
    const domainSpy = vi.spyOn(field, 'transitionAssignment');
    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(domainSpy).not.toHaveBeenCalled();
    domainSpy.mockRestore();

    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toBe('REJECTED');
    expect(replay.finalized_at).toBe(rejected.finalized_at);
    expect(replay.result_snapshot).toEqual({ http_status: 403 });

    // Exactly one advance, and no mutation of the foreign assignment.
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);
    expect(await assignmentStatus(foreignAssignment)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(foreignAssignment)).toBe(0);
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
    expect(await offlineAuditCount(operation.offline_operation_id, 'REJECTED')).toBe(1);
  });

  // --- 14. the duplicate answers from the RECEIPT, not from live state -----

  it('C10-11/R7: a duplicate returns the ORIGINAL bounded metadata even after the domain object has moved on', async () => {
    const device = `${tag}_dev_stale_snapshot`;
    const context = makeContext(fx.opAlpha, device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    const applied = expectResult(await service.submit(alpha(), context, operation));
    expect(applied.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });

    // The world moves on underneath the receipt.
    await prisma.fieldAssignment.update({ where: { id: assignmentId }, data: { status: 'COMPLETED', completedAt: new Date() } });

    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    // Still the post-accept state: a replay reads the receipt, never the live object.
    expect(replay.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });
    expect(await assignmentStatus(assignmentId)).toBe('COMPLETED');
  });

  // --- 15. privacy ---------------------------------------------------------

  it('C10-11/R6: neither the receipt nor the offline audit trail carries a message body, a recipient id, or an OFFLINE_* outbox row', async () => {
    const device = `${tag}_dev_privacy`;
    const context = makeContext(fx.opAlpha, device);
    const body = `wp20-secret-${randomUUID()}`;
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      payload: { incident_id: fx.incidentA1, recipient_user_ids: [fx.opBravo], body, retention_class: 'standard' },
    });

    const sent = expectResult(await service.submit(alpha(), context, operation));
    expect(sent.outcome).toBe('APPLIED');
    const messageId = sent.result_ref ?? '';

    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    // The two hash columns are excluded: a fingerprint is a one-way digest by
    // construction, so scanning it proves nothing about disclosure.
    const scrubbed: Record<string, unknown> = { ...receipts[0] };
    delete scrubbed.requestFingerprint;
    delete scrubbed.downstreamIdempotencyKey;
    const receiptJson = jsonWithBigInt(scrubbed);
    expect(receiptJson).not.toContain(body);
    expect(receiptJson).not.toContain(fx.opBravo);
    expect(jsonWithBigInt(receipts[0].resultSnapshot)).not.toContain(body);
    expect(jsonWithBigInt(receipts[0].resultSnapshot)).not.toContain(fx.opBravo);

    const auditRows = await prisma.fieldAuditLog.findMany({
      where: {
        organisationId: fx.orgA,
        kind: { in: [AUDIT_OFFLINE_OPERATION_RECEIVED, AUDIT_OFFLINE_OPERATION_FINALIZED] },
        payload: { path: ['offline_operation_id'], equals: operation.offline_operation_id },
      },
    });
    expect(auditRows).toHaveLength(2);
    const auditJson = jsonWithBigInt(auditRows.map((row) => row.payload));
    expect(auditJson).not.toContain(body);
    expect(auditJson).not.toContain(fx.opBravo);

    // The executor owns no outbox of its own: every published signal is the
    // DOMAIN's, written by WP-18 inside its own transaction.
    const outboxPayloads = [
      ...(await prisma.fieldOutbox.findMany({ where: { organisationId: fx.orgA }, select: { payload: true } })),
      ...(await prisma.incidentFieldMessageOutbox.findMany({ where: { organisationId: fx.orgA }, select: { payload: true } })),
    ].map((row) => row.payload as { kind?: unknown; message_id?: unknown });
    expect(outboxPayloads.some((payload) => typeof payload.kind === 'string' && payload.kind.startsWith('OFFLINE_'))).toBe(false);
    expect(outboxPayloads.filter((payload) => payload.kind === 'incident_field_message.updated' && payload.message_id === messageId)).toHaveLength(1);
  });

  // --- 16. R10 aggregate size ---------------------------------------------

  it('R10: an oversized AGGREGATE is refused before the durable write, and the offline path turns it into a deterministic rejection', async () => {
    const oversizedPayload = {
      incident_id: fx.incidentA1,
      recipient_user_ids: bulkRecipients,
      body: 'b'.repeat(16 * 1024),
      media_refs: Array.from({ length: 60 }, (_, index) => `media-${index}-${'m'.repeat(500)}`),
      retention_class: 'standard',
    };

    const before = {
      messages: await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA } }),
      recipients: await prisma.incidentFieldMessageRecipient.count({ where: { organisationId: fx.orgA } }),
      timeline: await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1 } }),
      outbox: await prisma.incidentFieldMessageOutbox.count({ where: { organisationId: fx.orgA } }),
    };

    // Every INDIVIDUAL bound passes: 120 of 128 recipients, 60 of 64 media
    // refs, a body exactly at the 16 KiB limit. Only the canonical aggregate
    // is too large — the case that used to fail AFTER the rows were committed.
    const principal = alpha();
    const input = messaging.parseSend({
      recipient_user_ids: oversizedPayload.recipient_user_ids,
      body: oversizedPayload.body,
      media_refs: oversizedPayload.media_refs,
      retention_class: oversizedPayload.retention_class,
      idempotency_key: `direct-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    await expect(messaging.send(principal, intersectSiteScope(principal, ACTION_MESSAGE_SEND), fx.incidentA1, input)).rejects.toBeInstanceOf(
      BadRequestException,
    );

    expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA } })).toBe(before.messages);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { organisationId: fx.orgA } })).toBe(before.recipients);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1 } })).toBe(before.timeline);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { organisationId: fx.orgA } })).toBe(before.outbox);

    // The same payload through the offline path is a DETERMINISTIC rejection:
    // it consumes its queue position rather than wedging the queue (C10-07).
    const device = `${tag}_dev_oversized`;
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      payload: oversizedPayload,
    });
    const rejected = expectResult(await service.submit(alpha(), makeContext(fx.opAlpha, device), operation));
    expect(rejected.outcome).toBe('REJECTED');
    expect(rejected.result_snapshot).toEqual({ http_status: 400 });
    expect(rejected.next_expected_sequence).toBe(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);

    expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA } })).toBe(before.messages);
    expect(await prisma.incidentFieldMessageRecipient.count({ where: { organisationId: fx.orgA } })).toBe(before.recipients);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1 } })).toBe(before.timeline);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { organisationId: fx.orgA } })).toBe(before.outbox);
  });

  // --- 17. identity binding ------------------------------------------------

  it('C10-02: a mismatched user, a mismatched organisation and a missing capability are all refused with zero persistence', async () => {
    const device = `${tag}_dev_binding`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    // The principal is opAlpha; the trusted device context names opBravo.
    const userMismatch = expectConflict(await service.submit(alpha(), makeContext(fx.opBravo, device), operation));
    expect(userMismatch.conflict_code).toBe('DEVICE_CONTEXT_MISMATCH');

    // The principal belongs to another organisation than the device context.
    const foreignPrincipal = principalFor(fx.opAlpha, 'field.operative', fx.siteA1, fx.orgGhost);
    const principalOrgMismatch = expectConflict(await service.submit(foreignPrincipal, makeContext(fx.opAlpha, device), operation));
    expect(principalOrgMismatch.conflict_code).toBe('DEVICE_CONTEXT_MISMATCH');

    // The ENVELOPE claims another organisation than the trusted context.
    const envelopeOrgMismatch = expectConflict(
      await service.submit(alpha(), makeContext(fx.opAlpha, device), { ...operation, organisation_id: fx.orgGhost }),
    );
    expect(envelopeOrgMismatch.conflict_code).toBe('DEVICE_CONTEXT_MISMATCH');

    // A dispatcher holds field.assignment.manage but NOT field.assignment.act:
    // replay is never a softer door into a capability than the live route.
    const dispatcherDevice = `${tag}_dev_binding_dispatcher`;
    const notAllowed = expectConflict(
      await service.submit(
        principalFor(fx.dispatcherA1, 'dispatcher'),
        makeContext(fx.dispatcherA1, dispatcherDevice),
        acceptOp(assignmentId, { device_id: dispatcherDevice, device_sequence: 0 }),
      ),
    );
    expect(notAllowed.conflict_code).toBe('OPERATION_NOT_ALLOWED');

    const devices = [device, dispatcherDevice];
    expect(await prisma.fieldOfflineOperationReceipt.count({ where: { organisationId: fx.orgA, deviceId: { in: devices } } })).toBe(0);
    expect(await prisma.fieldOfflineDeviceCursor.count({ where: { organisationId: fx.orgA, deviceId: { in: devices } } })).toBe(0);
    expect(await assignmentStatus(assignmentId)).toBe('REQUESTED');
  });

  // --- 18. operation id reuse ---------------------------------------------

  it('C10-03/R4: one offline_operation_id may occupy exactly one queue position, so reusing it at N+1 mutates nothing', async () => {
    const device = `${tag}_dev_operation_reuse`;
    const context = makeContext(fx.opAlpha, device);
    const applied = await newAssignment(fx.opAlpha);
    const untouched = await newAssignment(fx.opAlpha);

    const first = acceptOp(applied, { device_id: device, device_sequence: 0 });
    expect(expectResult(await service.submit(alpha(), context, first)).outcome).toBe('APPLIED');

    // A brand-new request (fresh idempotency key, next position) wearing the
    // PREVIOUS operation's identity.
    const reused = acceptOp(untouched, { device_id: device, device_sequence: 1, offline_operation_id: first.offline_operation_id });
    const conflict = expectConflict(await service.submit(alpha(), context, reused));

    expect(conflict.conflict_code).toBe('OPERATION_ID_REUSED');
    expect(conflict.expected_sequence).toBe(1);
    expect(conflict.received_sequence).toBe(1);

    expect(await assignmentStatus(untouched)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(untouched)).toBe(0);
    const receipts = await receiptsFor(fx.opAlpha, device);
    expect(receipts).toHaveLength(1);
    expect(Number(receipts[0].deviceSequence)).toBe(0);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);
  });

  // ===========================================================================
  // B10-01 — the claim fence
  //
  // Worker A claims a receipt and stalls (a GC pause, a hung socket, a paused
  // container) until its 60s lease expires. Worker B legally reclaims,
  // finalizes, and moves on. Then A wakes up holding a verdict computed from a
  // world that no longer exists. Every test below is that story, made
  // deterministic: the stall is a TIMESTAMP, never elapsed wall-clock time.
  // ===========================================================================

  // --- 19. B10-01/1 + B10-01/3 ---------------------------------------------

  it('B10-01/1,3: a STALE claimant markUnknown cannot downgrade the APPLIED outcome a newer claim recorded, and emits no audit row', async () => {
    const device = `${tag}_dev_b10_fence_downgrade`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const namespace = namespaceFor(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    // Generation 1 is consumed by a real attempt: the domain effect COMMITS,
    // finalization faults, the receipt records UNKNOWN and the cursor holds.
    expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    const receipt = (await receiptsFor(fx.opAlpha, device))[0];
    expect(receipt.status).toBe('UNKNOWN');
    expect(receipt.attemptCount).toBe(1);
    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');

    // Worker A claims generation 2, then stalls past its lease.
    const generationA = await claimAt(receipt.id, 2);
    await ageLeasePastExpiry(receipt.id);

    // Worker B legally reclaims the abandoned lease and records the truth.
    const generationB = await claimAt(receipt.id, 3);
    const byWorkerB = await repository.finalizeAndAdvance({
      ...fenceIdentity(receipt, namespace, operation.trace_id, generationB),
      outcome: 'APPLIED',
      conflictCode: null,
      resultRef: assignmentId,
      resultSnapshot: { assignment_id: assignmentId, status: 'ACCEPTED' },
    });
    expect(byWorkerB.kind).toBe('finalized');

    const auditsBefore = await finalizedAuditCount(operation.offline_operation_id);
    const unknownAuditsBefore = await offlineAuditCount(operation.offline_operation_id, 'UNKNOWN');
    const cursorBefore = await cursorFor(fx.opAlpha, device);
    expect(Number(cursorBefore?.lastFinalizedSequence)).toBe(0);

    // Worker A wakes up and reports the infrastructure fault it saw. Unfenced,
    // this would downgrade a FINALIZED APPLIED back to UNKNOWN — re-opening a
    // queue position whose effect has already committed, and inviting a third
    // attempt to fire it a second time.
    const lost = await repository.markUnknown(fenceIdentity(receipt, namespace, operation.trace_id, generationA));
    expect(lost.kind).toBe('lost');

    const after = await prisma.fieldOfflineOperationReceipt.findUniqueOrThrow({ where: { id: receipt.id } });
    expect(after.status).toBe('APPLIED');
    expect(after.outcome).toBe('APPLIED');
    expect(after.finalizedAt).not.toBeNull();
    expect(after.resultRef).toBe(assignmentId);

    // B10-01/3: the lost call mutated NOTHING — no false audit row, no cursor
    // movement, not even a cursor row touch.
    expect(await finalizedAuditCount(operation.offline_operation_id)).toBe(auditsBefore);
    expect(await offlineAuditCount(operation.offline_operation_id, 'UNKNOWN')).toBe(unknownAuditsBefore);
    const cursorAfter = await cursorFor(fx.opAlpha, device);
    expect(Number(cursorAfter?.lastFinalizedSequence)).toBe(0);
    expect(cursorAfter?.updatedAt.toISOString()).toBe(cursorBefore?.updatedAt.toISOString());

    // Still exactly one domain effect across the whole story.
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await assignmentAuditCount(assignmentId)).toBe(1);
  });

  // --- 20. B10-01/2 + B10-01/3 ---------------------------------------------

  it('B10-01/2,3: a STALE claimant finalize cannot rewrite the newer REJECTED outcome, advance the cursor again, or emit a false APPLIED audit row', async () => {
    const device = `${tag}_dev_b10_fence_rewrite`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const namespace = namespaceFor(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    const receipt = (await receiptsFor(fx.opAlpha, device))[0];
    expect(receipt.status).toBe('UNKNOWN');

    const generationA = await claimAt(receipt.id, 2);
    await ageLeasePastExpiry(receipt.id);
    const generationB = await claimAt(receipt.id, 3);

    // This time the attempt that legally owns the receipt records a
    // DETERMINISTIC rejection, which consumes the queue position (C10-07).
    const byWorkerB = await repository.finalizeAndAdvance({
      ...fenceIdentity(receipt, namespace, operation.trace_id, generationB),
      outcome: 'REJECTED',
      conflictCode: 'DOMAIN_REJECTED',
      resultRef: null,
      resultSnapshot: { http_status: 409 },
    });
    expect(byWorkerB.kind).toBe('finalized');

    const auditsBefore = await finalizedAuditCount(operation.offline_operation_id);
    const cursorBefore = await cursorFor(fx.opAlpha, device);
    // C10-07: exactly one advance, performed by the attempt that owned the receipt.
    expect(Number(cursorBefore?.lastFinalizedSequence)).toBe(0);

    // Worker A wakes up believing it applied. Unfenced, an `update by id` here
    // would put a stale APPLIED on top of a real REJECTED.
    const lost = await repository.finalizeAndAdvance({
      ...fenceIdentity(receipt, namespace, operation.trace_id, generationA),
      outcome: 'APPLIED',
      conflictCode: null,
      resultRef: assignmentId,
      resultSnapshot: { assignment_id: assignmentId, status: 'ACCEPTED' },
    });
    expect(lost.kind).toBe('lost');

    const after = await prisma.fieldOfflineOperationReceipt.findUniqueOrThrow({ where: { id: receipt.id } });
    expect(after.status).toBe('REJECTED');
    expect(after.outcome).toBe('REJECTED');
    expect(after.resultRef).toBeNull();
    expect(after.resultSnapshot).toEqual({ http_status: 409 });

    // B10-01/3: no false APPLIED audit row, and the cursor did not move again.
    expect(await finalizedAuditCount(operation.offline_operation_id)).toBe(auditsBefore);
    expect(await offlineAuditCount(operation.offline_operation_id, 'APPLIED')).toBe(0);
    const cursorAfter = await cursorFor(fx.opAlpha, device);
    expect(Number(cursorAfter?.lastFinalizedSequence)).toBe(0);
    expect(cursorAfter?.updatedAt.toISOString()).toBe(cursorBefore?.updatedAt.toISOString());
  });

  // --- 21. B10-01/4 ---------------------------------------------------------

  it('B10-01/4: a submission that LOSES its claim fence reports the winning attempt stored outcome, never its own stale verdict', async () => {
    const device = `${tag}_dev_b10_fence_reread`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    const receipt = (await receiptsFor(fx.opAlpha, device))[0];
    expect(receipt.status).toBe('UNKNOWN');

    // The retry claims generation 2 and reaches finalization — and at exactly
    // that instant a rival worker steals the (now aged) lease and finalizes
    // first. Injecting the steal INSIDE the finalize call is what makes the
    // interleaving deterministic instead of a sleep-and-hope race.
    const realFinalize = repository.finalizeAndAdvance.bind(repository);
    vi.spyOn(repository, 'finalizeAndAdvance').mockImplementationOnce(async (input) => {
      await ageLeasePastExpiry(input.receiptId);
      const rivalGeneration = await claimAt(input.receiptId, 3);
      const byRival = await realFinalize({ ...input, claimGeneration: rivalGeneration });
      expect(byRival.kind).toBe('finalized');
      // Now the caller's own write lands, carrying the superseded generation 2.
      return realFinalize(input);
    });

    const answered = expectResult(await service.submit(alpha(), context, operation));

    // The loser reports the WINNER's truth, down the ordinary replay path.
    expect(answered.outcome).toBe('APPLIED');
    expect(answered.replayed).toBe(true);
    expect(answered.result_ref).toBe(assignmentId);
    expect(answered.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });
    expect(answered.next_expected_sequence).toBe(1);

    const stored = await prisma.fieldOfflineOperationReceipt.findUniqueOrThrow({ where: { id: receipt.id } });
    expect(stored.status).toBe('APPLIED');
    expect(stored.attemptCount).toBe(3);
    expect(answered.finalized_at).toBe(stored.finalizedAt?.toISOString());

    // Exactly one finalization was recorded, by the attempt that owned the
    // receipt, and exactly one domain effect exists across all three attempts.
    expect(await offlineAuditCount(operation.offline_operation_id, 'APPLIED')).toBe(1);
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await assignmentAuditCount(assignmentId)).toBe(1);
    expect(await assignmentOutboxCount(assignmentId)).toBe(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);

    // And an ordinary reconnect afterwards converges on the same stored answer.
    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toBe('APPLIED');
    expect(replay.finalized_at).toBe(answered.finalized_at);
    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
  });

  // ===========================================================================
  // B10-02 — truthful recovery when the world has drifted
  //
  // The effect committed, the offline finalization faulted, and by the time the
  // device reconnects the CURRENT eligibility the domain re-checks no longer
  // holds. Re-running the domain call cannot answer "did it happen?" honestly;
  // the evidence row written in the effect's own transaction can.
  // ===========================================================================

  // --- 22. B10-02/5 ---------------------------------------------------------

  it('B10-02/5: a message send recovers APPLIED from the committed message even after the recipient has stopped being eligible', async () => {
    const device = `${tag}_dev_b10_drift_send`;
    const context = makeContext(fx.opAlpha, device);
    const recipientAssignment = await newAssignment(fx.opCharlie, 'ACCEPTED');
    const body = `wp20-drift-${randomUUID()}`;
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      payload: { incident_id: fx.incidentA1, recipient_user_ids: [fx.opCharlie], body, retention_class: 'standard' },
    });

    try {
      expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');

      const receipt = (await receiptsFor(fx.opAlpha, device))[0];
      expect(receipt.status).toBe('UNKNOWN');
      // The message DID commit — that is exactly why the outcome is unknown.
      const committed = await prisma.incidentFieldMessage.findFirstOrThrow({
        where: { organisationId: fx.orgA, senderUserId: fx.opAlpha, idempotencyKey: receipt.downstreamIdempotencyKey },
        select: { id: true },
      });
      expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: committed.id } })).toBe(1);
      expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();

      // THE WORLD CHANGES. The recipient's involvement in the incident ends, so
      // WP-18/C8-03 eligibility no longer holds for them.
      await prisma.fieldAssignment.update({ where: { id: recipientAssignment }, data: { status: 'COMPLETED', completedAt: new Date() } });

      // Proof the drift is real: an identical FRESH send is now a 400. A retry
      // that re-ran the domain would finalize REJECTED for a message that
      // already exists — false history, written into a receipt the device
      // replays as final.
      const principal = alpha();
      const freshInput = messaging.parseSend({
        recipient_user_ids: [fx.opCharlie],
        body,
        media_refs: [],
        retention_class: 'standard',
        idempotency_key: `drift-probe-${randomUUID()}`,
        trace_id: `trace-${randomUUID()}`,
      });
      await expect(messaging.send(principal, intersectSiteScope(principal, ACTION_MESSAGE_SEND), fx.incidentA1, freshInput)).rejects.toBeInstanceOf(
        BadRequestException,
      );

      // The retry asks the OWNING domain for evidence instead, and recovers.
      const recovered = expectResult(await service.submit(alpha(), context, operation));
      expect(recovered.outcome).toBe('APPLIED');
      expect(recovered.result_ref).toBe(committed.id);
      // R6 allowlist, rebuilt from the EVIDENCE row: identifiers and a count.
      expect(recovered.result_snapshot).toEqual({ incident_field_message_id: committed.id, incident_id: fx.incidentA1, recipient_count: 1 });
      expect(recovered.next_expected_sequence).toBe(1);

      // The recovery READ evidence; it created nothing.
      expect(await prisma.incidentFieldMessage.count({ where: { organisationId: fx.orgA, senderUserId: fx.opAlpha, traceId: operation.trace_id } })).toBe(1);
      expect(await prisma.incidentFieldMessageRecipient.count({ where: { messageId: committed.id } })).toBe(1);
      expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);

      const finalizedReceipt = (await receiptsFor(fx.opAlpha, device))[0];
      expect(finalizedReceipt.status).toBe('APPLIED');
      expect(finalizedReceipt.attemptCount).toBe(2);
      const snapshotJson = jsonWithBigInt(finalizedReceipt.resultSnapshot);
      expect(snapshotJson).toContain('recipient_count');
      expect(snapshotJson).not.toContain(body);
      expect(snapshotJson).not.toContain(fx.opCharlie);
    } finally {
      await prisma.fieldAssignment.update({ where: { id: recipientAssignment }, data: { status: 'ACCEPTED', completedAt: null } });
    }
  });

  // --- 23. B10-02/6 ---------------------------------------------------------

  it('B10-02/6: an assignment accept recovers the ORIGINAL intended status from evidence, not the status the assignment has since drifted to', async () => {
    const device = `${tag}_dev_b10_drift_assignment`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');
    expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();

    // THE WORLD CHANGES: the operative gets on with the job before the
    // reconnect lands, so the assignment has moved past the queued transition.
    await prisma.fieldAssignment.update({ where: { id: assignmentId }, data: { status: 'IN_PROGRESS', startedAt: new Date() } });

    const recovered = expectResult(await service.submit(alpha(), context, operation));
    expect(recovered.outcome).toBe('APPLIED');
    expect(recovered.result_ref).toBe(assignmentId);
    // WP-16's own ACTION_TARGETS for the recovered action — NOT the live
    // status. The evidence proves this action by this actor under this key
    // landed; what it landed was ACCEPTED. Reading live state instead would
    // write a value the recovered attempt never produced into a receipt the
    // device replays as final.
    expect(recovered.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });
    expect(recovered.next_expected_sequence).toBe(1);

    // The recovery did not touch the domain object it recovered.
    expect(await assignmentStatus(assignmentId)).toBe('IN_PROGRESS');
    expect(await prisma.fieldAuditLog.count({ where: { assignmentId, kind: 'FIELD_ASSIGNMENT_ACCEPTED' } })).toBe(1);
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(1);
    expect(await assignmentOutboxCount(assignmentId)).toBe(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);
  });

  // --- 24. B10-02/7 ---------------------------------------------------------

  it('B10-02/7: an acknowledgement recovers APPLIED without restamping acknowledged_at or appending a second timeline entry', async () => {
    const device = `${tag}_dev_b10_drift_ack`;
    const context = makeContext(fx.opAlpha, device);
    const messageId = await newDeliveredMessage(fx.opAlpha);
    const operation = makeOperation({
      device_id: device,
      device_sequence: 0,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
      payload: { message_id: messageId },
    });

    const timelineWhere = {
      incidentId: fx.incidentA1,
      kind: TIMELINE_MESSAGE_ACKNOWLEDGED,
      payload: { path: ['incident_field_message_id'], equals: messageId },
    };

    expect(expectConflict(await submitWithFaultedFinalize(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');

    // The acknowledgement COMMITTED. Its own effect is the drift: the C8-01
    // precondition the domain re-checks is DELIVERED, and the row is no longer
    // in that state.
    const before = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.opAlpha } });
    expect(before.deliveryState).toBe('ACKNOWLEDGED');
    expect(before.acknowledgedAt).not.toBeNull();
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere })).toBe(1);
    expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();

    const recovered = expectResult(await service.submit(alpha(), context, operation));
    expect(recovered.outcome).toBe('APPLIED');
    expect(recovered.result_ref).toBe(messageId);
    expect(recovered.result_snapshot).toEqual({ incident_field_message_id: messageId });
    expect(recovered.next_expected_sequence).toBe(1);

    // C10-06: the recovery cannot manufacture a second, later acknowledgement.
    const after = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.opAlpha } });
    expect(after.acknowledgedAt?.toISOString()).toBe(before.acknowledgedAt?.toISOString());
    expect(after.deliveryState).toBe('ACKNOWLEDGED');
    expect(await prisma.incidentTimelineEntry.count({ where: timelineWhere })).toBe(1);
    expect(await prisma.incidentFieldMessageActionIdempotency.count({ where: { messageId, action: 'acknowledge' } })).toBe(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);
  });

  // --- 25. B10-02/8 ---------------------------------------------------------

  it('B10-02/8: with NO committed evidence, a retry the domain deterministically refuses finalizes REJECTED and consumes its queue position', async () => {
    const device = `${tag}_dev_b10_no_evidence`;
    const assignmentId = await newAssignment(fx.opAlpha);
    const context = makeContext(fx.opAlpha, device);
    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: 0 });

    // The FIRST attempt dies INSIDE the domain call, before any effect: an
    // infrastructure fault, so the outcome is unknown and nothing committed.
    const infrastructure = vi.spyOn(field, 'transitionAssignment').mockRejectedValueOnce(new Error('simulated infrastructure fault'));
    expect(expectConflict(await service.submit(alpha(), context, operation)).conflict_code).toBe('UNKNOWN_OUTCOME');
    infrastructure.mockRestore();

    expect((await receiptsFor(fx.opAlpha, device))[0].status).toBe('UNKNOWN');
    expect(await assignmentStatus(assignmentId)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(0);
    expect((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence).toBeNull();

    // The world moves while the device is away: the assignment is cancelled, so
    // the queued accept can never apply.
    await prisma.fieldAssignment.update({ where: { id: assignmentId }, data: { status: 'CANCELLED', cancelledAt: new Date() } });

    // Generation 2 probes for evidence, finds NONE — and absence is proof,
    // because every evidence row is written in the same transaction as the
    // effect it records. So the deterministic 4xx is the real, first-and-only
    // answer rather than a re-evaluation contradicting a forgotten commit.
    const rejected = expectResult(await service.submit(alpha(), context, operation));
    expect(rejected.outcome).toBe('REJECTED');
    expect(rejected.replayed).toBe(false);
    expect(rejected.result_snapshot).toEqual({ http_status: 409 });
    expect(rejected.result_ref).toBeNull();
    expect(rejected.next_expected_sequence).toBe(1);
    // C10-07: a rejection consumes its position rather than wedging the queue.
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(0);

    // NO domain effect ever existed — which is exactly what makes REJECTED truthful.
    expect(await assignmentIdempotencyCount(assignmentId)).toBe(0);
    expect(await assignmentAuditCount(assignmentId)).toBe(0);
    expect(await assignmentOutboxCount(assignmentId)).toBe(0);
    expect(await assignmentStatus(assignmentId)).toBe('CANCELLED');
    expect(await offlineAuditCount(operation.offline_operation_id, 'REJECTED')).toBe(1);
  });

  // ===========================================================================
  // B10-03 — an exhausted sequence namespace
  // ===========================================================================

  // --- 26. B10-03/9 ---------------------------------------------------------

  it('B10-03/9: a namespace finalized at MAX reports NO next sequence, still replays its stored outcome, and admits nothing new', async () => {
    const device = `${tag}_dev_b10_exhaustion`;
    const context = makeContext(fx.opAlpha, device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const untouched = await newAssignment(fx.opAlpha);

    // One position short of the end of the namespace.
    await prisma.fieldOfflineDeviceCursor.create({
      data: {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        userId: fx.opAlpha,
        deviceId: device,
        lastFinalizedSequence: BigInt(MAX_OFFLINE_DEVICE_SEQUENCE) - 1n,
      },
    });

    const operation = acceptOp(assignmentId, { device_id: device, device_sequence: MAX_OFFLINE_DEVICE_SEQUENCE });
    const applied = expectResult(await service.submit(alpha(), context, operation));
    expect(applied.outcome).toBe('APPLIED');
    expect(applied.replayed).toBe(false);
    // `last + 1` would leave the safe-integer range, so the honest answer is
    // "there is no next sequence" — never a silently wrapped or rounded one.
    expect(applied.next_expected_sequence).toBeNull();
    expect(await assignmentStatus(assignmentId)).toBe('ACCEPTED');
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(MAX_OFFLINE_DEVICE_SEQUENCE);

    // An exhausted device can still read back what it already did.
    const replay = expectResult(await service.submit(alpha(), context, operation));
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toBe('APPLIED');
    expect(replay.next_expected_sequence).toBeNull();
    expect(replay.finalized_at).toBe(applied.finalized_at);
    expect(replay.result_snapshot).toEqual({ assignment_id: assignmentId, status: 'ACCEPTED' });

    // A CHANGED request at the consumed MAX position is still reuse: exhaustion
    // does not soften C10-04, and there is deliberately no cursor reset.
    const changed: OperationDraft = { ...operation, payload: { assignment_id: untouched, expected_status: 'REQUESTED' } };
    const conflict = expectConflict(await service.submit(alpha(), context, changed));
    expect(conflict.conflict_code).toBe('SEQUENCE_REUSED');
    expect(conflict.expected_sequence).toBeNull();
    expect(await assignmentStatus(untouched)).toBe('REQUESTED');
    expect(await assignmentIdempotencyCount(untouched)).toBe(0);

    // And nothing can follow MAX: the contract itself refuses the position, so
    // an exhausted namespace cannot be extended by a client that ignores the
    // null. Refused at parse time — no receipt, no cursor movement.
    const beyond = acceptOp(untouched, { device_id: device, device_sequence: MAX_OFFLINE_DEVICE_SEQUENCE + 1 });
    expect(expectInvalid(await service.submit(alpha(), context, beyond)).length).toBeGreaterThan(0);

    expect(await receiptsFor(fx.opAlpha, device)).toHaveLength(1);
    expect(Number((await cursorFor(fx.opAlpha, device))?.lastFinalizedSequence)).toBe(MAX_OFFLINE_DEVICE_SEQUENCE);
  });
});
