import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { AuthenticatedFieldDeviceContext, OfflineOperationResult } from '@sentinel/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { PrismaService } from '../../prisma/prisma.service';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { FieldOfflineReplayService } from './field-offline.service';
import type { OfflineSubmissionOutcome } from './field-offline.types';

/**
 * WP-29A / D29A-26 §24 — THE RECEIPT REMEMBERS WHICH AUTHORITY IT ACTED UNDER.
 *
 * The lease decides whether a queued operation may take effect. This suite is
 * about what happens AFTERWARDS: once the effect exists, can Sentinel still say
 * what authorised it? That is the question §25's audit list is made of, and a
 * lease that influenced an admission and then vanished from the durable record
 * would answer none of it.
 *
 * WHY THIS SUITE CALLS THE REPLAY SERVICE DIRECTLY.
 *
 * The full path — a StrongBox-signed envelope through the WP-25 gateway — is
 * exercised by the device-gateway acceptance suite, which owns the enrollment,
 * context and signing fixtures. What is being proven HERE is narrower and
 * belongs at this level: that the provenance argument reaches the receipt
 * intact, survives a retry, is not replaced by a later submission, and outlives
 * the lease's own revocation. Building a second signing harness to assert a
 * column would test the harness.
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

const tag = `wp29a_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteB1: `${tag}_siteB1`,
  opAlpha: `${tag}_opAlpha`,
  dispatcherA1: `${tag}_dispatcherA1`,
  opB: `${tag}_opB`,
  incidentA1: randomUUID(),
  /**
   * UUIDs, not tagged strings. `devices.id` is `@db.Uuid` and the lease holds a
   * composite Restrict relation to it, so a readable-but-invalid id would fail
   * as a driver cast error rather than as the thing under test.
   */
  deviceA: randomUUID(),
  deviceB: randomUUID(),
};

describe('WP-29A/D29A-26 §24 receipt lease provenance (live stack)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let service: FieldOfflineReplayService;
  let restoreEnv: Array<[string, string | undefined]> = [];

  beforeAll(async () => {
    restoreEnv = Object.entries(STACK_ENV).map(([key]) => [key, process.env[key]]);
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PATROL_SWEEP_SCHEDULER)
      .useClass(NoopPatrolSweepScheduler)
      .compile();
    app = moduleRef.createNestApplication();
    await app.init();
    prisma = app.get(PrismaService);
    service = app.get(FieldOfflineReplayService);
    await seed(prisma);
  }, 120_000);

  afterAll(async () => {
    if (prisma !== undefined) await cleanup(prisma);
    if (app !== undefined) await app.close();
    for (const [key, value] of restoreEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }, 60_000);

  // -------------------------------------------------------------------------

  async function seed(db: PrismaService): Promise<void> {
    await db.organisation.createMany({
      data: [
        { id: fx.orgA, name: 'WP-29A Org A' },
        { id: fx.orgB, name: 'WP-29A Org B' },
      ],
    });
    await db.site.createMany({
      data: [
        { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
        { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
      ],
    });
    const users = [
      { id: fx.opAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
      { id: fx.dispatcherA1, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
      { id: fx.opB, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
    ];
    await db.user.createMany({
      data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
    });
    await db.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });

    const hypothesisId = randomUUID();
    await db.incident.create({
      data: {
        id: fx.incidentA1,
        hypothesisId,
        incidentCandidateId: randomUUID(),
        sourceKind: 'FUSION_HYPOTHESIS',
        sourceRef: hypothesisId,
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        incidentType: 'wp29a.test',
        severity: 'SEV3',
        threatState: 2,
        confidence: 0.9,
        responseMode: 'STANDARD',
      },
    });
    await db.fieldAssignment.create({
      data: {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        incidentId: fx.incidentA1,
        assigneeUserId: fx.opAlpha,
        assignmentType: 'INCIDENT_RESPONSE',
        priority: 'SEV3',
        status: 'ACCEPTED',
        deliveryState: 'REQUESTED',
        needToKnowSummary: 'wp29a eligibility fixture',
        idempotencyKey: `${tag}-eligibility`,
        createdByUserId: fx.dispatcherA1,
        updatedByUserId: fx.dispatcherA1,
      },
    });

    /**
     * Devices, because a lease holds a tenant-composite Restrict relation to
     * one -- and a device in turn requires the enrolment record it came from.
     *
     * The grant -> request -> device chain is seeded DIRECTLY rather than by
     * running the real ceremony. The ceremony is proven at length in the
     * enrolment and gateway acceptance suites; re-running it here would make
     * this suite depend on attestation trust material it has no use for, and a
     * receipt-provenance test that fails because a challenge expired tells
     * nobody anything about receipt provenance.
     *
     * The chain is seeded HONESTLY, though: every foreign key is real, so the
     * `Restrict` relation under test is exercised against genuine rows.
     */
    for (const [deviceId, org, site, user] of [
      [fx.deviceA, fx.orgA, fx.siteA1, fx.opAlpha],
      [fx.deviceB, fx.orgB, fx.siteB1, fx.opB],
    ] as const) {
      const grantId = randomUUID();
      const requestId = randomUUID();
      await db.enrollmentBootstrapGrant.create({
        data: {
          id: grantId,
          organisationId: org,
          siteId: site,
          intendedUserId: user,
          issuedByUserId: user,
          // A DIGEST of a token that never existed. No bootstrap token is
          // created, stored or logged by this fixture -- the column holds a
          // digest by design, and a fixture has no reason to hold the preimage.
          tokenDigest: `${'0'.repeat(64)}`,
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
      await db.enrollmentRequest.create({
        data: {
          id: requestId,
          organisationId: org,
          siteId: site,
          intendedUserId: user,
          bootstrapGrantId: grantId,
          custody: 'PERSONAL',
          publicKey: 'seeded-public-key',
          publicKeyThumbprint: `${'1'.repeat(64)}`,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: 'P256_ECDSA_SHA256',
          serverSelectedSignatureProfile: 'P256_ECDSA_SHA256',
          requestFingerprint: `${'2'.repeat(64)}`,
          approvedSemanticsDigest: `${'3'.repeat(64)}`,
          attestationOutcome: 'UNAVAILABLE',
          attestationEvaluatedAt: new Date(),
          requestedAt: new Date(),
          state: 'ENROLLED',
        },
      });
      await db.device.create({
        data: {
          id: deviceId,
          organisationId: org,
          custody: 'PERSONAL',
          sequenceNamespaceId: `${deviceId}-ns`,
          trust: 'TRUSTED',
          enrolledByUserId: user,
          intendedUserId: user,
          enrollmentRequestId: requestId,
          enrolledAt: new Date(),
        },
      });
      // A device is entitled to a site through its scope row, not through a
      // column on the device — WP-24/D24-04a. The lease's site relation is to
      // `sites`, and this is what makes the pairing a real one.
      await db.deviceSiteScope.create({
        data: {
          organisationId: org,
          deviceId,
          siteId: site,
          assignedUserId: user,
          custody: 'PERSONAL',
          associatedAt: new Date(),
        },
      });
    }
  }

  async function cleanup(db: PrismaService): Promise<void> {
    const orgs = [fx.orgA, fx.orgB];
    await db.fieldOfflineOperationReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.fieldOfflineDeviceCursor.deleteMany({ where: { organisationId: { in: orgs } } });
    // Leases AFTER receipts: the receipt holds a Restrict relation to the lease,
    // which is the point of the relation and is asserted below.
    await db.devicePolicyLease.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.deviceSiteScope.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.device.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.enrollmentRequest.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.enrollmentBootstrapGrant.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.fieldAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.incidentFieldMessage.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.incident.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
    await db.user.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.site.deleteMany({ where: { organisationId: { in: orgs } } });
    await db.organisation.deleteMany({ where: { id: { in: orgs } } });
  }

  let seq = 0;

  async function newLease(overrides: { organisationId?: string; deviceId?: string; siteId?: string; actorUserId?: string } = {}) {
    const issuedAt = new Date();
    const row = await prisma.devicePolicyLease.create({
      data: {
        id: `${tag}-lease-${seq++}`,
        organisationId: overrides.organisationId ?? fx.orgA,
        deviceId: overrides.deviceId ?? fx.deviceA,
        siteId: overrides.siteId ?? fx.siteA1,
        actorUserId: overrides.actorUserId ?? fx.opAlpha,
        authorityBasisId: `${tag}-basis`,
        scope: ['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'],
        issuedAt,
        expiresAt: new Date(issuedAt.getTime() + 21_600_000),
      },
    });
    return row.id;
  }

  async function newDeliveredMessage(): Promise<string> {
    const row = await prisma.incidentFieldMessage.create({
      data: {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        incidentId: fx.incidentA1,
        senderUserId: fx.dispatcherA1,
        body: 'wp29a seeded message',
        mediaRefs: [],
        retentionClass: 'standard',
        idempotencyKey: `${tag}-message-${seq++}`,
        traceId: `${tag}-seed`,
        recipients: {
          create: [
            {
              organisationId: fx.orgA,
              siteId: fx.siteA1,
              recipientUserId: fx.opAlpha,
              deliveryState: 'DELIVERED',
              deliveredAt: new Date(),
            },
          ],
        },
      },
      select: { id: true },
    });
    return row.id;
  }

  const alpha = (): Principal =>
    buildPrincipal({ user: { id: fx.opAlpha, clearance: 5 }, organisation_id: fx.orgA, roles: [{ role: 'field.operative', site_id: fx.siteA1 }] });

  const context = (deviceId: string): AuthenticatedFieldDeviceContext => ({
    organisationId: fx.orgA,
    userId: fx.opAlpha,
    deviceId,
    authorisedSiteIds: [fx.siteA1],
  });

  function ackOperation(deviceId: string, messageId: string, sequence: number) {
    return {
      schema_version: 2 as const,
      offline_operation_id: randomUUID(),
      organisation_id: fx.orgA,
      site_id: fx.siteA1,
      device_id: deviceId,
      device_sequence: sequence,
      idempotency_key: `client-idem-${randomUUID()}`,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' as const,
      payload: { message_id: messageId },
      created_at: new Date().toISOString(),
      trace_id: `trace-${randomUUID()}`,
    };
  }

  function expectResult(outcome: OfflineSubmissionOutcome): OfflineOperationResult {
    expect(outcome.kind, JSON.stringify(outcome)).toBe('result');
    if (outcome.kind !== 'result') throw new Error('unreachable');
    return outcome.result;
  }

  async function receiptFor(deviceId: string, offlineOperationId: string) {
    return prisma.fieldOfflineOperationReceipt.findFirstOrThrow({
      where: { organisationId: fx.orgA, deviceId, offlineOperationId },
      select: { id: true, policyLeaseId: true, status: true, outcome: true, deviceSequence: true },
    });
  }

  // -------------------------------------------------------------------------

  it('an envelope-backed submission persists the EXACT lease it acted under', async () => {
    const device = `${tag}_dev_provenance`;
    const leaseId = await newLease();
    const operation = ackOperation(device, await newDeliveredMessage(), 0);

    const result = expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: leaseId }));
    expect(result.outcome).toBe('APPLIED');

    const receipt = await receiptFor(device, operation.offline_operation_id);
    expect(receipt.policyLeaseId).toBe(leaseId);
  });

  it('a retry converges on the SAME receipt and keeps its original lease', async () => {
    const device = `${tag}_dev_retry`;
    const leaseId = await newLease();
    const operation = ackOperation(device, await newDeliveredMessage(), 0);

    expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: leaseId }));
    const first = await receiptFor(device, operation.offline_operation_id);

    // Byte-identical resend — the normal case for a reconnecting queue.
    const replayed = expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: leaseId }));
    expect(replayed.outcome).toBe('APPLIED');

    const second = await receiptFor(device, operation.offline_operation_id);
    expect(second.id).toBe(first.id);
    expect(second.policyLeaseId).toBe(leaseId);
    const all = await prisma.fieldOfflineOperationReceipt.count({
      where: { organisationId: fx.orgA, deviceId: device, offlineOperationId: operation.offline_operation_id },
    });
    expect(all).toBe(1);
  });

  it('a resend naming a DIFFERENT lease does not replace the recorded one', async () => {
    // D29A-26 §24. The lease is written once, with the receipt, in the same
    // statement that makes the request fingerprint durable. A later submission
    // of the same operation converges on that receipt — so the authority
    // recorded is the authority the operation FIRST claimed, and a device
    // cannot rewrite its own provenance by re-sending under a newer lease.
    const device = `${tag}_dev_release`;
    const firstLease = await newLease();
    const secondLease = await newLease();
    expect(secondLease).not.toBe(firstLease);

    const operation = ackOperation(device, await newDeliveredMessage(), 0);
    expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: firstLease }));
    expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: secondLease }));

    const receipt = await receiptFor(device, operation.offline_operation_id);
    expect(receipt.policyLeaseId).toBe(firstLease);
  });

  it('a caller with no lease still submits, and its receipt is honestly marked as the legacy era', async () => {
    // D29A-26 §20/§21: the column is nullable so that pre-WP-29A operations
    // remain valid records rather than being back-filled with authority that
    // never existed. NULL means "before the mechanism", not "unknown quality".
    const device = `${tag}_dev_legacy`;
    const operation = ackOperation(device, await newDeliveredMessage(), 0);

    const result = expectResult(await service.submit(alpha(), context(device), operation));
    expect(result.outcome).toBe('APPLIED');

    const receipt = await receiptFor(device, operation.offline_operation_id);
    expect(receipt.policyLeaseId).toBeNull();
  });

  it('a revoked lease still resolves from its historical receipt', async () => {
    // §10 and §25 together: revocation is a state, and the receipt must still
    // be able to answer "what authority did this act under?" afterwards. If
    // revocation deleted the row, or the relation cascaded, this join would
    // come back empty and the audit question would be unanswerable.
    const device = `${tag}_dev_revoked`;
    const leaseId = await newLease();
    const operation = ackOperation(device, await newDeliveredMessage(), 0);
    expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: leaseId }));

    await prisma.devicePolicyLease.update({ where: { id: leaseId }, data: { revokedAt: new Date() } });

    const receipt = await prisma.fieldOfflineOperationReceipt.findFirstOrThrow({
      where: { organisationId: fx.orgA, deviceId: device, offlineOperationId: operation.offline_operation_id },
      select: { policyLeaseId: true, policyLease: { select: { id: true, revokedAt: true, scope: true, authorityBasisId: true } } },
    });
    expect(receipt.policyLeaseId).toBe(leaseId);
    expect(receipt.policyLease?.id).toBe(leaseId);
    expect(receipt.policyLease?.revokedAt).not.toBeNull();
    // The whole audit answer, still readable: what it authorised and why.
    expect(receipt.policyLease?.scope).toEqual(['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE']);
    expect(receipt.policyLease?.authorityBasisId).toBe(`${tag}-basis`);
  });

  it('the database REFUSES to delete a lease any receipt cites', async () => {
    // §17/§26. `Restrict`, not cascade: losing the lease would destroy the
    // provenance of every operation that already acted under it, and expiry and
    // revocation are states rather than reasons to erase the record.
    const device = `${tag}_dev_restrict`;
    const leaseId = await newLease();
    const operation = ackOperation(device, await newDeliveredMessage(), 0);
    expectResult(await service.submit(alpha(), context(device), operation, { policyLeaseId: leaseId }));

    await expect(prisma.devicePolicyLease.delete({ where: { id: leaseId } })).rejects.toThrow();
    await expect(prisma.devicePolicyLease.findUniqueOrThrow({ where: { id: leaseId } })).resolves.toBeTruthy();
  });

  it('the database REFUSES a receipt that names another tenant lease', async () => {
    // §4/§17: the tenant-composite relation makes an organisation-A receipt
    // naming an organisation-B lease impossible in the DATABASE, not merely
    // unlikely in the service. This is the row D24-04a names first.
    const foreignLease = await newLease({ organisationId: fx.orgB, deviceId: fx.deviceB, siteId: fx.siteB1, actorUserId: fx.opB });

    await expect(
      prisma.fieldOfflineOperationReceipt.create({
        data: {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          userId: fx.opAlpha,
          deviceId: `${tag}_dev_crosstenant`,
          deviceSequence: BigInt(0),
          offlineOperationId: randomUUID(),
          operationKind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
          requestFingerprint: 'fingerprint',
          downstreamIdempotencyKey: 'downstream',
          clientCreatedAt: new Date(),
          firstReceivedAt: new Date(),
          firstTraceId: 'trace',
          policyLeaseId: foreignLease,
        },
      }),
    ).rejects.toThrow();
  });
});
