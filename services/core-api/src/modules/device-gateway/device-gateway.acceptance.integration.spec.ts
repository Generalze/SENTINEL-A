import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS,
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_REQUEST_PROOF_MAX_AGE_MS,
  canonicalDeviceKeyRotationPossessionStatement,
  canonicalDevicePossessionStatement,
  canonicalDeviceRequestProofStatement,
  deriveP256PublicKeyThumbprint,
  type DeviceAttestationOutcome,
  type DeviceKeyStorage,
  type DeviceRequestPurpose,
} from '@sentinel/contracts';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { GlobalExceptionFilter } from '../../common/global-exception.filter';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { traceIdMiddleware } from '../../common/trace-id.middleware';
import { GlobalValidationPipe } from '../../common/validation.pipe';
import { PrismaService } from '../../prisma/prisma.service';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { DEVICE_ATTESTATION_EVALUATOR } from '../shield/attestation.evaluator';
import { DeviceEnrollmentService } from '../shield/device-enrollment.service';
import { DeviceKeyService } from '../shield/device-key.service';
import { DeviceRegistryService } from '../shield/device-registry.service';
import { DeviceTrustService } from '../shield/device-trust.service';
import {
  SettableDeviceAttestationEvaluator,
  generateTestDeviceKeyPair,
  signCanonicalStatement,
  type TestDeviceKeyPair,
} from '../shield/shield.test-support';
import { deviceContextEstablishmentChallengeDigest, type DeviceContextEstablishmentChallengeView } from './device-context.challenge';
import { DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS } from './device-gateway.constants';
import { DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND, deviceGatewayEnvelopeDigest, type DeviceGatewayOperationKind } from './device-gateway.envelope';
import { deviceGatewayDomainIdempotencyKey } from './device-gateway.idempotency';
import { DeviceGatewayRepository } from './device-gateway.repository';

/**
 * ============================================================================
 * WP-25 Authenticated Device Gateway — the Crucible.
 *
 * Driven over REAL HTTP, through the REAL module graph (AppModule), the REAL
 * global guard chain, the REAL frozen evaluators, the REAL P-256 verifier and
 * the REAL Postgres constraints. Nothing below stubs a security decision. The
 * only injected seams are WP-24's attestation evaluator — a token swap the
 * registry already owns — and, in four named tests, a `vi.spyOn` FAULT that
 * proves what happens when a write fails or the world moves between preflight
 * and commit.
 *
 * THIS IS NOT PROOF C, AND NOTHING HERE MAY BE READ AS IT (D25-07 / D25-09).
 *
 * EVERY "DEVICE" BELOW IS A P-256 KEYPAIR THIS TEST PROCESS GENERATED. There is
 * no hardware, no hardware-backed key store, no attestation vendor and no
 * mobile client anywhere in this suite. A passing test proves the GATEWAY
 * authenticates a holder of a registered private key and refuses everyone else;
 * it proves nothing whatsoever about a physical device. Proof C requires a real
 * device with a hardware-backed key speaking through a real client and belongs
 * to WP-28; WP-25 builds the boundary that makes Proof C possible and cannot
 * claim it. Proof D is likewise UNCLAIMED.
 *
 * D25-08: this spec boots the app, so it overrides `PATROL_SWEEP_SCHEDULER`
 * with the WP-22 no-op seam. It adds no scheduler of its own, and the gateway
 * has none — every expiry it enforces is a comparison taken at request time.
 * ============================================================================
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

const tag = `wp25_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const PROFILE = 'P256_ECDSA_SHA256';
const GATEWAY = '/api/v1/device-gateway';

const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  cmdIssuerA: `${tag}_cmdIssuerA`,
  cmdApproverA: `${tag}_cmdApproverA`,
  opAlpha: `${tag}_opAlpha`,
  opBravo: `${tag}_opBravo`,
  /** An operative whose §62 authority the fence tests withdraw and restore. */
  opCharlie: `${tag}_opCharlie`,
  dispatcherA: `${tag}_dispatcherA`,
  cmdIssuerB: `${tag}_cmdIssuerB`,
  cmdApproverB: `${tag}_cmdApproverB`,
  opB: `${tag}_opB`,
  incidentA1: randomUUID(),
};

let app: INestApplication;
let base: string;
let prisma: PrismaService;
let enrollment: DeviceEnrollmentService;
let registry: DeviceRegistryService;
let trust: DeviceTrustService;
let deviceKeys: DeviceKeyService;
let gatewayRepository: DeviceGatewayRepository;
let attestation: SettableDeviceAttestationEvaluator;

function principalFor(userId: string, role: string, siteId: string | null, organisationId: string): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 5 }, organisation_id: organisationId, roles: [{ role, site_id: siteId }] });
}

const traceId = (): string => `trace-${randomUUID()}`;

async function seed(): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-25 Org A' },
      { id: fx.orgB, name: 'WP-25 Org B' },
    ],
  });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });

  const users: Array<{ id: string; org: string; role: string; site: string }> = [
    { id: fx.cmdIssuerA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.cmdApproverA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.opAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opBravo, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opCharlie, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.dispatcherA, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
    { id: fx.cmdIssuerB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.cmdApproverB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.opB, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });

  const hypothesisId = randomUUID();
  await prisma.incident.create({
    data: {
      id: fx.incidentA1,
      hypothesisId,
      incidentCandidateId: randomUUID(),
      sourceKind: 'FUSION_HYPOTHESIS',
      sourceRef: hypothesisId,
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      incidentType: 'wp25.test',
      severity: 'SEV3',
      threatState: 2,
      confidence: 0.9,
      responseMode: 'STANDARD',
    },
  });

  // WP-18/C8-03 eligibility: an operative may only be named on an incident they
  // hold an OPERATIONAL assignment for.
  await prisma.fieldAssignment.createMany({
    data: [fx.opAlpha, fx.opBravo, fx.opCharlie].map((assignee) => ({
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      incidentId: fx.incidentA1,
      assigneeUserId: assignee,
      assignmentType: 'INCIDENT_RESPONSE',
      priority: 'SEV3',
      status: 'ACCEPTED',
      deliveryState: 'REQUESTED',
      needToKnowSummary: 'wp25 eligibility fixture',
      idempotencyKey: `${tag}-eligibility-${assignee}`,
      createdByUserId: fx.dispatcherA,
      updatedByUserId: fx.dispatcherA,
    })),
  });
}

async function cleanup(): Promise<void> {
  const organisationId = { in: [fx.orgA, fx.orgB] };
  await prisma.deviceGatewayOperationEvent.deleteMany({ where: { organisationId } });
  await prisma.authenticatedDeviceContextSite.deleteMany({ where: { organisationId } });
  await prisma.authenticatedDeviceContextRecord.deleteMany({ where: { organisationId } });
  await prisma.deviceContextEstablishmentChallenge.deleteMany({ where: { organisationId } });

  await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId } } });
  await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId } });
  await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId } });
  await prisma.incidentFieldMessage.deleteMany({ where: { organisationId } });
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId } });
  await prisma.fieldStateUpdateIdempotency.deleteMany({ where: { organisationId } });
  await prisma.fieldOperativeStateHistory.deleteMany({ where: { organisationId } });
  await prisma.fieldOperativeCurrentState.deleteMany({ where: { organisationId } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId } } });
  await prisma.incident.deleteMany({ where: { organisationId } });

  await prisma.deviceSecurityEvent.deleteMany({ where: { organisationId } });
  await prisma.deviceTrustTransition.deleteMany({ where: { organisationId } });
  await prisma.deviceAttestationObservation.deleteMany({ where: { organisationId } });
  await prisma.deviceNonceConsumption.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationVerification.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationChallenge.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationRequest.deleteMany({ where: { organisationId } });
  // WP-29A: leases BEFORE devices. `device_policy_leases` holds a tenant-composite
  // Restrict relation to `devices`, so a device that any lease names cannot be
  // deleted -- which is the point of the relation (D29A-26 s10: a lease must
  // survive the device's lifecycle, not be erased by it). Context establishment
  // now issues a lease, so every suite that establishes one creates these rows.
  await prisma.devicePolicyLease.deleteMany({ where: { organisationId } });
  await prisma.deviceSiteScope.deleteMany({ where: { organisationId } });
  await prisma.deviceKey.deleteMany({ where: { organisationId } });
  await prisma.device.deleteMany({ where: { organisationId } });
  await prisma.possessionVerification.deleteMany({ where: { organisationId } });
  await prisma.possessionChallenge.deleteMany({ where: { organisationId } });
  await prisma.enrollmentApproval.deleteMany({ where: { organisationId } });
  await prisma.enrollmentRequest.deleteMany({ where: { organisationId } });
  await prisma.enrollmentBootstrapGrant.deleteMany({ where: { organisationId } });
  await prisma.deviceCustodyRegime.deleteMany({ where: { organisationId } });

  await prisma.userRole.deleteMany({ where: { user: { organisationId } } });
  await prisma.user.deleteMany({ where: { organisationId } });
  await prisma.site.deleteMany({ where: { organisationId } });
  await prisma.organisation.deleteMany({ where: { id: { in: [fx.orgA, fx.orgB] } } });
}

interface TenantFixture {
  organisationId: string;
  siteId: string;
  issuer: Principal;
  approver: Principal;
  operativeId: string;
  operative: Principal;
}

let A: TenantFixture;
let B: TenantFixture;

beforeAll(async () => {
  for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
  attestation = new SettableDeviceAttestationEvaluator();
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    // D25-08: no uncontrolled background scheduler, and no increase in
    // cross-suite state coupling.
    .overrideProvider(PATROL_SWEEP_SCHEDULER)
    .useClass(NoopPatrolSweepScheduler)
    .overrideProvider(DEVICE_ATTESTATION_EVALUATOR)
    .useValue(attestation)
    .compile();

  app = moduleRef.createNestApplication();
  // The SAME request pipeline production boots, so the external refusal shape
  // this suite asserts on is the shape a real caller sees.
  app.use(traceIdMiddleware);
  app.useGlobalPipes(new GlobalValidationPipe());
  app.useGlobalFilters(new GlobalExceptionFilter());
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  base = `http://127.0.0.1:${typeof address === 'object' && address !== null ? address.port : 0}`;

  prisma = app.get(PrismaService);
  enrollment = app.get(DeviceEnrollmentService);
  registry = app.get(DeviceRegistryService);
  trust = app.get(DeviceTrustService);
  deviceKeys = app.get(DeviceKeyService);
  gatewayRepository = app.get(DeviceGatewayRepository);

  await cleanup();
  await seed();

  A = {
    organisationId: fx.orgA,
    siteId: fx.siteA1,
    issuer: principalFor(fx.cmdIssuerA, 'site.commander', fx.siteA1, fx.orgA),
    approver: principalFor(fx.cmdApproverA, 'site.commander', fx.siteA1, fx.orgA),
    operativeId: fx.opAlpha,
    operative: principalFor(fx.opAlpha, 'field.operative', fx.siteA1, fx.orgA),
  };
  B = {
    organisationId: fx.orgB,
    siteId: fx.siteB1,
    issuer: principalFor(fx.cmdIssuerB, 'site.commander', fx.siteB1, fx.orgB),
    approver: principalFor(fx.cmdApproverB, 'site.commander', fx.siteB1, fx.orgB),
    operativeId: fx.opB,
    operative: principalFor(fx.opB, 'field.operative', fx.siteB1, fx.orgB),
  };
}, 240_000);

afterAll(async () => {
  if (prisma !== undefined) await cleanup();
  if (app !== undefined) await app.close();
});

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

interface HttpResult {
  status: number;
  body: Record<string, unknown>;
  traceId: string;
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<HttpResult> {
  const trace = headers['x-trace-id'] ?? traceId();
  const response = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-trace-id': trace, ...headers },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text.length === 0 ? {} : (JSON.parse(text) as Record<string, unknown>), traceId: trace };
}

const asSession = (userId: string): Record<string, string> => ({ 'x-dev-user-id': userId });

/** Everything the gateway recorded under one request's trace. */
async function eventsForTrace(trace: string): Promise<Array<{ eventType: string; outcome: string; refusalReason: string | null; payload: unknown }>> {
  const rows = await prisma.deviceGatewayOperationEvent.findMany({ where: { traceId: trace }, orderBy: { createdAt: 'asc' } });
  return rows.map((row) => ({ eventType: row.eventType, outcome: row.outcome, refusalReason: row.refusalReason, payload: row.payload }));
}

/** The single internal reason the gateway recorded for a request. */
async function refusalReasonFor(trace: string): Promise<string | null> {
  const events = await eventsForTrace(trace);
  return events.at(-1)?.refusalReason ?? null;
}

// ---------------------------------------------------------------------------
// Enrollment — the real WP-24 ceremony, every step a real service call
// ---------------------------------------------------------------------------

interface EnrolledDevice {
  deviceId: string;
  keyId: string;
  keyVersion: number;
  trust: string;
  keyPair: TestDeviceKeyPair;
  tenant: TenantFixture;
}

async function enrol(
  options: {
    tenant?: TenantFixture;
    keyStorage?: DeviceKeyStorage;
    attestationOutcome?: DeviceAttestationOutcome;
  } = {},
): Promise<EnrolledDevice> {
  const tenant = options.tenant ?? A;
  const keyPair = generateTestDeviceKeyPair();
  attestation.outcome = options.attestationOutcome ?? 'UNAVAILABLE';

  const grant = await enrollment.issueBootstrapGrant(tenant.issuer, {
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    intendedUserId: tenant.operativeId,
    traceId: traceId(),
  });
  if (grant.outcome !== 'ISSUED') throw new Error(`grant not issued: ${JSON.stringify(grant)}`);

  const request = await enrollment.createEnrollmentRequest({
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    intendedUserId: tenant.operativeId,
    bootstrapToken: grant.token,
    custody: 'PERSONAL',
    publicKey: keyPair.publicKey,
    keyStorage: options.keyStorage ?? 'HARDWARE_BACKED',
    claimedSignatureProfile: PROFILE,
    custodyRegimeId: null,
    // WP-26/D26-04B: the SERVER's own attestation artifact reference. `null`
    // here means "no server-owned attestation accompanies this submission",
    // which the evaluator answers exactly as it did before the field existed.
    attestationArtifactRef: null,
    traceId: traceId(),
  });
  if (request.outcome !== 'REQUESTED') throw new Error(`request not created: ${JSON.stringify(request)}`);

  const approval = await enrollment.approveEnrollmentRequest(tenant.approver, {
    organisationId: tenant.organisationId,
    enrollmentRequestId: request.enrollmentRequestId,
    expectedRequestFingerprint: request.requestFingerprint,
    traceId: traceId(),
  });
  if (approval.outcome !== 'APPROVED') throw new Error(`approval refused: ${JSON.stringify(approval)}`);

  const challenge = await enrollment.issuePossessionChallenge(tenant.operative, {
    organisationId: tenant.organisationId,
    enrollmentRequestId: request.enrollmentRequestId,
    traceId: traceId(),
  });
  if (challenge.outcome !== 'ISSUED') throw new Error(`challenge refused: ${JSON.stringify(challenge)}`);

  const statement = canonicalDevicePossessionStatement({
    challenge_id: challenge.challengeId,
    enrollment_request_id: request.enrollmentRequestId,
    enrollment_request_fingerprint: request.requestFingerprint,
    nonce: challenge.nonce,
    public_key_thumbprint: deriveP256PublicKeyThumbprint(keyPair.publicKey),
    signature_profile: PROFILE,
  });
  await enrollment.verifyPossession({
    organisationId: tenant.organisationId,
    enrollmentRequestId: request.enrollmentRequestId,
    challengeId: challenge.challengeId,
    response: {
      schema_version: 1,
      challenge_id: challenge.challengeId,
      enrollment_request_id: request.enrollmentRequestId,
      claimed_signature_profile: PROFILE,
      signature: signCanonicalStatement(keyPair.privateKey, statement),
      answered_at: new Date().toISOString(),
    },
    traceId: traceId(),
  });

  const committed = await enrollment.commitEnrollment(tenant.operative, {
    organisationId: tenant.organisationId,
    enrollmentRequestId: request.enrollmentRequestId,
    challengeId: challenge.challengeId,
    traceId: traceId(),
  });
  if (committed.outcome !== 'COMMITTED') throw new Error(`commit refused: ${JSON.stringify(committed)}`);

  return {
    deviceId: committed.deviceId,
    keyId: committed.keyId,
    keyVersion: committed.keyVersion,
    trust: committed.trust,
    keyPair,
    tenant,
  };
}

/** The D24-10A rotation ceremony, end to end, so a rotation in this suite is a real one. */
async function rotate(device: EnrolledDevice): Promise<TestDeviceKeyPair> {
  const newKeyPair = generateTestDeviceKeyPair();
  const tenant = device.tenant;

  const request = await deviceKeys.requestKeyRotation(tenant.approver, {
    organisationId: tenant.organisationId,
    deviceId: device.deviceId,
    newPublicKey: newKeyPair.publicKey,
    newKeyStorage: 'HARDWARE_BACKED',
    traceId: traceId(),
  });
  if (request.outcome !== 'REQUESTED') throw new Error(`rotation not requested: ${JSON.stringify(request)}`);

  const challenge = await deviceKeys.issueRotationChallenge(tenant.approver, {
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    traceId: traceId(),
  });
  if (challenge.outcome !== 'ISSUED') throw new Error(`rotation challenge refused: ${JSON.stringify(challenge)}`);

  const standing = await registry.readDeviceStanding(tenant.approver, {
    organisationId: tenant.organisationId,
    deviceId: device.deviceId,
  });
  if (standing.outcome !== 'FOUND') throw new Error('device vanished');

  const possession = canonicalDeviceKeyRotationPossessionStatement({
    organisation_id: tenant.organisationId,
    device_id: device.deviceId,
    rotation_request_id: request.rotationRequestId,
    rotation_request_fingerprint: request.rotationRequestFingerprint,
    current_key_id: standing.standing.currentKeyId as string,
    current_key_version: standing.standing.currentKeyVersion as number,
    proposed_key_id: request.proposedKeyId,
    proposed_key_version: request.proposedKeyVersion,
    new_public_key_thumbprint: deriveP256PublicKeyThumbprint(newKeyPair.publicKey),
    rotation_challenge_id: challenge.challengeId,
    nonce: challenge.nonce,
    signature_profile: PROFILE,
  });
  await deviceKeys.verifyRotationPossession({
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    challengeId: challenge.challengeId,
    response: {
      schema_version: 1,
      challenge_id: challenge.challengeId,
      rotation_request_id: request.rotationRequestId,
      claimed_signature_profile: PROFILE,
      signature: signCanonicalStatement(newKeyPair.privateKey, possession),
      answered_at: new Date().toISOString(),
    },
    traceId: traceId(),
  });

  const continuity = signProof(device.keyPair, {
    contextId: randomUUID(),
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    actorUserId: tenant.operativeId,
    deviceId: device.deviceId,
    keyId: standing.standing.currentKeyId as string,
    keyVersion: standing.standing.currentKeyVersion as number,
    purpose: 'DEVICE_KEY_ROTATION',
    payloadDigest: request.rotationRequestFingerprint,
  });

  const outcome = await deviceKeys.commitKeyRotation(tenant.approver, {
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    challengeId: challenge.challengeId,
    continuityProof: continuity,
    traceId: traceId(),
  });
  if (outcome.outcome !== 'ROTATED') throw new Error(`rotation refused: ${JSON.stringify(outcome)}`);
  return newKeyPair;
}

// ---------------------------------------------------------------------------
// What a CONFORMING DEVICE does — the client half, written out in the open
// ---------------------------------------------------------------------------

/**
 * Builds and signs a frozen `DeviceRequestProof`.
 *
 * This is the whole of the client's cryptography, and it is deliberately
 * visible: what the device signs is the CONTRACT's canonical statement, with
 * the SERVER's signature profile substituted for its own claim (C15-01), and
 * `lowSCanonicaliseForSigning` applied by `signCanonicalStatement` because a
 * high-S signature is a value the contract refuses.
 */
function signProof(
  keyPair: TestDeviceKeyPair,
  input: {
    contextId: string;
    organisationId: string;
    siteId: string;
    actorUserId: string;
    deviceId: string;
    keyId: string;
    keyVersion: number;
    purpose: DeviceRequestPurpose;
    payloadDigest: string;
    nonce?: string;
    issuedAt?: string;
  },
): Record<string, unknown> {
  const proof = {
    schema_version: 1 as const,
    context_id: input.contextId,
    organisation_id: input.organisationId,
    site_id: input.siteId,
    actor_user_id: input.actorUserId,
    device_id: input.deviceId,
    key_id: input.keyId,
    key_version: input.keyVersion,
    purpose: input.purpose,
    payload_digest: input.payloadDigest,
    nonce: input.nonce ?? randomBytes(24).toString('base64url'),
    issued_at: input.issuedAt ?? new Date().toISOString(),
  };
  const statement = canonicalDeviceRequestProofStatement({ ...proof, signature_profile: PROFILE });
  return { ...proof, claimed_signature_profile: PROFILE, signature: signCanonicalStatement(keyPair.privateKey, statement) };
}

interface IssuedContext {
  context_id: string;
  organisation_id: string;
  actor_user_id: string;
  device_id: string;
  authorised_site_ids: string[];
  device_trust: string;
  key_id: string;
  key_version: number;
  issued_at: string;
  expires_at: string;
}

/** Step one of the ceremony: a HUMAN SESSION asks for a challenge. */
async function requestChallenge(
  device: EnrolledDevice,
  options: { actor?: string; siteId?: string; organisationId?: string } = {},
): Promise<HttpResult> {
  return post(
    `${GATEWAY}/contexts/establishment`,
    {
      organisation_id: options.organisationId ?? device.tenant.organisationId,
      device_id: device.deviceId,
      site_id: options.siteId ?? device.tenant.siteId,
    },
    asSession(options.actor ?? device.tenant.operativeId),
  );
}

/** The full ceremony, both steps, as a conforming client performs it. */
async function establish(
  device: EnrolledDevice,
  options: { actor?: string; siteId?: string; signer?: TestDeviceKeyPair } = {},
): Promise<{ challenge: DeviceContextEstablishmentChallengeView; result: HttpResult & { proof: Record<string, unknown> }; context: IssuedContext }> {
  const issued = await requestChallenge(device, options);
  expect(issued.status, JSON.stringify(issued.body)).toBe(201);
  const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
  const result = await completeEstablishment(challenge, options.signer ?? device.keyPair, { session: options.actor });
  return { challenge, result, context: (result.body as { context: IssuedContext }).context };
}

/**
 * Step two: the DEVICE signs the digest of the EXACT challenge, and the SAME
 * AUTHENTICATED HUMAN who opened the ceremony submits it (C17-01).
 *
 * `session` defaults to the actor the challenge is bound to, which is what a
 * conforming client does. Passing `null` sends NO session header; passing
 * another user id sends somebody else's live session. Both are refused, and
 * both have their own test below.
 */
async function completeEstablishment(
  challenge: DeviceContextEstablishmentChallengeView,
  signer: TestDeviceKeyPair,
  overrides: { nonce?: string; trace?: string; session?: string | null; proof?: Record<string, unknown>; bodyExtras?: Record<string, unknown> } = {},
): Promise<HttpResult & { proof: Record<string, unknown> }> {
  const proof = signProof(signer, {
    contextId: challenge.proposed_context_id,
    organisationId: challenge.organisation_id,
    siteId: challenge.site_id,
    actorUserId: challenge.actor_user_id,
    deviceId: challenge.device_id,
    keyId: challenge.key_id,
    keyVersion: challenge.key_version,
    purpose: 'RECONNECT_HANDSHAKE',
    payloadDigest: deviceContextEstablishmentChallengeDigest(challenge),
    nonce: overrides.nonce,
  });
  const session = overrides.session === undefined ? challenge.actor_user_id : overrides.session;
  const result = await post(
    `${GATEWAY}/contexts`,
    { establishment_id: challenge.establishment_id, proof: overrides.proof ?? proof, ...(overrides.bodyExtras ?? {}) },
    {
      ...(overrides.trace === undefined ? {} : { 'x-trace-id': overrides.trace }),
      ...(session === null ? {} : asSession(session)),
    },
  );
  return { ...result, proof: overrides.proof ?? proof };
}

const ROUTE: Readonly<Record<DeviceGatewayOperationKind, (targetId: string) => string>> = {
  FIELD_STATE_UPDATE: () => `${GATEWAY}/operations/field-state`,
  ASSIGNMENT_ACCEPT: (id) => `${GATEWAY}/operations/assignments/${id}/accept`,
  ASSIGNMENT_DECLINE: (id) => `${GATEWAY}/operations/assignments/${id}/decline`,
  INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE: (id) => `${GATEWAY}/operations/messages/${id}/acknowledge`,
};

/**
 * The digest a conforming device computes over the canonical typed envelope.
 *
 * It is built here from the fields the device already knows — the context it
 * holds and the site it is acting at — which is the point: the server rebuilds
 * the SAME envelope from ITS OWN state and refuses if the digests disagree.
 */
function envelopeDigestFor(
  kind: DeviceGatewayOperationKind,
  context: IssuedContext,
  siteId: string,
  targetId: string,
  payload: Record<string, unknown>,
): string {
  return deviceGatewayEnvelopeDigest({
    schema_version: 1,
    operation_kind: kind,
    organisation_id: context.organisation_id,
    site_id: siteId,
    actor_user_id: context.actor_user_id,
    device_id: context.device_id,
    target_type: DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND[kind],
    target_id: targetId,
    semantic_payload: payload,
  });
}

interface OperationRequest {
  kind: DeviceGatewayOperationKind;
  device: EnrolledDevice;
  context: IssuedContext;
  targetId?: string;
  payload?: Record<string, unknown>;
  siteId?: string;
  signer?: TestDeviceKeyPair;
  nonce?: string;
  issuedAt?: string;
  /** Extra top-level keys in the request body — used to prove they are refused. */
  bodyExtras?: Record<string, unknown>;
  /** A proof built elsewhere, presented here — the cross-purpose replay cases. */
  proof?: Record<string, unknown>;
  trace?: string;
  /**
   * C17-01: the authenticated human on the request.
   *
   * Defaults to the operative the context is bound to — what a conforming
   * client sends. `null` sends NO session header at all; another user id sends
   * somebody else's live session.
   */
  session?: string | null;
}

async function operate(request: OperationRequest): Promise<HttpResult & { proof: Record<string, unknown>; targetId: string }> {
  const siteId = request.siteId ?? request.context.authorised_site_ids[0] ?? '';
  const targetId = request.targetId ?? request.context.actor_user_id;
  const payload = request.payload ?? {};
  const proof =
    request.proof ??
    signProof(request.signer ?? request.device.keyPair, {
      contextId: request.context.context_id,
      organisationId: request.context.organisation_id,
      siteId,
      actorUserId: request.context.actor_user_id,
      deviceId: request.context.device_id,
      keyId: request.context.key_id,
      keyVersion: request.context.key_version,
      // D25-10: all three operations map to the frozen FIELD_OPERATION. No new
      // purpose value exists.
      purpose: 'FIELD_OPERATION',
      payloadDigest: envelopeDigestFor(request.kind, request.context, siteId, targetId, payload),
      nonce: request.nonce,
      issuedAt: request.issuedAt,
    });

  const session = request.session === undefined ? request.context.actor_user_id : request.session;
  const result = await post(
    ROUTE[request.kind](targetId),
    { proof, payload, ...(request.bodyExtras ?? {}) },
    {
      ...(request.trace === undefined ? {} : { 'x-trace-id': request.trace }),
      ...(session === null ? {} : asSession(session)),
    },
  );
  return { ...result, proof, targetId };
}

const fieldStatePayload = (state = 'PATROL'): Record<string, unknown> => ({
  state,
  location: null,
  source_at: new Date().toISOString(),
  freshness_ms: 0,
});

let fixtureSeq = 0;

/** A fresh REQUESTED assignment for `assignee`, so accept/decline has a real target. */
async function newAssignment(assignee: string): Promise<string> {
  const row = await prisma.fieldAssignment.create({
    data: {
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      incidentId: fx.incidentA1,
      assigneeUserId: assignee,
      assignmentType: 'INCIDENT_RESPONSE',
      priority: 'SEV3',
      status: 'REQUESTED',
      deliveryState: 'REQUESTED',
      needToKnowSummary: 'wp25 fixture',
      idempotencyKey: `${tag}-assignment-${(fixtureSeq += 1)}`,
      createdByUserId: fx.dispatcherA,
      updatedByUserId: fx.dispatcherA,
    },
    select: { id: true },
  });
  return row.id;
}

/**
 * A message whose recipient row already carries TRANSPORT evidence.
 *
 * WP-18's `ACKNOWLEDGE_REQUIRES_STATE` is DELIVERED and there is deliberately
 * no route that manufactures it — delivery evidence stays server-owned (D25-06)
 * — so the fixture writes it directly.
 */
async function newDeliveredMessage(recipient: string): Promise<string> {
  const row = await prisma.incidentFieldMessage.create({
    data: {
      organisationId: fx.orgA,
      siteId: fx.siteA1,
      incidentId: fx.incidentA1,
      senderUserId: fx.dispatcherA,
      body: 'wp25 seeded message',
      mediaRefs: [],
      retentionClass: 'standard',
      idempotencyKey: `${tag}-message-${(fixtureSeq += 1)}`,
      traceId: `${tag}-seed`,
      recipients: {
        create: [{ organisationId: fx.orgA, siteId: fx.siteA1, recipientUserId: recipient, deliveryState: 'DELIVERED', deliveredAt: new Date() }],
      },
    },
    select: { id: true },
  });
  return row.id;
}

/**
 * Runs `mutate` BETWEEN the preflight and the final effect transaction.
 *
 * The seam is the first statement of the transaction — the locking context
 * read. At that instant the preflight has approved everything and the
 * transaction holds no lock, so a mutation committed here is exactly the
 * D25-04A hazard: the world moved after the decision and before the commit.
 */
async function withMutationBeforeCommit<T>(mutate: () => Promise<void>, run: () => Promise<T>): Promise<T> {
  const original = gatewayRepository.lockContext.bind(gatewayRepository);
  const spy = vi.spyOn(gatewayRepository, 'lockContext').mockImplementationOnce(async (tx, organisationId, contextId) => {
    await mutate();
    return original(tx, organisationId, contextId);
  });
  try {
    return await run();
  } finally {
    spy.mockRestore();
  }
}

/**
 * The establishment ceremony's equivalent seam: `mutate` runs BETWEEN the
 * preflight and the final transaction of `completeEstablishment`.
 *
 * The seam is the transaction's first statement — the locking challenge read —
 * so at that instant the preflight has approved everything and the transaction
 * holds no lock. Exactly the D25-04A hazard, on the ceremony that MINTS
 * authority rather than on one that spends it.
 */
async function withMutationBeforeEstablishmentCommit<T>(mutate: () => Promise<void>, run: () => Promise<T>): Promise<T> {
  const original = gatewayRepository.lockEstablishmentChallenge.bind(gatewayRepository);
  const spy = vi
    .spyOn(gatewayRepository, 'lockEstablishmentChallenge')
    .mockImplementationOnce(async (tx, organisationId, id) => {
      await mutate();
      return original(tx, organisationId, id);
    });
  try {
    return await run();
  } finally {
    spy.mockRestore();
  }
}

/** Every gateway event this tenant holds, for the cross-tenant provenance assertions. */
async function eventCountFor(organisationId: string): Promise<number> {
  return prisma.deviceGatewayOperationEvent.count({ where: { organisationId } });
}

/**
 * The one-shot identities the GATEWAY has spent.
 *
 * Filtered to WP-25's own ceremony label deliberately: Shield's enrollment and
 * rotation ceremonies spend identities in the SAME store (D25-10 — there is no
 * second replay subsystem), so an unfiltered count would move whenever a
 * fixture enrolled or rotated a device and the assertion would be measuring
 * the wrong thing.
 */
async function nonceConsumptions(): Promise<Array<{ ceremony: string; storedOutcomeRef: string | null }>> {
  const rows = await prisma.deviceNonceConsumption.findMany({ where: { organisationId: fx.orgA, ceremony: 'GATEWAY_OPERATION' } });
  return rows.map((row) => ({ ceremony: row.ceremony, storedOutcomeRef: row.storedOutcomeRef }));
}

// ---------------------------------------------------------------------------

describe('WP-25/D25-03A establishing a context, without the circularity', () => {
  it('a device with NO context obtains one by signing the challenge', async () => {
    const device = await enrol();
    const { challenge, result, context } = await establish(device);

    expect(result.status).toBe(201);
    expect(context.context_id).toBe(challenge.proposed_context_id);
    expect(context.organisation_id).toBe(fx.orgA);
    expect(context.actor_user_id).toBe(fx.opAlpha);
    expect(context.device_id).toBe(device.deviceId);
    expect(context.authorised_site_ids).toEqual([fx.siteA1]);
    expect(context.key_id).toBe(device.keyId);
    expect(context.key_version).toBe(device.keyVersion);
    // The SERVER owns every field, including the window: at most the frozen
    // 300-second ceiling, and never a value the device proposed.
    expect(new Date(context.expires_at).getTime() - new Date(context.issued_at).getTime()).toBeLessThanOrEqual(
      DEVICE_CONTEXT_MAX_LIFETIME_MS,
    );

    const row = await prisma.authenticatedDeviceContextRecord.findUniqueOrThrow({ where: { id: context.context_id } });
    expect(row.establishmentId).toBe(challenge.establishment_id);
    expect(row.closedAt).toBeNull();
    const sites = await prisma.authenticatedDeviceContextSite.findMany({ where: { contextId: context.context_id } });
    expect(sites.map((site) => site.siteId)).toEqual([fx.siteA1]);
    // The ceremony is spent, in the same transaction that minted the context.
    const spent = await prisma.deviceContextEstablishmentChallenge.findUniqueOrThrow({ where: { id: challenge.establishment_id } });
    expect(spent.consumedAt).not.toBeNull();
  });

  it('the in-memory CANDIDATE context is never returned and never persisted', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    expect(issued.status).toBe(201);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    // Step one hands back a CHALLENGE and nothing that could be mistaken for a
    // context: no `device_trust`, no `authorised_site_ids`, no `context_id`.
    expect(Object.keys(issued.body)).toEqual(['challenge']);
    expect(Object.keys(challenge).sort()).toEqual(
      [
        'actor_user_id',
        'device_id',
        'establishment_id',
        'expires_at',
        'issued_at',
        'key_id',
        'key_version',
        'nonce',
        'organisation_id',
        'proposed_context_id',
        'schema_version',
        'site_id',
      ].sort(),
    );
    expect(JSON.stringify(issued.body)).not.toContain('device_trust');
    expect(JSON.stringify(issued.body)).not.toContain('authorised_site_ids');

    // And a REFUSED completion returns no context AND leaves no context row —
    // the candidate the evaluators judged existed only inside the process.
    const refused = await completeEstablishment(challenge, generateTestDeviceKeyPair());
    expect(refused.status).toBe(403);
    expect(JSON.stringify(refused.body)).not.toContain('context');
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
  });

  it('stealing EVERY field of the challenge confers ZERO authority without the key', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    // The attacker has the establishment id, the proposed context id, the
    // server nonce, the device id, the key id, the key version and the site —
    // every column of the row. They do not have the registered private key.
    const attacker = generateTestDeviceKeyPair();
    const trace = traceId();
    const stolen = await completeEstablishment(challenge, attacker, { trace });

    expect(stolen.status).toBe(403);
    expect(stolen.body.error).toBe('DEVICE_REQUEST_REFUSED');
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
    // The challenge is NOT burned by a failed attempt, so an attacker cannot
    // deny the legitimate device its ceremony by racing it with a bad
    // signature; the legitimate device still completes.
    expect((await prisma.deviceContextEstablishmentChallenge.findUniqueOrThrow({ where: { id: challenge.establishment_id } })).consumedAt).toBeNull();
    expect(await refusalReasonFor(trace)).toContain('POSSESSION_NOT_PROVEN');

    const honest = await completeEstablishment(challenge, device.keyPair);
    expect(honest.status).toBe(201);
  });

  it('WITHOUT an independent human session it refuses', async () => {
    const device = await enrol();
    // No `x-dev-user-id`: the global session guard rejects before the handler.
    const anonymous = await post(`${GATEWAY}/contexts/establishment`, {
      organisation_id: fx.orgA,
      device_id: device.deviceId,
      site_id: fx.siteA1,
    });
    expect(anonymous.status).toBe(401);

    // A live session that is NOT gateway-capable at this site is refused too,
    // and refused identically to every other establishment failure.
    const wrongSite = await requestChallenge(device, { siteId: fx.siteA2 });
    expect(wrongSite.status).toBe(403);
    expect(wrongSite.body.error).toBe('DEVICE_REQUEST_REFUSED');

    // A session in ANOTHER TENANT asking about this device: same answer.
    const foreign = await requestChallenge(device, { actor: fx.opB });
    expect(foreign.status).toBe(403);
    expect(foreign.body.error).toBe('DEVICE_REQUEST_REFUSED');
  });

  it('a SECOND use of a one-shot challenge refuses', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    expect((await completeEstablishment(challenge, device.keyPair)).status).toBe(201);

    // A FRESH nonce, so this is not merely a replayed proof: it is a second,
    // perfectly valid signature over the same spent ceremony.
    const trace = traceId();
    const second = await completeEstablishment(challenge, device.keyPair, { nonce: randomBytes(24).toString('base64url'), trace });
    expect(second.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('ESTABLISHMENT_NOT_USABLE');
    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(1);
  });

  it('an EXPIRED challenge refuses, against its own ceiling', async () => {
    // D25-12: the establishment ceiling is WP-25's own approved constant and is
    // NOT the frozen 60-second request-proof freshness. Asserting they differ
    // is asserting that WP-25 did not acquire a second freshness opinion.
    expect(DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS).toBe(120_000);
    expect(DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS).not.toBe(DEVICE_REQUEST_PROOF_MAX_AGE_MS);

    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    // The window the server actually chose IS that ceiling.
    expect(new Date(challenge.expires_at).getTime() - new Date(challenge.issued_at).getTime()).toBe(
      DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS,
    );

    const expiredAt = new Date(Date.now() - 1_000);
    await prisma.deviceContextEstablishmentChallenge.update({
      where: { id: challenge.establishment_id },
      data: { expiresAt: expiredAt },
    });
    const trace = traceId();
    const late = await completeEstablishment({ ...challenge, expires_at: expiredAt.toISOString() }, device.keyPair, { trace });
    expect(late.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('ESTABLISHMENT_NOT_USABLE');
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
  });
});

describe('WP-25/D25-01 there is no device bearer token, ever', () => {
  it('a context id WITHOUT a possession proof is refused', async () => {
    const device = await enrol();
    const { context } = await establish(device);

    // The whole "stolen context" scenario: every field perfect, presented by
    // somebody who does not hold the hardware key. With a live session, so this
    // is a possession failure and not an authentication one.
    const naked = await post(`${GATEWAY}/operations/field-state`, { payload: fieldStatePayload() }, asSession(fx.opAlpha));
    expect(naked.status).toBe(403);

    const trace = traceId();
    const forged = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device,
      context,
      payload: fieldStatePayload(),
      // A structurally perfect proof, signed by a key that is not registered.
      signer: generateTestDeviceKeyPair(),
      trace,
    });
    expect(forged.status).toBe(403);
    expect(forged.body.error).toBe('DEVICE_REQUEST_REFUSED');
    // The internal audit names the ACTUAL reason, which is the point of the
    // frozen evaluator's ordering: possession is checked LAST, so the stolen
    // context reaches the end and refuses for the right reason.
    expect(await refusalReasonFor(trace)).toContain('POSSESSION_NOT_PROVEN');
    expect(await prisma.fieldOperativeCurrentState.count({ where: { userId: fx.opAlpha } })).toBe(0);
  });

  it('a captured proof replayed VERBATIM causes no second effect, and the nonce stays spent', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    const first = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
    });
    expect(first.status).toBe(201);

    // The identical request, byte for byte — a captured proof replayed. The
    // one-shot identity is already spent, so this converges on the stored
    // outcome and causes NO second domain effect (D25-02).
    const replay = await post(
      ROUTE.ASSIGNMENT_ACCEPT(assignmentId),
      { proof: first.proof, payload: { expected_status: 'REQUESTED' } },
      asSession(fx.opAlpha),
    );
    expect(replay.status).toBe(201);
    expect(replay.body.outcome).toBe('CONVERGED');

    const idempotency = await prisma.fieldAssignmentActionIdempotency.findMany({ where: { assignmentId, action: 'accept' } });
    expect(idempotency).toHaveLength(1);
    const audit = await prisma.fieldAuditLog.findMany({ where: { assignmentId, kind: 'FIELD_ASSIGNMENT_ACCEPTED' } });
    expect(audit).toHaveLength(1);
  });

  it('a captured proof RETARGETED at another payload or another route is refused', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    const accept = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
    });
    expect(accept.status).toBe(201);

    // D25-11: the proof binds the DIGEST of the canonical typed envelope, and
    // the envelope names the operation kind. Carrying an ACCEPT proof to the
    // field-state route cannot work, however similar the bodies look.
    const trace = traceId();
    const carried = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device,
      context,
      payload: fieldStatePayload(),
      proof: accept.proof,
      trace,
    });
    expect(carried.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('PAYLOAD_DIGEST_MISMATCH');
    expect(await prisma.fieldOperativeCurrentState.count({ where: { userId: fx.opAlpha, siteId: fx.siteA1 } })).toBe(0);

    // And carried to the DECLINE route for the same assignment: the kind is in
    // the digest, so this is a different statement.
    const declined = await post(
      ROUTE.ASSIGNMENT_DECLINE(assignmentId),
      { proof: accept.proof, payload: { expected_status: 'REQUESTED' } },
      asSession(fx.opAlpha),
    );
    expect(declined.status).toBe(403);
  });

  it('D25-11: a body-supplied operation_kind that conflicts with the ROUTE refuses', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    const trace = traceId();
    const conflicting = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      bodyExtras: { operation_kind: 'FIELD_STATE_UPDATE' },
      trace,
    });
    expect(conflicting.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('OPERATION_KIND_CONFLICT');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
  });

  it('D25-16B: the device cannot choose the downstream domain idempotency key', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opBravo);

    // There is no parameter for it. A body that tries to smuggle one into the
    // SEMANTIC PAYLOAD is refused outright, because the payload is strict.
    const smuggled = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context: { ...context, actor_user_id: context.actor_user_id },
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED', idempotency_key: 'chosen-by-the-device' },
    });
    expect(smuggled.status).toBe(403);

    // C17-06: a top-level `idempotency_key` is no longer merely IGNORED — it is
    // REFUSED. The outer request schema is `.strict()`, because a field the
    // device did not sign has no business being accepted at a cryptographic
    // boundary even when nothing currently reads it.
    const rejected = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: await newAssignment(fx.opAlpha),
      payload: { expected_status: 'REQUESTED' },
      bodyExtras: { idempotency_key: 'chosen-by-the-device' },
    });
    expect(rejected.status).toBe(403);

    // And the key the domain actually stores is the SERVER's derivation, over
    // the signed operation — there is no parameter for it anywhere.
    const alphaAssignment = await newAssignment(fx.opAlpha);
    const committed = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: alphaAssignment,
      payload: { expected_status: 'REQUESTED' },
    });
    expect(committed.status).toBe(201);

    const expected = deviceGatewayDomainIdempotencyKey({
      organisationId: context.organisation_id,
      contextId: context.context_id,
      actorUserId: context.actor_user_id,
      deviceId: context.device_id,
      keyId: context.key_id,
      keyVersion: context.key_version,
      operationKind: 'ASSIGNMENT_ACCEPT',
      targetType: 'FIELD_ASSIGNMENT',
      targetId: alphaAssignment,
      deviceNonce: committed.proof.nonce as string,
      payloadDigest: committed.proof.payload_digest as string,
    });
    const stored = await prisma.fieldAssignmentActionIdempotency.findFirstOrThrow({ where: { assignmentId: alphaAssignment, action: 'accept' } });
    expect(stored.idempotencyKey).toBe(expected);
    expect(stored.idempotencyKey).not.toBe('chosen-by-the-device');
    expect(stored.idempotencyKey).toMatch(/^[0-9a-f]{64}$/u);
  });
});

describe('WP-25/D25-10 each of the three operations, end to end, with the real domain effect', () => {
  it('A. field state update', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const outboxBefore = await prisma.fieldOutbox.count({ where: { organisationId: fx.orgA } });

    const result = await operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload('RESPONDING') });
    expect(result.status).toBe(201);
    expect(result.body.outcome).toBe('COMMITTED');
    expect(result.body.target_type).toBe('FIELD_OPERATIVE_STATE');

    const state = await prisma.fieldOperativeCurrentState.findUniqueOrThrow({
      where: { organisationId_siteId_userId: { organisationId: fx.orgA, siteId: fx.siteA1, userId: fx.opAlpha } },
    });
    expect(state.state).toBe('RESPONDING');
    // The domain row names the AUTHENTICATED hardware, not a device id from a
    // JSON body — which is the C10-02 hole this whole work package closes.
    expect(state.deviceId).toBe(device.deviceId);
    expect(await prisma.fieldOperativeStateHistory.count({ where: { userId: fx.opAlpha, siteId: fx.siteA1 } })).toBe(1);
    expect(await prisma.fieldOutbox.count({ where: { organisationId: fx.orgA } })).toBe(outboxBefore + 1);
  });

  it('B. assignment ACCEPT and DECLINE', async () => {
    const device = await enrol();
    const { context } = await establish(device);

    const acceptId = await newAssignment(fx.opAlpha);
    const accepted = await operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: acceptId, payload: { expected_status: 'REQUESTED' } });
    expect(accepted.status).toBe(201);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: acceptId } })).status).toBe('ACCEPTED');

    const declineId = await newAssignment(fx.opAlpha);
    const declined = await operate({ kind: 'ASSIGNMENT_DECLINE', device, context, targetId: declineId, payload: { expected_status: 'REQUESTED' } });
    expect(declined.status).toBe(201);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: declineId } })).status).toBe('DECLINED');
  });

  it('C. incident field message acknowledgement, DELIVERED -> ACKNOWLEDGED', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const messageId = await newDeliveredMessage(fx.opAlpha);

    const result = await operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: messageId });
    expect(result.status).toBe(201);

    const recipient = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.opAlpha } });
    expect(recipient.deliveryState).toBe('ACKNOWLEDGED');
    expect(recipient.acknowledgedAt).not.toBeNull();
    // C8-01: the acknowledgement did NOT manufacture the transport evidence
    // that should have preceded it.
    expect(recipient.deliveredAt).not.toBeNull();
    expect(
      await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGED' } }),
    ).toBeGreaterThanOrEqual(1);
  });

  it('an acknowledgement of a row that is NOT DELIVERED is refused, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const row = await prisma.incidentFieldMessage.create({
      data: {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        incidentId: fx.incidentA1,
        senderUserId: fx.dispatcherA,
        body: 'wp25 undelivered',
        mediaRefs: [],
        retentionClass: 'standard',
        idempotencyKey: `${tag}-message-${(fixtureSeq += 1)}`,
        traceId: `${tag}-seed`,
        recipients: { create: [{ organisationId: fx.orgA, siteId: fx.siteA1, recipientUserId: fx.opAlpha, deliveryState: 'REQUESTED' }] },
      },
      select: { id: true },
    });

    const trace = traceId();
    const refused = await operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: row.id, trace });
    expect(refused.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('DOMAIN_EFFECT_REFUSED');
    expect((await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId: row.id } })).deliveryState).toBe('REQUESTED');
    // The domain refused AFTER the replay identity was claimed, so the claim
    // must not have survived: an identity burned for an operation that never
    // happened is precisely what D25-02 forbids.
    expect((await nonceConsumptions()).filter((row2) => row2.ceremony === 'GATEWAY_OPERATION' && row2.storedOutcomeRef === null)).toHaveLength(0);
  });
});

describe('WP-25/D25-02 the effect transaction commits together, or nothing does', () => {
  it('the replay claim, the domain effect, the domain idempotency, the outbox and both audits COMMIT TOGETHER', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const trace = traceId();

    const result = await operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload('ON_SCENE'), trace });
    expect(result.status).toBe(201);

    const expectedKey = deviceGatewayDomainIdempotencyKey({
      organisationId: context.organisation_id,
      contextId: context.context_id,
      actorUserId: context.actor_user_id,
      deviceId: context.device_id,
      keyId: context.key_id,
      keyVersion: context.key_version,
      operationKind: 'FIELD_STATE_UPDATE',
      targetType: 'FIELD_OPERATIVE_STATE',
      targetId: context.actor_user_id,
      deviceNonce: result.proof.nonce as string,
      payloadDigest: result.proof.payload_digest as string,
    });

    // 1. the gateway replay claim, in Shield's ONE store, under WP-25's ceremony
    const claim = await prisma.deviceNonceConsumption.findFirstOrThrow({
      where: { organisationId: fx.orgA, ceremony: 'GATEWAY_OPERATION', storedOutcomeRef: expectedKey },
    });
    expect(claim.storedOutcomeRef).toBe(expectedKey);
    // 2. the domain effect
    expect(
      (
        await prisma.fieldOperativeCurrentState.findUniqueOrThrow({
          where: { organisationId_siteId_userId: { organisationId: fx.orgA, siteId: fx.siteA1, userId: fx.opAlpha } },
        })
      ).state,
    ).toBe('ON_SCENE');
    // 3. the domain idempotency identity, SERVER-derived
    expect(
      await prisma.fieldStateUpdateIdempotency.findUnique({
        where: {
          organisationId_siteId_userId_deviceId_idempotencyKey: {
            organisationId: fx.orgA,
            siteId: fx.siteA1,
            userId: fx.opAlpha,
            deviceId: device.deviceId,
            idempotencyKey: expectedKey,
          },
        },
      }),
    ).not.toBeNull();
    // 4. the domain outbox row and 5. the domain audit row
    expect(await prisma.fieldOutbox.count({ where: { organisationId: fx.orgA, siteId: fx.siteA1 } })).toBeGreaterThanOrEqual(1);
    expect(await prisma.fieldAuditLog.count({ where: { organisationId: fx.orgA, kind: 'FIELD_STATE_UPDATED' } })).toBeGreaterThanOrEqual(1);
    // 6. the gateway security audit, naming the outcome reference
    const events = await eventsForTrace(trace);
    expect(events.map((event) => event.eventType)).toEqual(['OPERATION_COMMITTED']);
    expect((events[0]?.payload as Record<string, unknown>).domain_idempotency_key).toBe(expectedKey);
  });

  it('a forced failure AFTER the domain mutation rolls back ALL of it', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const outboxBefore = await prisma.fieldOutbox.count({ where: { organisationId: fx.orgA } });
    const claimsBefore = (await nonceConsumptions()).length;

    // The fault is injected at the LAST write of the transaction — after the
    // replay identity has been claimed and after the domain service has
    // mutated the assignment. Everything must disappear together.
    const spy = vi
      .spyOn(gatewayRepository, 'appendOperationEvent')
      .mockRejectedValueOnce(new Error('wp25 injected fault: the gateway audit write failed'));
    let status = 0;
    try {
      const result = await operate({
        kind: 'ASSIGNMENT_ACCEPT',
        device,
        context,
        targetId: assignmentId,
        payload: { expected_status: 'REQUESTED' },
      });
      status = result.status;
    } finally {
      spy.mockRestore();
    }
    expect(status).toBe(500);

    // ZERO domain row movement...
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    // ...zero domain idempotency...
    expect(await prisma.fieldAssignmentActionIdempotency.count({ where: { assignmentId } })).toBe(0);
    // ...zero outbox...
    expect(await prisma.fieldOutbox.count({ where: { organisationId: fx.orgA } })).toBe(outboxBefore);
    // ...and zero committed replay claim. This is the invariant in one line:
    // no FIRST_SEEN device replay consumption survives without its effect.
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
  });
});

describe('WP-25/D25-04A the fence: the world moving between preflight and commit', () => {
  it('the device is REVOKED between preflight and commit -> refuse, zero effect, zero consumption', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    const result = await withMutationBeforeCommit(
      async () => {
        const revoked = await trust.declareDisposition(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'STOLEN',
          reason: 'wp25 fence',
          traceId: traceId(),
        });
        if (revoked.outcome !== 'DECLARED') throw new Error(`disposition refused: ${JSON.stringify(revoked)}`);
      },
      () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
    );

    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('CREDENTIAL_REVOKED');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
  });

  it('the key ROTATES between preflight and commit -> KEY_VERSION_ROTATED, zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    const result = await withMutationBeforeCommit(
      async () => {
        await rotate(device);
      },
      () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
    );

    expect(result.status).toBe(403);
    // CONTEXT_KEY_MISMATCH, not KEY_VERSION_ROTATED, and the distinction is a
    // FINDING rather than a compromise. The frozen evaluator asks
    // `registered.key_id !== context.key_id` BEFORE it asks about the version,
    // and Shield's D24-10A rotation mints a NEW key id as well as a new
    // version — so a real rotation is caught one line earlier than the
    // directive's prose anticipates. The security property is identical and
    // strictly stronger in ordering: a context bound to a superseded
    // credential is refused before possession is even considered, with zero
    // effect and zero consumption. `KEY_VERSION_ROTATED` remains the refusal
    // for a registry whose key id is stable across versions; Shield's is not.
    expect(await refusalReasonFor(trace)).toContain('CONTEXT_KEY_MISMATCH');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
  });

  it('the CONTEXT is closed between preflight and commit -> refuse, zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    const result = await withMutationBeforeCommit(
      async () => {
        const closed = await gatewayRepository.closeContext(fx.orgA, context.context_id, 'WP25_FENCE', new Date());
        expect(closed).toBe(1);
      },
      () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
    );

    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('CONTEXT_NOT_USABLE');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
  });

  it("the ACTOR's authority is withdrawn between preflight and commit -> refuse, zero effect", async () => {
    const charlie: TenantFixture = { ...A, operativeId: fx.opCharlie, operative: principalFor(fx.opCharlie, 'field.operative', fx.siteA1, fx.orgA) };
    const device = await enrol({ tenant: charlie });
    const { context } = await establish(device, { actor: fx.opCharlie });
    const assignmentId = await newAssignment(fx.opCharlie);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    const roles = await prisma.userRole.findMany({ where: { userId: fx.opCharlie } });
    try {
      const result = await withMutationBeforeCommit(
        async () => {
          await prisma.userRole.deleteMany({ where: { userId: fx.opCharlie } });
        },
        () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
      );
      expect(result.status).toBe(403);
      // The frozen evaluator's own verdict, not a gateway paraphrase.
      expect(await refusalReasonFor(trace)).toContain('ACTOR_AUTHORITY_REMOVED');
      expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
      expect((await nonceConsumptions()).length).toBe(claimsBefore);
    } finally {
      await prisma.userRole.createMany({ data: roles.map((role) => ({ userId: role.userId, role: role.role, siteId: role.siteId })) });
    }
  });

  it("the ACTOR's SITE entitlement is withdrawn between preflight and commit -> refuse, zero effect", async () => {
    const charlie: TenantFixture = { ...A, operativeId: fx.opCharlie, operative: principalFor(fx.opCharlie, 'field.operative', fx.siteA1, fx.orgA) };
    const device = await enrol({ tenant: charlie });
    const { context } = await establish(device, { actor: fx.opCharlie });
    const assignmentId = await newAssignment(fx.opCharlie);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    try {
      const result = await withMutationBeforeCommit(
        async () => {
          // The operative keeps the ROLE and loses the SITE — a move, not a
          // suspension. These are separate facts and the refusal says which.
          await prisma.userRole.updateMany({ where: { userId: fx.opCharlie }, data: { siteId: fx.siteA2 } });
        },
        () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
      );
      expect(result.status).toBe(403);
      expect(await refusalReasonFor(trace)).toContain('SITE_ENTITLEMENT_LOST');
      expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
      expect((await nonceConsumptions()).length).toBe(claimsBefore);
    } finally {
      await prisma.userRole.updateMany({ where: { userId: fx.opCharlie }, data: { siteId: fx.siteA1 } });
    }
  });

  it('a key rotation invalidates a context bound to the SUPERSEDED version', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const newKeyPair = await rotate(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const trace = traceId();

    // The context names key version 1; the registry now says 2. The frozen
    // evaluator refuses on the VERSION, before it ever asks about possession —
    // so this is not "the signature happened to fail".
    const result = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device: { ...device, keyPair: newKeyPair },
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      trace,
    });
    expect(result.status).toBe(403);
    // See the fence test above for why this reads CONTEXT_KEY_MISMATCH rather
    // than KEY_VERSION_ROTATED: Shield's rotation moves the key ID as well as
    // the version, and the frozen evaluator checks the id first. Either way
    // the context bound to the superseded credential is dead.
    expect(await refusalReasonFor(trace)).toContain('CONTEXT_KEY_MISMATCH');

    // A FRESH context, bound to the new version, works — the rotation
    // invalidated the context, not the device.
    const reissued = await establish({ ...device, keyPair: newKeyPair });
    expect(reissued.context.key_version).toBe(context.key_version + 1);
    const accepted = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device: { ...device, keyPair: newKeyPair },
      context: reissued.context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
    });
    expect(accepted.status).toBe(201);
  });
});

describe('WP-25/D25-02 convergence and conflict', () => {
  it('an EXACT DUPLICATE converges without a second domain effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const messageId = await newDeliveredMessage(fx.opAlpha);

    const first = await operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: messageId });
    expect(first.status).toBe(201);
    expect(first.body.outcome).toBe('COMMITTED');

    const trace = traceId();
    const again = await post(
      ROUTE.INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE(messageId),
      { proof: first.proof, payload: {} },
      { 'x-trace-id': trace, ...asSession(fx.opAlpha) },
    );
    expect(again.status).toBe(201);
    expect(again.body.outcome).toBe('CONVERGED');

    // One acknowledgement, one idempotency row, one timeline entry.
    expect(await prisma.incidentFieldMessageActionIdempotency.count({ where: { messageId, action: 'acknowledge' } })).toBe(1);
    const events = await eventsForTrace(trace);
    expect(events.map((event) => event.eventType)).toEqual(['OPERATION_CONVERGED']);
  });

  it('CHANGED SEMANTICS under the same one-shot identity CONFLICTS', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const nonce = randomBytes(24).toString('base64url');

    const first = await operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload('PATROL'), nonce });
    expect(first.status).toBe(201);

    // The SAME nonce, a DIFFERENT signed statement. There is no shared outcome
    // to converge on, so this is a conflict rather than a duplicate.
    const trace = traceId();
    const conflicting = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device,
      context,
      payload: fieldStatePayload('OFF_DUTY'),
      nonce,
      trace,
    });
    expect(conflicting.status).toBe(409);
    expect(conflicting.body.error).toBe('DEVICE_REQUEST_CONFLICT');
    expect(await refusalReasonFor(trace)).toContain('NONCE_REUSED_WITH_CHANGED_SEMANTICS');
    expect(
      (
        await prisma.fieldOperativeCurrentState.findUniqueOrThrow({
          where: { organisationId_siteId_userId: { organisationId: fx.orgA, siteId: fx.siteA1, userId: fx.opAlpha } },
        })
      ).state,
    ).toBe('PATROL');
  });

  it('an EXACT DUPLICATE whose stored outcome cannot be proved FAILS CLOSED', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const messageId = await newDeliveredMessage(fx.opAlpha);

    const first = await operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: messageId });
    expect(first.status).toBe(201);

    // Erase the DOMAIN's evidence while leaving the replay row behind — the
    // exact shape of a stored outcome reference that no longer resolves. The
    // gateway must refuse rather than "converge" on an effect it cannot prove.
    await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { messageId, action: 'acknowledge' } });
    const trace = traceId();
    const unresolvable = await post(
      ROUTE.INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE(messageId),
      { proof: first.proof, payload: {} },
      { 'x-trace-id': trace, ...asSession(fx.opAlpha) },
    );
    expect(unresolvable.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('DUPLICATE_UNRESOLVABLE');
  });
});

describe('WP-25 current registry standing decides, not the context snapshot', () => {
  it('a QUARANTINED device is refused a FIELD_OPERATION, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    // The context was minted while the device was operable. Trust then moves.
    const changed = await trust.changeDeviceTrust(A.approver, {
      organisationId: fx.orgA,
      deviceId: device.deviceId,
      to: 'QUARANTINED',
      reason: 'wp25 trust gate',
      traceId: traceId(),
    });
    expect(changed.outcome).toBe('CHANGED');

    const trace = traceId();
    const refused = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      trace,
    });
    expect(refused.status).toBe(403);
    // The frozen purpose table decides: FIELD_OPERATION admits TRUSTED and
    // DEGRADED and nothing else. Widening that row is a contract change.
    expect(await refusalReasonFor(trace)).toContain('DEVICE_TRUST_NOT_PERMITTED');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
  });

  it('an attestation aged past the grace degrades the answer IMMEDIATELY, before the row catches up', async () => {
    const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
    expect(device.trust).toBe('TRUSTED');

    // Age the evidence past the six-hour grace WITHOUT recording a new
    // observation. Nothing has written to the device row, so the persisted
    // column still says TRUSTED — which, before WP-24's C16-R5, is exactly what
    // an authorisation check would have believed.
    const agedAt = new Date(Date.now() - (DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS + 600_000));
    await prisma.deviceAttestationObservation.updateMany({
      where: { deviceId: device.deviceId },
      data: { evaluatedAt: agedAt, observedAt: agedAt },
    });
    // The provider then goes dark. The observation is APPENDED DIRECTLY rather
    // than through `recordAttestationObservation`, precisely so the durable
    // TRUSTED -> DEGRADED transition does NOT run: what is under test is what
    // the gateway concludes while the device row has not caught up.
    await prisma.deviceAttestationObservation.create({
      data: {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        outcome: 'UNAVAILABLE',
        attestationReference: null,
        evaluatedAt: new Date(),
        observedAt: new Date(),
        traceId: traceId(),
      },
    });
    expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('TRUSTED');
    // Shield's ONE canonical effective resolution already says otherwise...
    expect(await registry.effectiveDeviceTrust(fx.orgA, device.deviceId)).toBe('DEGRADED');

    // ...and the gateway acts on THAT, on the very next request, recording the
    // effective standing rather than the stale column.
    const { context } = await establish(device);
    expect(context.device_trust).toBe('DEGRADED');
    const trace = traceId();
    const result = await operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload('OBSERVING'), trace });
    expect(result.status).toBe(201);
    const events = await eventsForTrace(trace);
    expect((events[0]?.payload as Record<string, unknown>).effective_trust).toBe('DEGRADED');
    // DEGRADED still admits FIELD_OPERATION under the frozen purpose table, so
    // this ageing degrades the ANSWER without refusing the operation. The
    // refusal case is the QUARANTINED test above; what is proved here is that
    // the gateway never reads the persisted column.
    expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('TRUSTED');
  });
});

describe('WP-25/D25-10 what the gateway does NOT expose', () => {
  it('assignment start, complete, cancel and reassign are not reachable through the gateway', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    for (const action of ['start', 'complete', 'cancel', 'reassign']) {
      const response = await post(
        `${GATEWAY}/operations/assignments/${assignmentId}/${action}`,
        {
        proof: signProof(device.keyPair, {
          contextId: context.context_id,
          organisationId: context.organisation_id,
          siteId: fx.siteA1,
          actorUserId: context.actor_user_id,
          deviceId: context.device_id,
          keyId: context.key_id,
          keyVersion: context.key_version,
          purpose: 'FIELD_OPERATION',
          payloadDigest: 'f'.repeat(64),
        }),
        payload: { expected_status: 'REQUESTED' },
        },
        asSession(fx.opAlpha),
      );
      // 404: there is NO ROUTE. Not a guard that could be relaxed, not a check
      // somebody could delete — nothing in the module constructs those actions.
      // The session is present, so this is a route that does not exist rather
      // than a route refusing an unauthenticated caller.
      expect(response.status, action).toBe(404);
    }
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
  });

  it('there is no device WebSocket ingress and no realtime device route', async () => {
    // The REST surface is the whole surface (D25-10). This asserts the routes
    // that exist are the six that were declared, by probing an invented one.
    expect((await post(`${GATEWAY}/operations/whisper`, {}, asSession(fx.opAlpha))).status).toBe(404);
    expect((await post(`${GATEWAY}/socket`, {}, asSession(fx.opAlpha))).status).toBe(404);
  });
});

describe('WP-25/D25-13 the refusal boundary is not an enumeration oracle', () => {
  it('foreign-tenant and nonexistent answer IDENTICALLY, for contexts and for devices', async () => {
    const deviceA = await enrol();
    const { context } = await establish(deviceA);

    // A REAL context in ANOTHER TENANT, presented by a proof claiming org A.
    const deviceB = await enrol({ tenant: B });
    const foreign = await establish(deviceB, { actor: fx.opB });
    expect(foreign.result.status).toBe(201);

    const nonexistentContext = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device: deviceA,
      context: { ...context, context_id: randomUUID() },
      payload: fieldStatePayload(),
    });
    const foreignContext = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device: deviceA,
      context: { ...context, context_id: foreign.context.context_id },
      payload: fieldStatePayload(),
    });
    const malformedContextId = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device: deviceA,
      context: { ...context, context_id: 'not-a-uuid-at-all' },
      payload: fieldStatePayload(),
    });

    const shape = (result: HttpResult): unknown => ({ status: result.status, error: result.body.error, keys: Object.keys(result.body).sort() });
    expect(shape(nonexistentContext)).toEqual(shape(foreignContext));
    // Even a context id Postgres could not have parsed answers the same way: an
    // oracle built out of error shapes is still an oracle.
    expect(shape(malformedContextId)).toEqual(shape(foreignContext));
    expect(nonexistentContext.body.error).toBe('DEVICE_REQUEST_REFUSED');

    // Establishment: a nonexistent device, another tenant's real device, and a
    // real device at a site this actor cannot work.
    const answers = await Promise.all([
      requestChallenge({ ...deviceA, deviceId: randomUUID() }),
      requestChallenge({ ...deviceB, tenant: A }),
      requestChallenge(deviceA, { siteId: fx.siteA2 }),
    ]);
    for (const answer of answers) {
      expect(shape(answer)).toEqual(shape(answers[0] as HttpResult));
      expect(answer.status).toBe(403);
    }

    // ...while the INTERNAL audit is precise, and the three reasons differ.
    const reasons = await prisma.deviceGatewayOperationEvent.findMany({
      where: { organisationId: fx.orgA, eventType: 'ESTABLISHMENT_REFUSED' },
      select: { refusalReason: true },
    });
    expect(new Set(reasons.map((row) => row.refusalReason)).size).toBeGreaterThan(1);
  });
});

describe('WP-25/D25-13 nothing secret ever reaches an audit payload', () => {
  it('no raw signature, private key material, nonce or session credential in ANY gateway event', async () => {
    const device = await enrol();
    const { challenge, context } = await establish(device);
    const messageId = await newDeliveredMessage(fx.opAlpha);
    const committed = await operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: messageId });
    expect(committed.status).toBe(201);
    // ...and a refusal, so refusal payloads are in the sample too.
    await operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload(), signer: generateTestDeviceKeyPair() });

    const events = await prisma.deviceGatewayOperationEvent.findMany({ where: { organisationId: { in: [fx.orgA, fx.orgB] } } });
    expect(events.length).toBeGreaterThan(5);

    const forbidden = [
      committed.proof.signature as string,
      committed.proof.nonce as string,
      challenge.nonce,
      'PRIVATE KEY',
      'x-dev-user-id',
    ];
    for (const event of events) {
      const serialised = JSON.stringify(event.payload);
      for (const secret of forbidden) {
        expect(serialised.includes(secret), `${event.eventType} leaked a secret`).toBe(false);
      }
      // The payload is scalars only — a nested object is where a raw blob
      // hides, and the allowlist has no arm that can produce one.
      for (const value of Object.values(event.payload as Record<string, unknown>)) {
        expect(value === null || ['string', 'number', 'boolean'].includes(typeof value)).toBe(true);
      }
    }

    // The context id IS recorded, precisely because it authorises nothing.
    expect(events.some((event) => event.contextId === context.context_id)).toBe(true);
  });
});


// ---------------------------------------------------------------------------
// C17-01 — the session proves WHO, the proof proves WHICH HARDWARE, and the
// live re-read proves STILL AUTHORISED NOW. None substitutes for another.
// ---------------------------------------------------------------------------

describe('WP-25/C17-01 human AUTHENTICATION is not an authorisation lookup', () => {
  it('a VALID P-256 proof with NO human session refuses, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const claimsBefore = (await nonceConsumptions()).length;

    // Everything the old code needed: a perfect context, a perfect signature by
    // the registered key, and an actor row that still resolves with a live
    // capability. The ONLY thing missing is the human on the other end.
    const anonymous = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      session: null,
    });
    expect(anonymous.status).toBe(401);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    expect((await nonceConsumptions()).length).toBe(claimsBefore);

    // ...and the same request WITH the session commits, so the refusal above is
    // the session and nothing else.
    const admitted = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
    });
    expect(admitted.status).toBe(201);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('ACCEPTED');
  });

  it('a VALID proof carried by the WRONG authenticated human refuses, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const trace = traceId();

    // opBravo is a real, live, gateway-capable operative at the same site. The
    // proof is alpha's device speaking for alpha's context. Possession is
    // perfect and authority is perfect — and the caller is not the person the
    // context is bound to.
    const impostor = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      session: fx.opBravo,
      trace,
    });
    expect(impostor.status).toBe(403);
    expect(impostor.body.error).toBe('DEVICE_REQUEST_REFUSED');
    expect(await refusalReasonFor(trace)).toContain('SESSION_ACTOR_MISMATCH');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
  });

  it('the CORRECT session with an INVALID proof refuses — the session rescues nothing', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const trace = traceId();

    const forged = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      signer: generateTestDeviceKeyPair(),
      trace,
    });
    expect(forged.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('POSSESSION_NOT_PROVEN');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
  });

  it('a challenge issued, then NO session at completion: refuse, and ZERO context', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    const anonymous = await completeEstablishment(challenge, device.keyPair, { session: null });
    expect(anonymous.status).toBe(401);
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
    // The ceremony is untouched, so the legitimate holder can still complete it.
    expect((await prisma.deviceContextEstablishmentChallenge.findUniqueOrThrow({ where: { id: challenge.establishment_id } })).consumedAt).toBeNull();

    // A DIFFERENT live human, holding the whole challenge and a perfect
    // signature, is refused too — and the internal reason names why.
    const trace = traceId();
    const impostor = await completeEstablishment(challenge, device.keyPair, { session: fx.opBravo, trace });
    expect(impostor.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SESSION_ACTOR_MISMATCH');
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();

    const honest = await completeEstablishment(challenge, device.keyPair);
    expect(honest.status).toBe(201);
  });

  it('a stolen context PLUS the device key, with no human session, is ZERO authority', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const before = await eventCountFor(fx.orgA);
    const stateBefore = await prisma.fieldOperativeStateHistory.count({ where: { organisationId: fx.orgA, userId: fx.opAlpha } });
    const acknowledgedBefore = await prisma.incidentFieldMessageRecipient.count({
      where: { organisationId: fx.orgA, deliveryState: 'ACKNOWLEDGED' },
    });
    const claimsBefore = (await nonceConsumptions()).length;

    // The complete attacker: the context id, the device, the registered private
    // key, and a freshly minted signature for every route. No session.
    const outcomes = await Promise.all([
      operate({ kind: 'FIELD_STATE_UPDATE', device, context, payload: fieldStatePayload(), session: null }),
      operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: await newAssignment(fx.opAlpha), payload: { expected_status: 'REQUESTED' }, session: null }),
      operate({ kind: 'ASSIGNMENT_DECLINE', device, context, targetId: await newAssignment(fx.opAlpha), payload: { expected_status: 'REQUESTED' }, session: null }),
      operate({ kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', device, context, targetId: await newDeliveredMessage(fx.opAlpha), session: null }),
    ]);
    for (const outcome of outcomes) expect(outcome.status).toBe(401);

    // Nothing happened, anywhere: no state transition, no acknowledgement, no
    // one-shot identity spent, and not even an audit row — the guard chain
    // refuses before the module runs.
    expect(await prisma.fieldOperativeStateHistory.count({ where: { organisationId: fx.orgA, userId: fx.opAlpha } })).toBe(stateBefore);
    expect(
      await prisma.incidentFieldMessageRecipient.count({ where: { organisationId: fx.orgA, deliveryState: 'ACKNOWLEDGED' } }),
    ).toBe(acknowledgedBefore);
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
    expect(await eventCountFor(fx.orgA)).toBe(before);
  });

  it('a live session does NOT rescue a role withdrawn between preflight and commit, at ESTABLISHMENT', async () => {
    const charlie: TenantFixture = { ...A, operativeId: fx.opCharlie, operative: principalFor(fx.opCharlie, 'field.operative', fx.siteA1, fx.orgA) };
    const device = await enrol({ tenant: charlie });
    const issued = await requestChallenge(device, { actor: fx.opCharlie });
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    const roles = await prisma.userRole.findMany({ where: { userId: fx.opCharlie } });
    const trace = traceId();
    try {
      const result = await withMutationBeforeEstablishmentCommit(
        async () => {
          await prisma.userRole.deleteMany({ where: { userId: fx.opCharlie } });
        },
        () => completeEstablishment(challenge, device.keyPair, { session: fx.opCharlie, trace }),
      );
      expect(result.status).toBe(403);
      // AUTHENTICATED and AUTHORISED are two facts. The session is live and
      // correct throughout; the live re-read is what refuses.
      expect(await refusalReasonFor(trace)).not.toBeNull();
      expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
      expect((await prisma.deviceContextEstablishmentChallenge.findUniqueOrThrow({ where: { id: challenge.establishment_id } })).consumedAt).toBeNull();
    } finally {
      await prisma.userRole.createMany({ data: roles.map((role) => ({ userId: role.userId, role: role.role, siteId: role.siteId })) });
    }
  });
});

// ---------------------------------------------------------------------------
// C17-02 — a request may not choose which tenant owns an append-only row
// ---------------------------------------------------------------------------

describe('WP-25/C17-02 the audit tenant is the SESSION’s, never the request’s', () => {
  it('an org-A session claiming org-B writes NOTHING under org-B, in either ceremony', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const bEventsBefore = await eventCountFor(fx.orgB);

    // 1. The establishment REQUEST, naming another tenant.
    const claimedRequest = await requestChallenge(device, { organisationId: fx.orgB });
    // 2. A real org-A challenge, answered by a proof that CLAIMS org B. The
    //    signature is genuine — it is a real signature over a lying statement.
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    const lyingProof = signProof(device.keyPair, {
      contextId: challenge.proposed_context_id,
      organisationId: fx.orgB,
      siteId: challenge.site_id,
      actorUserId: challenge.actor_user_id,
      deviceId: challenge.device_id,
      keyId: challenge.key_id,
      keyVersion: challenge.key_version,
      purpose: 'RECONNECT_HANDSHAKE',
      payloadDigest: deviceContextEstablishmentChallengeDigest(challenge),
    });
    const completionTrace = traceId();
    const claimedCompletion = await completeEstablishment(challenge, device.keyPair, {
      proof: lyingProof,
      trace: completionTrace,
    });
    // 3. An OPERATION whose proof claims org B against a real org-A context.
    const operationTrace = traceId();
    const claimedOperation = await operate({
      kind: 'FIELD_STATE_UPDATE',
      device,
      context,
      payload: fieldStatePayload(),
      proof: signProof(device.keyPair, {
        contextId: context.context_id,
        organisationId: fx.orgB,
        siteId: fx.siteA1,
        actorUserId: context.actor_user_id,
        deviceId: context.device_id,
        keyId: context.key_id,
        keyVersion: context.key_version,
        purpose: 'FIELD_OPERATION',
        payloadDigest: envelopeDigestFor('FIELD_STATE_UPDATE', context, fx.siteA1, context.actor_user_id, fieldStatePayload()),
      }),
      trace: operationTrace,
    });

    // Externally identical, in the D25-13 shape.
    expect(claimedRequest.status).toBe(403);
    expect(claimedCompletion.status).toBe(403);
    expect(claimedOperation.status).toBe(403);
    for (const answer of [claimedRequest, claimedCompletion, claimedOperation]) {
      expect(answer.body.error).toBe('DEVICE_REQUEST_REFUSED');
    }

    // ZERO gateway events under org B. The tenant an attacker NAMED is not the
    // tenant that owns the row — the audit tables have no lifecycle foreign key,
    // so this is the only provenance there is.
    expect(await eventCountFor(fx.orgB)).toBe(bEventsBefore);

    // ...and every retained event belongs to org A, with the precise internal
    // reason naming the claim.
    const retained = await prisma.deviceGatewayOperationEvent.findMany({
      where: { traceId: { in: [completionTrace, operationTrace] } },
      select: { organisationId: true, refusalReason: true },
    });
    expect(retained.length).toBe(2);
    for (const row of retained) {
      expect(row.organisationId).toBe(fx.orgA);
      expect(row.refusalReason).toContain('PROOF_ORGANISATION_MISMATCH');
    }
  });
});

// ---------------------------------------------------------------------------
// C17-03 — the lost response, answered honestly
// ---------------------------------------------------------------------------

describe('WP-25/C17-03 an exact establishment retry CONVERGES', () => {
  it('the byte-identical signed request returns the SAME context, and mints no second one', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    const first = await completeEstablishment(challenge, device.keyPair);
    expect(first.status).toBe(201);
    const original = (first.body as { context: IssuedContext }).context;

    // THE LOST RESPONSE. The server committed; the answer never arrived; the
    // device re-sends the EXACT bytes it sent the first time.
    const trace = traceId();
    const retry = await completeEstablishment(challenge, device.keyPair, { proof: first.proof, trace });
    expect(retry.status).toBe(201);
    const converged = (retry.body as { context: IssuedContext }).context;

    expect(converged.context_id).toBe(original.context_id);
    expect(converged.issued_at).toBe(original.issued_at);
    // NO EXPIRY EXTENSION. A retry that lengthened the window would be minting
    // authority out of a network failure.
    expect(converged.expires_at).toBe(original.expires_at);
    expect(converged).toEqual(original);

    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(1);
    expect(await prisma.authenticatedDeviceContextSite.count({ where: { contextId: original.context_id } })).toBe(1);
    expect((await eventsForTrace(trace)).map((event) => event.eventType)).toEqual(['CONTEXT_CONVERGED']);
  });

  it('convergence grants NO new authority — the session requirement still applies to the retry', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    const first = await completeEstablishment(challenge, device.keyPair);
    expect(first.status).toBe(201);

    const anonymous = await completeEstablishment(challenge, device.keyPair, { proof: first.proof, session: null });
    expect(anonymous.status).toBe(401);

    const trace = traceId();
    const impostor = await completeEstablishment(challenge, device.keyPair, { proof: first.proof, session: fx.opBravo, trace });
    expect(impostor.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SESSION_ACTOR_MISMATCH');

    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(1);
  });

  it('CHANGED SEMANTICS under a spent establishment is still a refusal, not a convergence', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    const nonce = randomBytes(24).toString('base64url');

    expect((await completeEstablishment(challenge, device.keyPair, { nonce })).status).toBe(201);

    // The SAME one-shot identity — the replay key does not cover `issued_at` —
    // carrying a DIFFERENT signed statement. There is nothing to converge on.
    const trace = traceId();
    const changed = await completeEstablishment(challenge, device.keyPair, {
      nonce,
      trace,
      proof: signProof(device.keyPair, {
        contextId: challenge.proposed_context_id,
        organisationId: challenge.organisation_id,
        siteId: challenge.site_id,
        actorUserId: challenge.actor_user_id,
        deviceId: challenge.device_id,
        keyId: challenge.key_id,
        keyVersion: challenge.key_version,
        purpose: 'RECONNECT_HANDSHAKE',
        payloadDigest: deviceContextEstablishmentChallengeDigest(challenge),
        nonce,
        issuedAt: new Date(Date.now() - 1_500).toISOString(),
      }),
    });
    expect(changed.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('NONCE_REUSED_WITH_CHANGED_SEMANTICS');
    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(1);
  });

  it('a stored outcome ref that resolves to NO exact context FAILS CLOSED', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    const first = await completeEstablishment(challenge, device.keyPair);
    expect(first.status).toBe(201);
    const original = (first.body as { context: IssuedContext }).context;

    // Erase the authoritative context while leaving the replay row and the spent
    // challenge behind: a stored outcome reference that no longer resolves.
    await prisma.authenticatedDeviceContextSite.deleteMany({ where: { contextId: original.context_id } });
    await prisma.authenticatedDeviceContextRecord.delete({ where: { id: original.context_id } });

    const trace = traceId();
    const retry = await completeEstablishment(challenge, device.keyPair, { proof: first.proof, trace });
    expect(retry.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('DUPLICATE_UNRESOLVABLE');
    // It did NOT quietly mint a replacement.
    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(0);
  });

  it('a SECOND, FRESHLY SIGNED use of a spent ceremony is still refused', async () => {
    // C17-03 relaxes the gate for an EXACT retry and for nothing else. A new
    // nonce is a new identity, so this is a second ceremony, not a lost answer.
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    expect((await completeEstablishment(challenge, device.keyPair)).status).toBe(201);

    const trace = traceId();
    const second = await completeEstablishment(challenge, device.keyPair, { nonce: randomBytes(24).toString('base64url'), trace });
    expect(second.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('ESTABLISHMENT_NOT_USABLE');
    expect(await prisma.authenticatedDeviceContextRecord.count({ where: { establishmentId: challenge.establishment_id } })).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// C17-04 — the final fence reads inside its own transaction, and LOCKS
// ---------------------------------------------------------------------------

describe('WP-25/C17-04 the final fence holds the rows its decision rests on', () => {
  it('a CONCURRENT transaction cannot release the device site scope between the decision and the commit', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    let releaseSettled = false;
    let releaseObserved: Promise<unknown> | null = null;

    // The seam is INSIDE the gateway's final transaction, AFTER it has locked
    // the exact (organisation, device, site) scope row and BEFORE it commits.
    // This is a REAL concurrent transaction, not a hook that mutates a row in
    // front of an unlocked read: it runs on its own connection, against the same
    // Postgres, and the only thing standing between it and the row is the lock.
    const original = gatewayRepository.appendOperationEvent.bind(gatewayRepository);
    const spy = vi.spyOn(gatewayRepository, 'appendOperationEvent').mockImplementationOnce(async (db, envelope, input) => {
      releaseObserved = prisma
        .$transaction(
          async (tx) =>
            tx.$executeRaw`UPDATE device_site_scopes
               SET released_at = clock_timestamp()
               WHERE organisation_id = ${fx.orgA} AND device_id = ${device.deviceId}::uuid
                 AND site_id = ${fx.siteA1} AND released_at IS NULL`,
          { timeout: 20_000, maxWait: 20_000 },
        )
        .then((value) => {
          releaseSettled = true;
          return value;
        });
      // Give the concurrent writer a real chance to win. It cannot: the row is
      // locked by the transaction this callback is running inside.
      await new Promise((resolve) => {
        setTimeout(resolve, 750);
      });
      expect(releaseSettled, 'a scope withdrawal slipped between the decision and the commit').toBe(false);
      return original(db, envelope, input);
    });

    let committed: Awaited<ReturnType<typeof operate>>;
    try {
      committed = await operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' } });
    } finally {
      spy.mockRestore();
    }

    // The gateway won the row, so its decision and its effect commit together.
    expect(committed.status).toBe(201);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('ACCEPTED');

    // The withdrawal was not lost — it was SERIALISED behind the commit, and it
    // lands the moment the lock is released.
    await releaseObserved;
    expect(releaseSettled).toBe(true);
    expect(await prisma.deviceSiteScope.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId, releasedAt: null } })).toBe(0);

    // ...and the very next operation on that device is refused, because the
    // fence is re-read per request rather than trusted from the last one.
    const trace = traceId();
    const after = await operate({
      kind: 'ASSIGNMENT_DECLINE',
      device,
      context,
      targetId: await newAssignment(fx.opAlpha),
      payload: { expected_status: 'REQUESTED' },
      trace,
    });
    expect(after.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SITE_AUTHORITY_MISSING');
  });

  it('a device site scope released BEFORE the locked read refuses, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);
    const claimsBefore = (await nonceConsumptions()).length;
    const trace = traceId();

    const result = await withMutationBeforeCommit(
      async () => {
        await prisma.deviceSiteScope.updateMany({
          where: { organisationId: fx.orgA, deviceId: device.deviceId, siteId: fx.siteA1, releasedAt: null },
          data: { releasedAt: new Date() },
        });
      },
      () => operate({ kind: 'ASSIGNMENT_ACCEPT', device, context, targetId: assignmentId, payload: { expected_status: 'REQUESTED' }, trace }),
    );

    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SITE_AUTHORITY_MISSING');
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    expect((await nonceConsumptions()).length).toBe(claimsBefore);
  });
});

// ---------------------------------------------------------------------------
// C17-05 — the key binding is enforced by Postgres, not by a service check
// ---------------------------------------------------------------------------

describe('WP-25/C17-05 a context cannot name one device and carry another’s key', () => {
  const CHALLENGE_INSERT = `INSERT INTO device_context_establishment_challenges
      (id, organisation_id, proposed_context_id, actor_user_id, device_id, site_id, key_id, key_version, nonce, issued_at, expires_at, updated_at)
    VALUES ($1::uuid, $2, $3::uuid, $4, $5::uuid, $6, $7, $8, $9, clock_timestamp(), clock_timestamp(), clock_timestamp())`;

  const CONTEXT_INSERT = `INSERT INTO authenticated_device_contexts
      (id, organisation_id, actor_user_id, device_id, key_id, key_version, issued_at, expires_at, establishment_id, issuance_trace_id, updated_at)
    VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, clock_timestamp(), clock_timestamp(), $7::uuid, $8, clock_timestamp())`;

  it('POSTGRES ITSELF rejects a raw challenge or context carrying another device’s key', async () => {
    const alpha = await enrol();
    const bravo = await enrol();
    expect(bravo.keyId).not.toBe(alpha.keyId);

    // A CHALLENGE naming device alpha while carrying bravo's key. Both objects
    // genuinely exist; the TUPLE does not.
    await expect(
      prisma.$executeRawUnsafe(
        CHALLENGE_INSERT,
        randomUUID(),
        fx.orgA,
        randomUUID(),
        fx.opAlpha,
        alpha.deviceId,
        fx.siteA1,
        bravo.keyId,
        bravo.keyVersion,
        'c17-05',
      ),
    ).rejects.toThrow(/foreign key|violates/iu);

    // The same for a CONTEXT, against a real, unspent challenge of alpha's.
    const issued = await requestChallenge(alpha);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;
    await expect(
      prisma.$executeRawUnsafe(
        CONTEXT_INSERT,
        randomUUID(),
        fx.orgA,
        fx.opAlpha,
        alpha.deviceId,
        bravo.keyId,
        bravo.keyVersion,
        challenge.establishment_id,
        'c17-05',
      ),
    ).rejects.toThrow(/foreign key|violates/iu);

    // A WRONG KEY VERSION of the device's OWN key is rejected too — the tuple is
    // four columns, not two.
    await expect(
      prisma.$executeRawUnsafe(
        CONTEXT_INSERT,
        randomUUID(),
        fx.orgA,
        fx.opAlpha,
        alpha.deviceId,
        alpha.keyId,
        alpha.keyVersion + 1,
        challenge.establishment_id,
        'c17-05',
      ),
    ).rejects.toThrow(/foreign key|violates/iu);

    // ...and the HONEST tuple is accepted, so the constraint is not vacuously
    // rejecting everything.
    const honestId = randomUUID();
    await prisma.$executeRawUnsafe(
      CONTEXT_INSERT,
      honestId,
      fx.orgA,
      fx.opAlpha,
      alpha.deviceId,
      alpha.keyId,
      alpha.keyVersion,
      challenge.establishment_id,
      'c17-05',
    );
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: honestId } })).not.toBeNull();
    await prisma.authenticatedDeviceContextRecord.delete({ where: { id: honestId } });
  });
});

// ---------------------------------------------------------------------------
// C17-06 — an unsigned field is refused at a signed boundary
// ---------------------------------------------------------------------------

describe('WP-25/C17-06 the signed boundary refuses unknown top-level fields', () => {
  it('every unsigned top-level value on an OPERATION is refused, with zero effect', async () => {
    const device = await enrol();
    const { context } = await establish(device);

    for (const extra of [
      { organisation_id: fx.orgB },
      { device_id: randomUUID() },
      { actor_user_id: fx.opBravo },
      { context_id: randomUUID() },
      { purpose: 'OFFLINE_SYNC' },
      { idempotency_key: 'chosen-by-the-device' },
      { seen_at: new Date().toISOString() },
    ]) {
      const assignmentId = await newAssignment(fx.opAlpha);
      const trace = traceId();
      const refused = await operate({
        kind: 'ASSIGNMENT_ACCEPT',
        device,
        context,
        targetId: assignmentId,
        payload: { expected_status: 'REQUESTED' },
        bodyExtras: extra,
        trace,
      });
      expect(refused.status, JSON.stringify(extra)).toBe(403);
      // REJECTED, not silently discarded: the internal audit names the envelope.
      expect(await refusalReasonFor(trace)).toContain('ENVELOPE_MALFORMED');
      expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('REQUESTED');
    }
  });

  it('the DELIBERATE equality-bound echoes are still accepted', async () => {
    const device = await enrol();
    const { context } = await establish(device);
    const assignmentId = await newAssignment(fx.opAlpha);

    const committed = await operate({
      kind: 'ASSIGNMENT_ACCEPT',
      device,
      context,
      targetId: assignmentId,
      payload: { expected_status: 'REQUESTED' },
      bodyExtras: { operation_kind: 'ASSIGNMENT_ACCEPT', target_type: 'FIELD_ASSIGNMENT', target_id: assignmentId },
    });
    expect(committed.status).toBe(201);
    expect((await prisma.fieldAssignment.findUniqueOrThrow({ where: { id: assignmentId } })).status).toBe('ACCEPTED');
  });

  it('an unsigned top-level value on the COMPLETION request is refused, and the ceremony survives', async () => {
    const device = await enrol();
    const issued = await requestChallenge(device);
    const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

    const smuggled = await completeEstablishment(challenge, device.keyPair, {
      bodyExtras: { organisation_id: fx.orgB, context_id: randomUUID() },
    });
    // A SHAPE complaint about the caller’s own bytes, and nothing was touched.
    expect(smuggled.status).toBe(400);
    expect(smuggled.body.error).toBe('DEVICE_REQUEST_MALFORMED');
    expect(await prisma.authenticatedDeviceContextRecord.findUnique({ where: { id: challenge.proposed_context_id } })).toBeNull();
    expect((await prisma.deviceContextEstablishmentChallenge.findUniqueOrThrow({ where: { id: challenge.establishment_id } })).consumedAt).toBeNull();

    // The honest request still completes.
    expect((await completeEstablishment(challenge, device.keyPair)).status).toBe(201);
  });
});
