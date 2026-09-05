import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  WHISPER_DEVICE_ACTION_V2_PROFILE,
  canonicalDevicePossessionStatement,
  canonicalDeviceRequestProofStatement,
  canonicalWhisperDeviceActionV2Statement,
  deriveP256PublicKeyThumbprint,
  whisperDeviceActionV2Fingerprint,
  whisperDeviceActionV2ReplayKey,
  whisperDeviceActionV2StatementInput,
  type DeviceAttestationOutcome,
  type DeviceKeyStorage,
  type DeviceRequestPurpose,
} from '@sentinel/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { GlobalExceptionFilter } from '../../common/global-exception.filter';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { traceIdMiddleware } from '../../common/trace-id.middleware';
import { GlobalValidationPipe } from '../../common/validation.pipe';
import { PrismaService } from '../../prisma/prisma.service';
import { deviceContextEstablishmentChallengeDigest, type DeviceContextEstablishmentChallengeView } from '../device-gateway/device-context.challenge';
import { DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND, deviceGatewayEnvelopeDigest } from '../device-gateway/device-gateway.envelope';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { DEVICE_ATTESTATION_EVALUATOR } from '../shield/attestation.evaluator';
import { DeviceEnrollmentService } from '../shield/device-enrollment.service';
import { DeviceTrustService } from '../shield/device-trust.service';
import {
  SettableDeviceAttestationEvaluator,
  generateTestDeviceKeyPair,
  signCanonicalStatement,
  type TestDeviceKeyPair,
} from '../shield/shield.test-support';
import { WHISPER_DEVICE_ACTION_V2_CEREMONY } from './whisper-device-action.constants';

/**
 * ============================================================================
 * WP-27 — THE V2 DEVICE-ACTION BOUNDARY, DRIVEN OVER REAL HTTP.
 *
 * Through the REAL module graph (AppModule), the REAL global guard chain, the
 * REAL WP-25 gateway pipeline, the REAL Shield registry and enrollment
 * ceremony, the REAL P-256 verifier and the REAL Postgres constraints. Nothing
 * below stubs a security decision; the only injected seam is WP-24's
 * attestation evaluator, a token swap the registry already owns.
 *
 * THIS IS NOT PROOF C, AND NOTHING HERE MAY BE READ AS IT.
 *
 * EVERY "DEVICE" BELOW IS A P-256 KEYPAIR THIS TEST PROCESS GENERATED. There is
 * no hardware, no hardware-backed key store, no attestation vendor and no
 * mobile client. A passing test proves that the v2 boundary authenticates a
 * holder of a registered private key and refuses everyone else; it proves
 * nothing whatever about a physical device.
 *
 * WHAT AN ACCEPTED REQUEST HERE MEANS, PRECISELY
 * ----------------------------------------------
 * The statement is AUTHENTIC under the registered key, BOUND to the
 * server-established context, FRESH against the server clock, and its one-shot
 * identity is now SPENT. It is NOT a recognition, NOT an eligibility verdict
 * and NOT a dispatch: no Whisper signal is resolved, no roster consulted, no
 * threshold compared and no response protocol entered. The frozen v1 runtime
 * owns all of that and is untouched by this suite.
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

const tag = `wp27_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const GATEWAY = '/api/v1/device-gateway';
const DEVICE_ACTION_ROUTE = `${GATEWAY}/operations/device-action`;

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
  cmdIssuerB: `${tag}_cmdIssuerB`,
  cmdApproverB: `${tag}_cmdApproverB`,
  opB: `${tag}_opB`,
};

let app: INestApplication;
let base: string;
let prisma: PrismaService;
let enrollment: DeviceEnrollmentService;
let trust: DeviceTrustService;
let attestation: SettableDeviceAttestationEvaluator;

function principalFor(userId: string, role: string, siteId: string | null, organisationId: string): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 5 }, organisation_id: organisationId, roles: [{ role, site_id: siteId }] });
}

const traceId = (): string => `trace-${randomUUID()}`;

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

async function seed(): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-27 Org A' },
      { id: fx.orgB, name: 'WP-27 Org B' },
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
    { id: fx.cmdIssuerB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.cmdApproverB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.opB, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });
}

async function cleanup(): Promise<void> {
  const organisationId = { in: [fx.orgA, fx.orgB] };
  await prisma.deviceGatewayOperationEvent.deleteMany({ where: { organisationId } });
  await prisma.authenticatedDeviceContextSite.deleteMany({ where: { organisationId } });
  await prisma.authenticatedDeviceContextRecord.deleteMany({ where: { organisationId } });
  await prisma.deviceContextEstablishmentChallenge.deleteMany({ where: { organisationId } });
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

beforeAll(async () => {
  for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
  attestation = new SettableDeviceAttestationEvaluator();
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(PATROL_SWEEP_SCHEDULER)
    .useClass(NoopPatrolSweepScheduler)
    .overrideProvider(DEVICE_ATTESTATION_EVALUATOR)
    .useValue(attestation)
    .compile();

  app = moduleRef.createNestApplication();
  app.use(traceIdMiddleware);
  app.useGlobalPipes(new GlobalValidationPipe());
  app.useGlobalFilters(new GlobalExceptionFilter());
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  base = `http://127.0.0.1:${typeof address === 'object' && address !== null ? address.port : 0}`;

  prisma = app.get(PrismaService);
  enrollment = app.get(DeviceEnrollmentService);
  trust = app.get(DeviceTrustService);

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

async function refusalReasonFor(trace: string): Promise<string | null> {
  const rows = await prisma.deviceGatewayOperationEvent.findMany({ where: { traceId: trace }, orderBy: { createdAt: 'asc' } });
  return rows.at(-1)?.refusalReason ?? null;
}

async function eventsForTrace(trace: string): Promise<Array<{ eventType: string; outcome: string; payload: unknown }>> {
  const rows = await prisma.deviceGatewayOperationEvent.findMany({ where: { traceId: trace }, orderBy: { createdAt: 'asc' } });
  return rows.map((row) => ({ eventType: row.eventType, outcome: row.outcome, payload: row.payload }));
}

/**
 * Every one-shot identity WP-27 has spent, filtered to its OWN ceremony label.
 *
 * Shield's enrollment, rotation and the WP-25 gateway all spend identities in
 * the SAME store (there is no second replay subsystem), so an unfiltered count
 * would move whenever a fixture enrolled a device and would be measuring the
 * wrong thing.
 */
async function deviceActionConsumptions(): Promise<Array<{ replayIdentityDigest: string; statementFingerprint: string; storedOutcomeRef: string | null }>> {
  const rows = await prisma.deviceNonceConsumption.findMany({
    where: { organisationId: { in: [fx.orgA, fx.orgB] }, ceremony: WHISPER_DEVICE_ACTION_V2_CEREMONY },
  });
  return rows.map((row) => ({
    replayIdentityDigest: row.replayIdentityDigest,
    statementFingerprint: row.statementFingerprint,
    storedOutcomeRef: row.storedOutcomeRef,
  }));
}

// ---------------------------------------------------------------------------
// Enrollment and establishment — the real ceremonies
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
  options: { tenant?: TenantFixture; keyStorage?: DeviceKeyStorage; attestationOutcome?: DeviceAttestationOutcome } = {},
): Promise<EnrolledDevice> {
  const tenant = options.tenant ?? A;
  const keyPair = generateTestDeviceKeyPair();
  // A device-action statement requires TRUSTED and nothing less (W21-05), so
  // the fixture enrols with real positive attestation evidence rather than
  // arranging trust after the fact.
  attestation.outcome = options.attestationOutcome ?? 'VERIFIED';

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
    claimedSignatureProfile: WHISPER_DEVICE_ACTION_V2_PROFILE,
    custodyRegimeId: null,
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
    signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
  });
  await enrollment.verifyPossession({
    organisationId: tenant.organisationId,
    enrollmentRequestId: request.enrollmentRequestId,
    challengeId: challenge.challengeId,
    response: {
      schema_version: 1,
      challenge_id: challenge.challengeId,
      enrollment_request_id: request.enrollmentRequestId,
      claimed_signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
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

  return { deviceId: committed.deviceId, keyId: committed.keyId, keyVersion: committed.keyVersion, trust: committed.trust, keyPair, tenant };
}

/** The frozen `DeviceRequestProof`, signed exactly as a conforming device signs it. */
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
    issued_at: new Date().toISOString(),
  };
  const statement = canonicalDeviceRequestProofStatement({ ...proof, signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE });
  return {
    ...proof,
    claimed_signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
    signature: signCanonicalStatement(keyPair.privateKey, statement),
  };
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

async function establish(device: EnrolledDevice, options: { actor?: string } = {}): Promise<IssuedContext> {
  const issued = await post(
    `${GATEWAY}/contexts/establishment`,
    { organisation_id: device.tenant.organisationId, device_id: device.deviceId, site_id: device.tenant.siteId },
    asSession(options.actor ?? device.tenant.operativeId),
  );
  expect(issued.status, JSON.stringify(issued.body)).toBe(201);
  const challenge = (issued.body as { challenge: DeviceContextEstablishmentChallengeView }).challenge;

  const proof = signProof(device.keyPair, {
    contextId: challenge.proposed_context_id,
    organisationId: challenge.organisation_id,
    siteId: challenge.site_id,
    actorUserId: challenge.actor_user_id,
    deviceId: challenge.device_id,
    keyId: challenge.key_id,
    keyVersion: challenge.key_version,
    purpose: 'RECONNECT_HANDSHAKE',
    payloadDigest: deviceContextEstablishmentChallengeDigest(challenge),
  });
  const completed = await post(
    `${GATEWAY}/contexts`,
    { establishment_id: challenge.establishment_id, proof },
    asSession(options.actor ?? device.tenant.operativeId),
  );
  expect(completed.status, JSON.stringify(completed.body)).toBe(201);
  return (completed.body as { context: IssuedContext }).context;
}

// ---------------------------------------------------------------------------
// What a CONFORMING DEVICE does — the v2 client half, written out in the open
// ---------------------------------------------------------------------------

interface DeviceActionClaimsInput {
  keyId: string;
  keyVersion: number;
  whisperSignalId?: string;
  whisperSignalVersion?: number;
  deviceActionId?: string;
  recognisedAt?: string;
  confidence?: number;
  nonce?: string;
}

/** The identity the SERVER will resolve. A conforming client reproduces it; it never sends it. */
interface StatementIdentity {
  context_id: string;
  organisation_id: string;
  site_id: string;
  actor_user_id: string;
  device_id: string;
}

function identityOf(context: IssuedContext, siteId?: string): StatementIdentity {
  return {
    context_id: context.context_id,
    organisation_id: context.organisation_id,
    site_id: siteId ?? (context.authorised_site_ids[0] as string),
    actor_user_id: context.actor_user_id,
    device_id: context.device_id,
  };
}

function rawClaims(input: DeviceActionClaimsInput): Record<string, unknown> {
  return {
    schema_version: 2,
    key_id: input.keyId,
    key_version: input.keyVersion,
    whisper_signal_id: input.whisperSignalId ?? `${tag}-signal`,
    whisper_signal_version: input.whisperSignalVersion ?? 1,
    modality: 'DEVICE_ACTION',
    device_action_id: input.deviceActionId ?? `${tag}-action`,
    recognised_at: input.recognisedAt ?? new Date().toISOString(),
    confidence: input.confidence ?? 0.93,
    anti_replay_nonce: input.nonce ?? `${tag}-${randomBytes(12).toString('base64url')}`,
  };
}

/**
 * Signs the v2 statement the way a conforming device does: the CONTRACT's
 * canonical bytes, with the SERVER's signature profile — which the client knows
 * implicitly from its own key and NEVER sends.
 */
function signClaims(
  signer: TestDeviceKeyPair,
  identity: StatementIdentity,
  claims: Record<string, unknown>,
  overrides: { signOver?: string } = {},
): Record<string, unknown> {
  const message =
    overrides.signOver ??
    canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(
        { ...identity, ...claims, signature: 'placeholder' } as never,
        WHISPER_DEVICE_ACTION_V2_PROFILE,
      ),
    );
  return { ...claims, signature: signCanonicalStatement(signer.privateKey, message) };
}

interface DeviceActionRequest {
  device: EnrolledDevice;
  context: IssuedContext;
  /** The exact payload posted. Built by `signClaims` unless a case overrides it. */
  payload: Record<string, unknown>;
  siteId?: string;
  /** The key the TRANSPORT proof is signed with. Defaults to the device's own. */
  proofSigner?: TestDeviceKeyPair;
  purpose?: DeviceRequestPurpose;
  proof?: Record<string, unknown>;
  session?: string | null;
  trace?: string;
}

/**
 * Posts a device-action operation.
 *
 * The transport proof is minted over the digest of the FINAL payload, so the
 * WP-25 layer is satisfied and every assertion below is about the WP-27 layer.
 * Where a case wants the transport layer to refuse instead, it supplies its own
 * `proof`.
 */
async function deviceAction(request: DeviceActionRequest): Promise<HttpResult & { proof: Record<string, unknown> }> {
  const siteId = request.siteId ?? (request.context.authorised_site_ids[0] as string);
  const digest = deviceGatewayEnvelopeDigest({
    schema_version: 1,
    operation_kind: 'DEVICE_ACTION',
    organisation_id: request.context.organisation_id,
    site_id: siteId,
    actor_user_id: request.context.actor_user_id,
    device_id: request.context.device_id,
    target_type: DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND.DEVICE_ACTION,
    target_id: request.context.actor_user_id,
    semantic_payload: request.payload,
  });
  const proof =
    request.proof ??
    signProof(request.proofSigner ?? request.device.keyPair, {
      contextId: request.context.context_id,
      organisationId: request.context.organisation_id,
      siteId,
      actorUserId: request.context.actor_user_id,
      deviceId: request.context.device_id,
      keyId: request.context.key_id,
      keyVersion: request.context.key_version,
      purpose: request.purpose ?? 'WHISPER_DEVICE_ACTION',
      payloadDigest: digest,
    });
  const session = request.session === undefined ? request.context.actor_user_id : request.session;
  const result = await post(
    DEVICE_ACTION_ROUTE,
    { proof, payload: request.payload },
    {
      ...(request.trace === undefined ? {} : { 'x-trace-id': request.trace }),
      ...(session === null ? {} : asSession(session)),
    },
  );
  return { ...result, proof };
}

/** The conforming happy path, in one call. */
async function conformingPayload(device: EnrolledDevice, context: IssuedContext, input: Partial<DeviceActionClaimsInput> = {}): Promise<Record<string, unknown>> {
  const claims = rawClaims({ keyId: context.key_id, keyVersion: context.key_version, ...input });
  return signClaims(device.keyPair, identityOf(context), claims);
}

// ===========================================================================
// ACCEPT
// ===========================================================================

describe('WP-27 a valid P-256 signed canonical v2 statement is ACCEPTED', () => {
  it('commits, spends exactly one v2 one-shot identity, and audits without secrets', async () => {
    const device = await enrol();
    expect(device.trust).toBe('TRUSTED');
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });

    expect(result.status, JSON.stringify(result.body)).toBe(201);
    expect(result.body.outcome).toBe('COMMITTED');
    expect(result.body.operation_kind).toBe('DEVICE_ACTION');
    expect(result.body.target_type).toBe('DEVICE_ACTION_STATEMENT');
    // The target is the OPERATIVE. No Whisper signal identifier appears in the
    // route, the response envelope or the audit row.
    expect(result.body.target_id).toBe(context.actor_user_id);

    const view = result.body.result as Record<string, unknown>;
    expect(view.outcome).toBe('VERIFIED_STATEMENT');
    expect(view.source).toBe('SENTINEL_SERVER_VERIFICATION');
    expect(view.signature_profile).toBe(WHISPER_DEVICE_ACTION_V2_PROFILE);
    expect(view.device_trust).toBe('TRUSTED');
    expect(view.refusal).toBeNull();
    // The verdict carries WHAT it is about, so it cannot be borrowed.
    expect(view.context_id).toBe(context.context_id);
    expect(view.device_id).toBe(context.device_id);
    expect(view.key_version).toBe(context.key_version);

    // EXACTLY ONE new v2 identity, on the exact statement bytes.
    const after = await deviceActionConsumptions();
    expect(after.length).toBe(before + 1);
    const expectedFingerprint = whisperDeviceActionV2Fingerprint(
      whisperDeviceActionV2StatementInput({ ...identityOf(context), ...payload } as never, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    expect(after.some((row) => row.statementFingerprint === expectedFingerprint)).toBe(true);
    expect(view.statement_fingerprint).toBe(expectedFingerprint);

    // D25-13: no signature, no key and NO NONCE in any audit payload.
    const events = await eventsForTrace(trace);
    expect(events.map((event) => event.eventType)).toEqual(['OPERATION_COMMITTED']);
    const serialised = JSON.stringify(events);
    expect(serialised).not.toContain(payload.signature as string);
    expect(serialised).not.toContain(payload.anti_replay_nonce as string);
    expect(serialised).not.toContain(device.keyPair.publicKey);
  }, 180_000);
});

// ===========================================================================
// REJECT — the statement itself
// ===========================================================================

describe('WP-27 a statement that is not what the key signed is REJECTED', () => {
  it('statement ALTERED AFTER SIGNING -> refused, no v2 identity spent', async () => {
    const device = await enrol();
    const context = await establish(device);
    const signed = await conformingPayload(device, context);
    // The transport proof below is minted over the ALTERED payload, so WP-25 is
    // satisfied and the refusal is WP-27's: the signature covers bytes that no
    // longer describe this request.
    const altered = { ...signed, confidence: 0.11 };
    const before = (await deviceActionConsumptions()).length;

    const trace = traceId();
    const result = await deviceAction({ device, context, payload: altered, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SIGNATURE_INVALID');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a VALID SIGNATURE OVER NON-CANONICAL BYTES is refused', async () => {
    const device = await enrol();
    const context = await establish(device);
    const identity = identityOf(context);
    const claims = rawClaims({ keyId: context.key_id, keyVersion: context.key_version });
    // Same fields, same values — but serialised with the keys in insertion
    // order rather than sorted, and without the canonicaliser. It is a
    // genuinely valid ECDSA signature by the registered key over bytes the
    // server will never reproduce.
    const nonCanonical = JSON.stringify({ domain: 'sentinel.whisper.device-action.v2', ...identity, ...claims });
    const payload = signClaims(device.keyPair, identity, claims, { signOver: nonCanonical });
    const before = (await deviceActionConsumptions()).length;

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SIGNATURE_INVALID');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a MALFORMED ECDSA signature never reaches a verifier', async () => {
    const device = await enrol();
    const context = await establish(device);
    const signed = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    // Padded, truncated, DER-shaped and non-base64url values are refused by the
    // BRANDED contract schema at the envelope parse — before a key is touched.
    for (const bad of [`${signed.signature as string}=`, (signed.signature as string).slice(0, 40), 'MEUCIQDnot-canonical', '']) {
      const trace = traceId();
      const result = await deviceAction({ device, context, payload: { ...signed, signature: bad }, trace });
      // D25-13: the boundary is not an enumeration oracle, so EVERY operation
      // refusal — a shape complaint included — leaves as the same 403. The
      // precise reason goes to the internal audit and nowhere else.
      expect(result.status, `signature ${JSON.stringify(bad)}`).toBe(403);
      expect(await refusalReasonFor(trace)).toBe('ENVELOPE_MALFORMED');
    }
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a payload naming an ALGORITHM or PROFILE is refused — the client never names one', async () => {
    const device = await enrol();
    const context = await establish(device);
    const signed = await conformingPayload(device, context);

    for (const field of ['signature_algorithm', 'signature_profile', 'curve', 'hash_algorithm']) {
      const trace = traceId();
      const result = await deviceAction({ device, context, payload: { ...signed, [field]: 'P256_ECDSA_SHA256' }, trace });
      expect(result.status, field).toBe(403);
      expect(await refusalReasonFor(trace)).toBe('ENVELOPE_MALFORMED');
    }
  }, 180_000);

  it('a v1-SHAPED result cannot be presented on the v2 path', async () => {
    const device = await enrol();
    const context = await establish(device);
    const signed = await conformingPayload(device, context);
    const trace = traceId();
    // Deterministic dispatch: `schema_version` decides, and nothing probes.
    const result = await deviceAction({ device, context, payload: { ...signed, schema_version: 1 }, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toBe('ENVELOPE_MALFORMED');
  }, 180_000);
});

// ===========================================================================
// REJECT — the bindings
// ===========================================================================

describe('WP-27 every binding is REJECTED when it disagrees with the server', () => {
  it('device_id, key_id and key_version, each altered on its own', async () => {
    const device = await enrol();
    const other = await enrol();
    const context = await establish(device);
    const before = (await deviceActionConsumptions()).length;

    const cases: Array<[string, Record<string, unknown>]> = [
      ['key_id', { keyId: other.keyId }],
      ['key_version', { keyVersion: context.key_version + 1 }],
    ];
    for (const [name, override] of cases) {
      const claims = rawClaims({ keyId: context.key_id, keyVersion: context.key_version, ...override });
      // Signed over the ALTERED claims, so this is not a signature failure: the
      // device genuinely attests to a key it is not using.
      const payload = signClaims(device.keyPair, identityOf(context), claims);
      const trace = traceId();
      const result = await deviceAction({ device, context, payload, trace });
      expect(result.status, name).toBe(403);
      expect(await refusalReasonFor(trace), name).toMatch(/CONTEXT_KEY_MISMATCH|KEY_VERSION_ROTATED/u);
    }

    // `device_id` is not a payload field at all — it is ENVELOPE identity,
    // resolved from the persisted context. Presenting one is refused as an
    // unknown key rather than accepted and ignored.
    const trace = traceId();
    const signed = await conformingPayload(device, context);
    const result = await deviceAction({ device, context, payload: { ...signed, device_id: other.deviceId }, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toBe('ENVELOPE_MALFORMED');

    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('the WRONG REGISTERED PUBLIC KEY — a statement signed by another device', async () => {
    const device = await enrol();
    const impostor = await enrol();
    const context = await establish(device);
    const before = (await deviceActionConsumptions()).length;

    // The TRANSPORT proof is the real device's, so WP-25 admits the request.
    // The v2 statement is signed by a different registered device's key, and
    // the registry resolves the key by THIS device's own pointer — so there is
    // no key to fall back to and the verification simply fails.
    const claims = rawClaims({ keyId: context.key_id, keyVersion: context.key_version });
    const payload = signClaims(impostor.keyPair, identityOf(context), claims);

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SIGNATURE_INVALID');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a WRONG DEVICE/KEY ASSOCIATION — this device, another device’s key id', async () => {
    const device = await enrol();
    const other = await enrol();
    const context = await establish(device);
    const claims = rawClaims({ keyId: other.keyId, keyVersion: other.keyVersion });
    const payload = signClaims(device.keyPair, identityOf(context), claims);

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('CONTEXT_KEY_MISMATCH');
  }, 180_000);

  it('CROSS-SITE: a site the context was not issued for', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const trace = traceId();
    // `siteA2` is a real site in the same tenant that this context does not
    // cover. WP-25's own binding refuses first, which is the correct ordering:
    // the site is envelope identity, not a signed claim the device may propose.
    const result = await deviceAction({ device, context, payload, siteId: fx.siteA2, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toMatch(/CONTEXT_SITE_NOT_AUTHORISED|SITE_NOT_USABLE|PROOF_REFUSED/u);
  }, 180_000);

  it('CROSS-ORGANISATION: another tenant’s device, another tenant’s context', async () => {
    const deviceA = await enrol();
    const deviceB = await enrol({ tenant: B });
    const contextA = await establish(deviceA);
    const contextB = await establish(deviceB);
    const before = (await deviceActionConsumptions()).length;

    // Tenant B's device signs a statement naming tenant A's identity, and
    // presents it under tenant A's session. Nothing about it resolves.
    const claims = rawClaims({ keyId: contextA.key_id, keyVersion: contextA.key_version });
    const payload = signClaims(deviceB.keyPair, identityOf(contextA), claims);
    const trace = traceId();
    const result = await deviceAction({ device: deviceA, context: contextA, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('SIGNATURE_INVALID');

    // And tenant B's OWN context cannot be spent under tenant A's session.
    const crossTrace = traceId();
    const crossed = await deviceAction({
      device: deviceB,
      context: contextB,
      payload: await conformingPayload(deviceB, contextB),
      session: fx.opAlpha,
      trace: crossTrace,
    });
    expect(crossed.status).toBe(403);
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 240_000);

  it('the WRONG OPERATIVE — a valid statement carried by somebody else’s live session', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, session: fx.opBravo, trace });
    expect(result.status).toBe(403);
    // C17-01: possession and identity are two facts, and holding the hardware
    // does not make the caller the operative the context is bound to.
    expect(await refusalReasonFor(trace)).toBe('SESSION_ACTOR_MISMATCH');

    // ...and with NO session at all, the request never reaches the service.
    const anonymous = await deviceAction({ device, context, payload, session: null });
    expect([401, 403]).toContain(anonymous.status);
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);
});

// ===========================================================================
// REJECT — the registry
// ===========================================================================

describe('WP-27 the registry decides, and it decides NOW', () => {
  it('a REVOKED device is refused, with zero effect', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    const revoked = await trust.declareDisposition(A.approver, {
      organisationId: fx.orgA,
      deviceId: device.deviceId,
      disposition: 'STOLEN',
      reason: 'wp27 revocation',
      traceId: traceId(),
    });
    expect(revoked.outcome).toBe('DECLARED');

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('CREDENTIAL_REVOKED');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('an INELIGIBLE trust state is refused — WHISPER_DEVICE_ACTION admits TRUSTED alone', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    // DEGRADED is enough for a FIELD_OPERATION and is NOT enough here. That
    // asymmetry is W21-05, and it is the reason the route selects
    // WHISPER_DEVICE_ACTION rather than travelling under a Field purpose.
    const changed = await trust.changeDeviceTrust(A.approver, {
      organisationId: fx.orgA,
      deviceId: device.deviceId,
      to: 'DEGRADED',
      reason: 'wp27 trust gate',
      traceId: traceId(),
    });
    expect(changed.outcome).toBe('CHANGED');

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('DEVICE_TRUST_NOT_PERMITTED');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('an UNSUPPORTED REGISTRY PROFILE is refused, with no fallback to another verifier', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    // The registry column is moved directly: there is no ceremony that can put
    // an unapproved profile on a key, which is the point — this asserts what
    // happens if one ever arrives, by corruption or by a future migration.
    await prisma.deviceKey.updateMany({
      where: { organisationId: fx.orgA, keyId: device.keyId },
      data: { signatureProfile: 'ED25519_NOT_APPROVED' },
    });
    try {
      const trace = traceId();
      const result = await deviceAction({ device, context, payload, trace });
      expect(result.status).toBe(403);
      // The registry record cannot even satisfy its own contract, so it is
      // never handed to a verifier. Either refusal is fail-closed; neither
      // selects a different algorithm.
      expect(await refusalReasonFor(trace)).toMatch(/REGISTRY_KEY_UNRESOLVABLE|SIGNATURE_PROFILE_NOT_SUPPORTED/u);
      expect((await deviceActionConsumptions()).length).toBe(before);
    } finally {
      await prisma.deviceKey.updateMany({
        where: { organisationId: fx.orgA, keyId: device.keyId },
        data: { signatureProfile: WHISPER_DEVICE_ACTION_V2_PROFILE },
      });
    }
  }, 180_000);

  it('an UNKNOWN key — a context whose device row has been withdrawn — is refused', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const compromised = await trust.declareDisposition(A.approver, {
      organisationId: fx.orgA,
      deviceId: device.deviceId,
      disposition: 'COMPROMISED_KEY',
      reason: 'wp27 unknown key',
      traceId: traceId(),
    });
    expect(compromised.outcome).toBe('DECLARED');

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).not.toBeNull();
  }, 180_000);
});

// ===========================================================================
// REJECT — freshness, purpose and replay
// ===========================================================================

describe('WP-27 freshness, purpose and the one-shot identity', () => {
  it('a STALE statement is refused against the SERVER clock', async () => {
    const device = await enrol();
    const context = await establish(device);
    const before = (await deviceActionConsumptions()).length;
    // Three minutes old: past the frozen two-minute v1 window, which v2 reuses
    // rather than restating.
    const payload = await conformingPayload(device, context, { recognisedAt: new Date(Date.now() - 180_000).toISOString() });

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('RECOGNITION_STALE');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a statement claiming to be signed FROM THE FUTURE is refused', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context, { recognisedAt: new Date(Date.now() + 120_000).toISOString() });
    const trace = traceId();
    const result = await deviceAction({ device, context, payload, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('RECOGNITION_FUTURE_SKEW');
  }, 180_000);

  it('a proof minted for FIELD_OPERATION cannot spend a device action', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);
    const before = (await deviceActionConsumptions()).length;

    const trace = traceId();
    const result = await deviceAction({ device, context, payload, purpose: 'FIELD_OPERATION', trace });
    expect(result.status).toBe(403);
    // The ROUTE chose WHISPER_DEVICE_ACTION. Exactly one purpose is admissible
    // per evaluation (C15-04), so cross-purpose reuse is a refusal.
    expect(await refusalReasonFor(trace)).toContain('PURPOSE_NOT_ALLOWED');
    expect((await deviceActionConsumptions()).length).toBe(before);
  }, 180_000);

  it('a TRANSPORT RETRY of the identical request causes no duplicate effect', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);

    const first = await deviceAction({ device, context, payload });
    expect(first.status).toBe(201);
    expect(first.body.outcome).toBe('COMMITTED');
    const after = (await deviceActionConsumptions()).length;

    // The BYTE-IDENTICAL proof, re-sent — the lost-response case.
    const trace = traceId();
    const retry = await deviceAction({ device, context, payload, proof: first.proof, trace });
    expect(retry.status).toBe(201);
    expect(retry.body.outcome).toBe('CONVERGED');
    expect((await deviceActionConsumptions()).length).toBe(after);
    expect((await eventsForTrace(trace)).map((event) => event.eventType)).toEqual(['OPERATION_CONVERGED']);
  }, 180_000);

  it('a REPLAYED valid statement, under a FRESH transport proof, does not re-execute', async () => {
    const device = await enrol();
    const context = await establish(device);
    const payload = await conformingPayload(device, context);

    expect((await deviceAction({ device, context, payload })).status).toBe(201);
    const after = await deviceActionConsumptions();

    // A brand-new transport proof with a brand-new transport nonce, carrying
    // the SAME captured statement. WP-25 admits the transport; WP-27's own
    // one-shot identity is what stops it — and it REFUSES rather than reporting
    // a success for an effect this request did not cause. The lost-response
    // case is the byte-identical retry above, answered one layer up.
    const trace = traceId();
    const replay = await deviceAction({ device, context, payload, trace });
    expect(replay.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('REPLAY_IDENTITY_ALREADY_SPENT');
    expect((await deviceActionConsumptions()).length).toBe(after.length);
  }, 180_000);

  it('THE SAME ACTION UNDER A DIFFERENT ECDSA SIGNATURE does not re-execute', async () => {
    const device = await enrol();
    const context = await establish(device);
    const identity = identityOf(context);
    const claims = rawClaims({ keyId: context.key_id, keyVersion: context.key_version });

    const first = signClaims(device.keyPair, identity, claims);
    expect((await deviceAction({ device, context, payload: first })).status).toBe(201);
    const after = await deviceActionConsumptions();

    // ECDSA is randomised, so re-signing the SAME statement produces DIFFERENT
    // bytes that verify just as well. If the replay identity or the statement
    // fingerprint included the signature, this would look like a new action and
    // would execute a second time. Neither does.
    const second = signClaims(device.keyPair, identity, claims);
    expect(second.signature).not.toBe(first.signature);

    const trace = traceId();
    const resent = await deviceAction({ device, context, payload: second, trace });
    expect(resent.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('REPLAY_IDENTITY_ALREADY_SPENT');
    expect((await deviceActionConsumptions()).length).toBe(after.length);

    // Both presentations landed on ONE row, keyed on the action's semantic
    // identity, holding ONE statement fingerprint.
    const replayKey = whisperDeviceActionV2ReplayKey({ ...identity, ...claims } as never);
    const fingerprint = whisperDeviceActionV2Fingerprint(
      whisperDeviceActionV2StatementInput({ ...identity, ...claims, signature: first.signature } as never, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    expect(replayKey).not.toContain(first.signature as string);
    expect(after.filter((row) => row.statementFingerprint === fingerprint).length).toBe(1);
  }, 180_000);

  it('the SAME NONCE carrying a DIFFERENT action is a conflict, not a second effect', async () => {
    const device = await enrol();
    const context = await establish(device);
    const identity = identityOf(context);
    const nonce = `${tag}-${randomBytes(12).toString('base64url')}`;

    const first = signClaims(device.keyPair, identity, rawClaims({ keyId: context.key_id, keyVersion: context.key_version, nonce }));
    expect((await deviceAction({ device, context, payload: first })).status).toBe(201);
    const after = (await deviceActionConsumptions()).length;

    const different = signClaims(
      device.keyPair,
      identity,
      rawClaims({ keyId: context.key_id, keyVersion: context.key_version, nonce, deviceActionId: `${tag}-other-action` }),
    );
    const trace = traceId();
    const result = await deviceAction({ device, context, payload: different, trace });
    expect(result.status).toBe(403);
    expect(await refusalReasonFor(trace)).toContain('REPLAY_IDENTITY_REUSED');
    expect((await deviceActionConsumptions()).length).toBe(after);
  }, 180_000);
});
