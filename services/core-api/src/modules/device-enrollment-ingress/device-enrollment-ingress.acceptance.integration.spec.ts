import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { canonicalDevicePossessionStatement, deriveP256PublicKeyThumbprint } from '@sentinel/contracts';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { GlobalExceptionFilter } from '../../common/global-exception.filter';
import { traceIdMiddleware } from '../../common/trace-id.middleware';
import { GlobalValidationPipe } from '../../common/validation.pipe';
import { PrismaService } from '../../prisma/prisma.service';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { signCanonicalStatement } from '../shield/shield.test-support';
import {
  ANDROID_ATTESTATION_TRUST_MATERIAL,
  type AndroidAttestationTrustMaterial,
  type AndroidAttestationTrustMaterialProvider,
} from './android-attestation.trust-material';
import {
  TEST_PACKAGE_NAME,
  TEST_SIGNING_DIGEST,
  buildSyntheticChain,
  canonicalPublicKeyOf,
  generateEcKeyPair,
  type SyntheticChain,
  type TestKeyPair,
} from './android-attestation.test-support';
import {
  ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
  ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS,
  DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS,
} from './device-enrollment-ingress.constants';

/**
 * ============================================================================
 * WP-26 Field Mobile Foundation — the Crucible.
 *
 * Driven over REAL HTTP, through the REAL module graph (AppModule), the REAL
 * global guard chain, the REAL frozen evaluators, the REAL P-256 verifier, the
 * REAL Android Key Attestation verifier — chain walk, DER reader, anchor
 * comparison, revocation check and all — and the REAL Postgres constraints.
 * Nothing below stubs a security decision. The ONE injected seam is the trust
 * material, which is SERVER CONFIGURATION by design (D26-04B): a test supplies
 * anchors and a revocation snapshot exactly as a deployment would, and cannot
 * reach into the verdict rules themselves.
 *
 * A SYNTHETIC CHAIN IS NOT A PHYSICAL DEVICE. THIS IS NOT PROOF C.
 *
 * Every "device" below is a P-256 keypair this test process generated, and
 * every attestation chain is a chain this test process signed with a root it
 * also generated. There is no StrongBox, no TEE, no non-exportable key, no
 * Google root and no Android client anywhere in this suite. What a passing test
 * proves is that the VERIFIER's logic is correct and that the BRIDGE refuses
 * what it must; it proves nothing whatsoever about hardware. D26-10 rules that
 * an emulator is not a hardware test, and a certificate builder is one step
 * further from hardware than an emulator. Physical-device acceptance is
 * required to close WP-26 and is STILL NOT Proof C (D26-08) — that is the WP-28
 * gate over a real device invoking a real DEVICE_ACTION Whisper. Proof D is
 * likewise UNCLAIMED.
 *
 * D25-08, still binding: this spec boots the app, so it overrides
 * `PATROL_SWEEP_SCHEDULER` with the WP-22 no-op seam. It adds no scheduler of
 * its own, and the ingress has none — every expiry it enforces is a comparison
 * taken at request time.
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

const tag = `wp26_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const PROFILE = 'P256_ECDSA_SHA256';
const INGRESS = '/api/v1/device-enrollment';
const COMMAND = '/api/v1/device-enrollment/command';

const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteB1: `${tag}_siteB1`,
  cmdIssuerA: `${tag}_cmdIssuerA`,
  cmdApproverA: `${tag}_cmdApproverA`,
  opAlpha: `${tag}_opAlpha`,
  opBravo: `${tag}_opBravo`,
  cmdIssuerB: `${tag}_cmdIssuerB`,
  opB: `${tag}_opB`,
};

/**
 * The trust material seam, settable per test.
 *
 * It stands in for a deployment's pinned Google roots and its revocation
 * snapshot. It is the ONLY thing this suite injects, and it is deliberately
 * the thing D26-04B says must be SERVER configuration: a test that could
 * instead reach into the verifier's verdict rules would be testing its own
 * stub.
 */
class SettableTrustMaterial implements AndroidAttestationTrustMaterialProvider {
  material: AndroidAttestationTrustMaterial = {
    configured: false,
    reason: 'TEST_NOT_CONFIGURED',
    trustAnchorSetVersion: 'wp26-test/none',
    revocationSnapshotVersion: 'wp26-test/none',
  };

  async current(_now: Date): Promise<AndroidAttestationTrustMaterial> {
    return this.material;
  }
}

let app: INestApplication;
let base: string;
let prisma: PrismaService;
let trust: SettableTrustMaterial;

/**
 * The ONE pinned root for this suite.
 *
 * A single root, generated once and pinned as server configuration, so that
 * "the chain anchors to a root the SERVER chose" and "the chain anchors to a
 * root the DEVICE brought" are two genuinely different situations rather than
 * an artefact of regenerating fixtures.
 */
let pinnedRootKeyPair: TestKeyPair;
let pinnedRoot: SyntheticChain;

async function seed(): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-26 Org A' },
      { id: fx.orgB, name: 'WP-26 Org B' },
    ],
  });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });
  const users: Array<{ id: string; org: string; role: string; site: string }> = [
    { id: fx.cmdIssuerA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.cmdApproverA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.opAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opBravo, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.cmdIssuerB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.opB, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });
}

async function cleanup(): Promise<void> {
  const organisationId = { in: [fx.orgA, fx.orgB] };
  await prisma.androidKeyAttestationArtifact.deleteMany({ where: { organisationId } });
  await prisma.deviceAttestationChallenge.deleteMany({ where: { organisationId } });

  await prisma.deviceSecurityEvent.deleteMany({ where: { organisationId } });
  await prisma.deviceTrustTransition.deleteMany({ where: { organisationId } });
  await prisma.deviceAttestationObservation.deleteMany({ where: { organisationId } });
  await prisma.deviceNonceConsumption.deleteMany({ where: { organisationId } });
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
  trust = new SettableTrustMaterial();

  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(PATROL_SWEEP_SCHEDULER)
    .useClass(NoopPatrolSweepScheduler)
    // The ONLY injected seam. NOTE what is NOT overridden:
    // `DEVICE_ATTESTATION_EVALUATOR` keeps its real WP-26 provider, so every
    // verdict below is reached by the real evaluator resolving a real artifact.
    .overrideProvider(ANDROID_ATTESTATION_TRUST_MATERIAL)
    .useValue(trust)
    .compile();

  app = moduleRef.createNestApplication();
  app.use(traceIdMiddleware);
  app.useGlobalPipes(new GlobalValidationPipe());
  app.useGlobalFilters(new GlobalExceptionFilter());
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  base = `http://127.0.0.1:${typeof address === 'object' && address !== null ? address.port : 0}`;

  prisma = app.get(PrismaService);
  await cleanup();
  await seed();

  pinnedRootKeyPair = generateEcKeyPair();
  pinnedRoot = buildSyntheticChain({ challenge: Buffer.alloc(32), rootKeyPair: pinnedRootKeyPair });
}, 240_000);

afterAll(async () => {
  if (prisma !== undefined) await cleanup();
  if (app !== undefined) await app.close();
});

beforeEach(() => {
  trust.material = configuredMaterial();
});

/** Server configuration as a healthy deployment would supply it. */
function configuredMaterial(overrides: Partial<Extract<AndroidAttestationTrustMaterial, { configured: true }>> = {}) {
  const material: Extract<AndroidAttestationTrustMaterial, { configured: true }> = {
    configured: true,
    anchors: [pinnedRoot.root],
    trustAnchorSetVersion: 'wp26-test-anchors/1',
    revocations: new Map(),
    revocationSnapshotVersion: 'wp26-test-revocations/1',
    revocationFetchedAt: new Date(),
    expectedPackageName: TEST_PACKAGE_NAME,
    expectedSigningDigests: [TEST_SIGNING_DIGEST.toString('hex')],
    ...overrides,
  };
  return material;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

interface HttpResult {
  status: number;
  body: Record<string, unknown>;
  /** The raw response text, so a leak test can search everything that was sent. */
  text: string;
  traceId: string;
}

/** Everything the server has said to a client during this suite, for the leak scan. */
const responseTranscript: string[] = [];

async function request(method: 'POST' | 'GET', path: string, body: unknown, headers: Record<string, string> = {}): Promise<HttpResult> {
  const trace = headers['x-trace-id'] ?? `trace-${randomUUID()}`;
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-trace-id': trace, ...headers },
    body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined,
  });
  const text = await response.text();
  responseTranscript.push(text);
  return {
    status: response.status,
    body: text.length === 0 ? {} : (JSON.parse(text) as Record<string, unknown>),
    text,
    traceId: trace,
  };
}

const post = (path: string, body: unknown, headers: Record<string, string> = {}): Promise<HttpResult> =>
  request('POST', path, body, headers);
const get = (path: string, headers: Record<string, string> = {}): Promise<HttpResult> => request('GET', path, null, headers);

const asSession = (userId: string): Record<string, string> => ({ 'x-dev-user-id': userId });

// ---------------------------------------------------------------------------
// The ceremony, as a conforming client performs it
// ---------------------------------------------------------------------------

async function issueGrant(
  options: { issuer?: string; organisationId?: string; siteId?: string; intendedUserId?: string } = {},
): Promise<{ grantId: string; token: string }> {
  const result = await post(
    `${COMMAND}/bootstrap-grants`,
    {
      organisation_id: options.organisationId ?? fx.orgA,
      site_id: options.siteId ?? fx.siteA1,
      intended_user_id: options.intendedUserId ?? fx.opAlpha,
    },
    asSession(options.issuer ?? fx.cmdIssuerA),
  );
  if (result.status !== 201) throw new Error(`grant not issued: ${result.status} ${result.text}`);
  return { grantId: result.body.grant_id as string, token: result.body.bootstrap_token as string };
}

async function requestAttestationChallenge(
  token: string,
  options: { session?: string; organisationId?: string; siteId?: string; intendedUserId?: string } = {},
): Promise<HttpResult> {
  return post(
    `${INGRESS}/attestation-challenge`,
    {
      organisation_id: options.organisationId ?? fx.orgA,
      site_id: options.siteId ?? fx.siteA1,
      intended_user_id: options.intendedUserId ?? fx.opAlpha,
      bootstrap_token: token,
    },
    asSession(options.session ?? fx.opAlpha),
  );
}

interface SubmittedRequest {
  chain: SyntheticChain;
  deviceKeyPair: TestKeyPair;
  canonicalPublicKey: string;
  result: HttpResult;
}

async function submitEnrollmentRequest(
  token: string,
  challengeId: string,
  challengeValue: string,
  options: {
    session?: string;
    deviceKeyPair?: TestKeyPair;
    /** Craft the KeyDescription — the TEE/StrongBox, boot-state and origin knobs. */
    keyDescription?: Parameters<typeof buildSyntheticChain>[0]['keyDescription'];
    /** Attest against DIFFERENT bytes from the ones the server issued. */
    attestedChallenge?: Buffer;
    omitAttestationExtension?: boolean;
    /** Build the chain under a root the server has NOT pinned. */
    rootKeyPair?: TestKeyPair;
    /** Attest a DIFFERENT key from the one submitted. */
    attestedKeyPair?: TestKeyPair;
    leafSerial?: number;
    notBefore?: Date;
    notAfter?: Date;
  } = {},
): Promise<SubmittedRequest> {
  const deviceKeyPair = options.deviceKeyPair ?? generateEcKeyPair();
  const chain = buildSyntheticChain({
    challenge: options.attestedChallenge ?? Buffer.from(challengeValue, 'base64url'),
    leafKeyPair: options.attestedKeyPair ?? deviceKeyPair,
    rootKeyPair: options.rootKeyPair ?? pinnedRootKeyPair,
    keyDescription: options.keyDescription,
    omitAttestationExtension: options.omitAttestationExtension,
    leafSerial: options.leafSerial,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
  });
  const canonicalPublicKey = canonicalPublicKeyOf(deviceKeyPair);
  const result = await post(
    `${INGRESS}/requests`,
    {
      organisation_id: fx.orgA,
      site_id: fx.siteA1,
      intended_user_id: fx.opAlpha,
      bootstrap_token: token,
      attestation_challenge_id: challengeId,
      public_key: canonicalPublicKey,
      claimed_signature_profile: PROFILE,
      custody: 'PERSONAL',
      custody_regime_id: null,
      certificate_chain: chain.chainBase64,
    },
    asSession(options.session ?? fx.opAlpha),
  );
  return { chain, deviceKeyPair, canonicalPublicKey, result };
}

/** Grant -> attestation challenge -> request, the three steps every test needs. */
async function openCeremony(
  options: Parameters<typeof submitEnrollmentRequest>[3] = {},
): Promise<{ grantId: string; token: string; challengeId: string; challengeValue: string; submitted: SubmittedRequest }> {
  const grant = await issueGrant();
  const challenge = await requestAttestationChallenge(grant.token);
  expect(challenge.status).toBe(201);
  const challengeId = challenge.body.attestation_challenge_id as string;
  const challengeValue = challenge.body.challenge as string;
  const submitted = await submitEnrollmentRequest(grant.token, challengeId, challengeValue, options);
  return { grantId: grant.grantId, token: grant.token, challengeId, challengeValue, submitted };
}

async function approve(enrollmentRequestId: string, fingerprint: string, approver = fx.cmdApproverA): Promise<HttpResult> {
  return post(
    `${COMMAND}/enrollment-requests/${enrollmentRequestId}/approve`,
    { organisation_id: fx.orgA, expected_request_fingerprint: fingerprint },
    asSession(approver),
  );
}

/** Possession challenge -> StrongBox signature -> commit. */
async function proveAndCommit(
  enrollmentRequestId: string,
  fingerprint: string,
  deviceKeyPair: TestKeyPair,
  canonicalPublicKey: string,
): Promise<{ possession: HttpResult; commit: HttpResult }> {
  const challenge = await post(
    `${INGRESS}/possession-challenge`,
    { organisation_id: fx.orgA, enrollment_request_id: enrollmentRequestId },
    asSession(fx.opAlpha),
  );
  expect(challenge.status).toBe(201);
  const challengeId = challenge.body.challenge_id as string;

  const statement = canonicalDevicePossessionStatement({
    challenge_id: challengeId,
    enrollment_request_id: enrollmentRequestId,
    enrollment_request_fingerprint: fingerprint,
    nonce: challenge.body.nonce as string,
    public_key_thumbprint: deriveP256PublicKeyThumbprint(canonicalPublicKey),
    signature_profile: PROFILE,
  });

  const possession = await post(
    `${INGRESS}/possession`,
    {
      organisation_id: fx.orgA,
      enrollment_request_id: enrollmentRequestId,
      challenge_id: challengeId,
      response: {
        schema_version: 1,
        challenge_id: challengeId,
        enrollment_request_id: enrollmentRequestId,
        claimed_signature_profile: PROFILE,
        signature: signCanonicalStatement(deviceKeyPair.privateKey, statement),
        answered_at: new Date().toISOString(),
      },
    },
    asSession(fx.opAlpha),
  );

  const commit = await post(
    `${INGRESS}/commit`,
    { organisation_id: fx.orgA, enrollment_request_id: enrollmentRequestId, challenge_id: challengeId },
    asSession(fx.opAlpha),
  );
  return { possession, commit };
}

/** The artifact row the verifier wrote for one ceremony. */
async function artifactFor(attestationChallengeId: string) {
  const row = await prisma.androidKeyAttestationArtifact.findFirst({
    where: { organisationId: fx.orgA, attestationChallengeId },
    orderBy: { createdAt: 'desc' },
  });
  if (row === null) throw new Error('no attestation artifact was written');
  return row;
}

// ===========================================================================
// 1. THE HAPPY CEREMONY, END TO END
// ===========================================================================

describe('WP-26/D26-01 the full enrollment ceremony, over HTTP', () => {
  it('grant -> attestation challenge -> request -> approval -> possession -> commit -> registered device', async () => {
    const ceremony = await openCeremony();
    expect(ceremony.submitted.result.status).toBe(201);
    // D26-02: the SERVER concluded HARDWARE_BACKED from its own verdict. There
    // is no request field the client could have claimed it with.
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('VERIFIED');
    expect(ceremony.submitted.result.body.key_storage).toBe('HARDWARE_BACKED');

    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;

    // The commander's queue shows the request, with the exact fingerprint they
    // will have to name back.
    const pending = await get(`${COMMAND}/pending?organisation_id=${fx.orgA}`, asSession(fx.cmdApproverA));
    expect(pending.status).toBe(200);
    const queue = pending.body.requests as Array<Record<string, unknown>>;
    const queued = queue.find((entry) => entry.enrollment_request_id === enrollmentRequestId);
    expect(queued).toBeDefined();
    expect(queued?.request_fingerprint).toBe(fingerprint);
    expect(queued?.attestation_outcome).toBe('VERIFIED');

    const approval = await approve(enrollmentRequestId, fingerprint);
    expect(approval.status).toBe(201);
    expect(approval.body.approved_request_fingerprint).toBe(fingerprint);

    const finished = await proveAndCommit(
      enrollmentRequestId,
      fingerprint,
      ceremony.submitted.deviceKeyPair,
      ceremony.submitted.canonicalPublicKey,
    );
    expect(finished.possession.status).toBe(201);
    expect(finished.possession.body.outcome).toBe('VERIFIED');
    expect(finished.commit.status).toBe(201);
    expect(finished.commit.body.outcome).toBe('COMMITTED');

    // The registry holds a real device, on the key that was actually attested.
    const deviceId = finished.commit.body.device_id as string;
    const device = await prisma.device.findFirst({ where: { id: deviceId, organisationId: fx.orgA } });
    expect(device).not.toBeNull();
    const key = await prisma.deviceKey.findFirst({ where: { organisationId: fx.orgA, deviceId, status: 'CURRENT' } });
    expect(key?.publicKeyThumbprint).toBe(deriveP256PublicKeyThumbprint(ceremony.submitted.canonicalPublicKey));
    expect(key?.keyStorage).toBe('HARDWARE_BACKED');
    // D23-03 + C14-05: a hardware-backed key with a CURRENT verified attestation
    // is the ONE combination that starts TRUSTED, and this is the first time in
    // Sentinel's history that the combination has been reachable.
    expect(finished.commit.body.trust).toBe('TRUSTED');
  }, 120_000);

  it('the approval must name the EXACT fingerprint (C14-02)', async () => {
    const ceremony = await openCeremony();
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const wrong = createHash('sha256').update('not-this-request').digest('hex');
    const refused = await approve(enrollmentRequestId, wrong);
    expect(refused.status).toBe(403);
    // Nothing was approved, so nothing can proceed.
    const challenge = await post(
      `${INGRESS}/possession-challenge`,
      { organisation_id: fx.orgA, enrollment_request_id: enrollmentRequestId },
      asSession(fx.opAlpha),
    );
    expect(challenge.status).toBe(403);
  }, 120_000);
});

// ===========================================================================
// 2. D26-04A — the attestation challenge
// ===========================================================================

describe('WP-26/D26-04A the server nonce comes BEFORE key generation, and it binds', () => {
  it('a key attested against a DIFFERENT server challenge is not VERIFIED', async () => {
    const ceremony = await openCeremony({ attestedChallenge: randomBytes(32) });
    expect(ceremony.submitted.result.status).toBe(201);
    expect(ceremony.submitted.result.body.attestation_outcome).not.toBe('VERIFIED');
    expect(ceremony.submitted.result.body.key_storage).toBe('SOFTWARE');

    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('NEGATIVE');
    expect(artifact.outcomeReason).toBe('ATTESTATION_CHALLENGE_MISMATCH');
  }, 120_000);

  it('a chain with NO attestation extension at all is not VERIFIED', async () => {
    const ceremony = await openCeremony({ omitAttestationExtension: true });
    expect(ceremony.submitted.result.body.attestation_outcome).not.toBe('VERIFIED');
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('INVALID');
    expect(artifact.outcomeReason).toBe('ATTESTATION_EXTENSION_MISSING');
  }, 120_000);

  it('an EXPIRED attestation challenge refuses, and the grant still being alive does not save it', async () => {
    const grant = await issueGrant();
    const challenge = await requestAttestationChallenge(grant.token);
    expect(challenge.status).toBe(201);
    const challengeId = challenge.body.attestation_challenge_id as string;
    const challengeValue = challenge.body.challenge as string;

    // Age the challenge past its own ceiling. The GRANT is untouched and still
    // has its full 600-second window: an old attestation must not be accepted
    // merely because the grant has time left.
    await prisma.deviceAttestationChallenge.update({
      where: { id: challengeId },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    const grantRow = await prisma.enrollmentBootstrapGrant.findFirst({ where: { id: grant.grantId } });
    expect(grantRow?.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(grantRow?.consumedAt).toBeNull();
    expect(grantRow?.revokedAt).toBeNull();

    const submitted = await submitEnrollmentRequest(grant.token, challengeId, challengeValue);
    expect(submitted.result.status).toBe(403);
    // Nothing was verified and nothing was opened.
    const artifacts = await prisma.androidKeyAttestationArtifact.count({ where: { attestationChallengeId: challengeId } });
    expect(artifacts).toBe(0);
    const requests = await prisma.enrollmentRequest.count({ where: { bootstrapGrantId: grant.grantId } });
    expect(requests).toBe(0);
  }, 120_000);

  it('the challenge cannot outlive its bootstrap grant', async () => {
    const grant = await issueGrant();
    // A grant with less life left than the challenge ceiling. The challenge must
    // be CLAMPED to the grant, not given its own full window.
    const grantExpiry = new Date(Date.now() + 5_000);
    await prisma.enrollmentBootstrapGrant.update({ where: { id: grant.grantId }, data: { expiresAt: grantExpiry } });

    const challenge = await requestAttestationChallenge(grant.token);
    expect(challenge.status).toBe(201);
    const expiresAt = new Date(challenge.body.expires_at as string);
    expect(expiresAt.getTime()).toBeLessThanOrEqual(grantExpiry.getTime());
    // ... and strictly less than what its OWN ceiling would have allowed.
    expect(expiresAt.getTime()).toBeLessThan(Date.now() + DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS);

    const row = await prisma.deviceAttestationChallenge.findFirst({
      where: { id: challenge.body.attestation_challenge_id as string },
    });
    expect(row?.expiresAt.getTime()).toBeLessThanOrEqual(grantExpiry.getTime());
  }, 120_000);

  it('a challenge whose grant is already dead is refused outright', async () => {
    const grant = await issueGrant();
    await prisma.enrollmentBootstrapGrant.update({
      where: { id: grant.grantId },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    const refused = await requestAttestationChallenge(grant.token);
    expect(refused.status).toBe(403);
    const challenges = await prisma.deviceAttestationChallenge.count({ where: { bootstrapGrantId: grant.grantId } });
    expect(challenges).toBe(0);
  }, 120_000);

  it('the challenge is ONE-SHOT: it cannot be reused, even by the same operative', async () => {
    const grant = await issueGrant();
    const challenge = await requestAttestationChallenge(grant.token);
    const challengeId = challenge.body.attestation_challenge_id as string;
    const challengeValue = challenge.body.challenge as string;

    const first = await submitEnrollmentRequest(grant.token, challengeId, challengeValue);
    expect(first.result.status).toBe(201);

    const second = await submitEnrollmentRequest(grant.token, challengeId, challengeValue);
    expect(second.result.status).toBe(403);

    const consumed = await prisma.deviceAttestationChallenge.findFirst({ where: { id: challengeId } });
    expect(consumed?.consumedAt).not.toBeNull();
    // Exactly one verification happened against it.
    const artifacts = await prisma.androidKeyAttestationArtifact.count({ where: { attestationChallengeId: challengeId } });
    expect(artifacts).toBe(1);
  }, 120_000);

  it('a challenge minted under one grant cannot be answered under another', async () => {
    const first = await issueGrant();
    const second = await issueGrant();
    const challenge = await requestAttestationChallenge(first.token);
    const submitted = await submitEnrollmentRequest(
      second.token,
      challenge.body.attestation_challenge_id as string,
      challenge.body.challenge as string,
    );
    expect(submitted.result.status).toBe(403);
  }, 120_000);
});

// ===========================================================================
// 3. C14-02 / C17-01 — the human halves
// ===========================================================================

describe('WP-26/C14-02 a stolen grant plus an attacker key still cannot win an approved enrollment', () => {
  it('a stolen grant presented by the WRONG HUMAN is refused at the ingress, BEFORE Shield', async () => {
    const grant = await issueGrant();
    // opBravo is a real, authenticated Field operative in the right tenant and
    // at the right site. They hold the stolen token, and they present it for the
    // ceremony it was actually issued for — naming opAlpha, correctly. They are
    // not opAlpha, and that is the whole of it.
    const stolen = await requestAttestationChallenge(grant.token, { session: fx.opBravo });
    expect(stolen.status).toBe(403);

    // The refusal is at the INGRESS, before the token ever reaches Shield: no
    // challenge, and the grant is untouched. That matters — a session-binding
    // failure must not become a denial of service against the operative the
    // grant was issued for, who may simply be the next person to pick up the
    // phone.
    expect(await prisma.deviceAttestationChallenge.count({ where: { bootstrapGrantId: grant.grantId } })).toBe(0);
    const grantRow = await prisma.enrollmentBootstrapGrant.findFirst({ where: { id: grant.grantId } });
    expect(grantRow?.consumedAt).toBeNull();

    const legitimate = await requestAttestationChallenge(grant.token);
    expect(legitimate.status).toBe(201);
  }, 120_000);

  it('a stolen grant presented in a context it was NOT issued for BURNS (D24-03a, the probe rule)', async () => {
    const grant = await issueGrant();
    // Now the thief presents the token as a ceremony for THEMSELVES. The ingress
    // session binding is satisfied — they really are opBravo — so the token
    // reaches Shield, which finds a grant issued for a different intended user.
    // A probe is not a typo: the grant is BURNED and a security event is written
    // under the grant's OWN organisation.
    const probe = await requestAttestationChallenge(grant.token, { session: fx.opBravo, intendedUserId: fx.opBravo });
    expect(probe.status).toBe(403);

    const burned = await prisma.enrollmentBootstrapGrant.findFirst({ where: { id: grant.grantId } });
    expect(burned?.consumedAt).not.toBeNull();
    const events = await prisma.deviceSecurityEvent.findMany({
      where: { organisationId: fx.orgA, eventType: 'BOOTSTRAP_REPLAY_REFUSED' },
    });
    expect(events.some((event) => JSON.stringify(event.payload).includes(grant.grantId))).toBe(true);

    // And the grant is dead for EVERYONE, including the operative it was issued
    // for. That is the intended cost: a probed grant is re-issued, not reused.
    const afterProbe = await requestAttestationChallenge(grant.token);
    expect(afterProbe.status).toBe(403);
    expect(await prisma.deviceAttestationChallenge.count({ where: { bootstrapGrantId: grant.grantId } })).toBe(0);
  }, 120_000);

  it('a second, attacker-keyed request under an approved grant is refused, and the approved key is the one registered', async () => {
    const ceremony = await openCeremony();
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;
    expect((await approve(enrollmentRequestId, fingerprint)).status).toBe(201);

    // The attacker now holds the grant and their own key, and even holds the
    // intended user's session. C16-02's ONE GRANT, ONE CEREMONY rule stops them:
    // a materially different submission behind a grant that already opened a
    // request is a conflict, not a second approval candidate.
    const attackerChallenge = await requestAttestationChallenge(ceremony.token);
    expect(attackerChallenge.status).toBe(201);
    const attackerKey = generateEcKeyPair();
    const attacker = await submitEnrollmentRequest(
      ceremony.token,
      attackerChallenge.body.attestation_challenge_id as string,
      attackerChallenge.body.challenge as string,
      { deviceKeyPair: attackerKey },
    );
    expect(attacker.result.status).toBe(403);

    // The ceremony completes on the APPROVED key, and only on it.
    const finished = await proveAndCommit(
      enrollmentRequestId,
      fingerprint,
      ceremony.submitted.deviceKeyPair,
      ceremony.submitted.canonicalPublicKey,
    );
    expect(finished.commit.body.outcome).toBe('COMMITTED');
    const key = await prisma.deviceKey.findFirst({
      where: { organisationId: fx.orgA, deviceId: finished.commit.body.device_id as string, status: 'CURRENT' },
    });
    expect(key?.publicKeyThumbprint).toBe(deriveP256PublicKeyThumbprint(ceremony.submitted.canonicalPublicKey));
    expect(key?.publicKeyThumbprint).not.toBe(deriveP256PublicKeyThumbprint(canonicalPublicKeyOf(attackerKey)));
  }, 120_000);

  it('the possession step refuses a DIFFERENT authenticated human, and 401s with no session at all', async () => {
    const ceremony = await openCeremony();
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;
    expect((await approve(enrollmentRequestId, fingerprint)).status).toBe(201);

    const wrongHuman = await post(
      `${INGRESS}/possession-challenge`,
      { organisation_id: fx.orgA, enrollment_request_id: enrollmentRequestId },
      asSession(fx.opBravo),
    );
    expect(wrongHuman.status).toBe(403);

    const noSession = await post(`${INGRESS}/possession-challenge`, {
      organisation_id: fx.orgA,
      enrollment_request_id: enrollmentRequestId,
    });
    expect(noSession.status).toBe(401);

    // And every other mobile route behaves the same with no session.
    for (const route of ['attestation-challenge', 'requests', 'possession', 'commit']) {
      const unauthenticated = await post(`${INGRESS}/${route}`, {});
      expect(unauthenticated.status, route).toBe(401);
    }
  }, 120_000);

  it('the commit refuses a different authenticated human even after a valid possession proof', async () => {
    const ceremony = await openCeremony();
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;
    expect((await approve(enrollmentRequestId, fingerprint)).status).toBe(201);

    const challenge = await post(
      `${INGRESS}/possession-challenge`,
      { organisation_id: fx.orgA, enrollment_request_id: enrollmentRequestId },
      asSession(fx.opAlpha),
    );
    const challengeId = challenge.body.challenge_id as string;
    const statement = canonicalDevicePossessionStatement({
      challenge_id: challengeId,
      enrollment_request_id: enrollmentRequestId,
      enrollment_request_fingerprint: fingerprint,
      nonce: challenge.body.nonce as string,
      public_key_thumbprint: deriveP256PublicKeyThumbprint(ceremony.submitted.canonicalPublicKey),
      signature_profile: PROFILE,
    });
    // A PERFECT possession proof, carried by the wrong human's live session.
    const refused = await post(
      `${INGRESS}/possession`,
      {
        organisation_id: fx.orgA,
        enrollment_request_id: enrollmentRequestId,
        challenge_id: challengeId,
        response: {
          schema_version: 1,
          challenge_id: challengeId,
          enrollment_request_id: enrollmentRequestId,
          claimed_signature_profile: PROFILE,
          signature: signCanonicalStatement(ceremony.submitted.deviceKeyPair.privateKey, statement),
          answered_at: new Date().toISOString(),
        },
      },
      asSession(fx.opBravo),
    );
    expect(refused.status).toBe(403);
    // No verification row was created at all — the refusal is BEFORE Shield.
    const verifications = await prisma.possessionVerification.count({ where: { enrollmentRequestId } });
    expect(verifications).toBe(0);
  }, 120_000);
});

describe('WP-26/D26-09 the mobile surface can NEVER approve', () => {
  it('there is no approval route on the mobile surface', async () => {
    for (const route of ['approve', 'approvals', 'enrollment-requests/approve']) {
      const missing = await post(`${INGRESS}/${route}`, { organisation_id: fx.orgA }, asSession(fx.opAlpha));
      expect(missing.status, route).toBe(404);
    }
  }, 120_000);

  it('the commander action refuses a Field operative on the Command route', async () => {
    const ceremony = await openCeremony();
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;

    // The intended user, holding the correct fingerprint, on the real route.
    const refused = await approve(enrollmentRequestId, fingerprint, fx.opAlpha);
    expect(refused.status).toBe(403);
    expect(await prisma.enrollmentApproval.count({ where: { enrollmentRequestId } })).toBe(0);

    // ... and the ISSUER cannot approve their own grant either (D24-03).
    const issuerRefused = await approve(enrollmentRequestId, fingerprint, fx.cmdIssuerA);
    expect(issuerRefused.status).toBe(403);
    expect(await prisma.enrollmentApproval.count({ where: { enrollmentRequestId } })).toBe(0);
  }, 120_000);
});

describe('WP-26/C17-02 the session is the tenant anchor', () => {
  it('an org-A session claiming org-B produces ZERO rows and ZERO events under org-B', async () => {
    const before = {
      events: await prisma.deviceSecurityEvent.count({ where: { organisationId: fx.orgB } }),
      challenges: await prisma.deviceAttestationChallenge.count({ where: { organisationId: fx.orgB } }),
      artifacts: await prisma.androidKeyAttestationArtifact.count({ where: { organisationId: fx.orgB } }),
      requests: await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgB } }),
      grants: await prisma.enrollmentBootstrapGrant.count({ where: { organisationId: fx.orgB } }),
    };

    const grant = await issueGrant();
    const claimingB = await requestAttestationChallenge(grant.token, {
      session: fx.opAlpha,
      organisationId: fx.orgB,
      siteId: fx.siteB1,
      intendedUserId: fx.opB,
    });
    expect(claimingB.status).toBe(403);

    // The same claim on the Command surface, from an org-A commander.
    const commandClaimingB = await post(
      `${COMMAND}/bootstrap-grants`,
      { organisation_id: fx.orgB, site_id: fx.siteB1, intended_user_id: fx.opB },
      asSession(fx.cmdIssuerA),
    );
    expect([403, 404]).toContain(commandClaimingB.status);

    const after = {
      events: await prisma.deviceSecurityEvent.count({ where: { organisationId: fx.orgB } }),
      challenges: await prisma.deviceAttestationChallenge.count({ where: { organisationId: fx.orgB } }),
      artifacts: await prisma.androidKeyAttestationArtifact.count({ where: { organisationId: fx.orgB } }),
      requests: await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgB } }),
      grants: await prisma.enrollmentBootstrapGrant.count({ where: { organisationId: fx.orgB } }),
    };
    expect(after).toEqual(before);
  }, 120_000);
});

// ===========================================================================
// 4. D26-04B — the verifier
// ===========================================================================

describe('WP-26/D26-04B the Android Key Attestation verifier', () => {
  it('a TEE certificate is NOT promoted into the StrongBox profile', async () => {
    const ceremony = await openCeremony({
      keyDescription: {
        attestationSecurityLevel: ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        keymasterSecurityLevel: ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      },
    });
    expect(ceremony.submitted.result.status).toBe(201);
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('NEGATIVE');
    expect(ceremony.submitted.result.body.key_storage).toBe('SOFTWARE');

    const artifact = await artifactFor(ceremony.challengeId);
    // A DISTINCT reason. "Good hardware, wrong profile" and "not hardware" are
    // different facts and an operator must be able to tell them apart.
    expect(artifact.outcomeReason).toBe('SECURITY_LEVEL_NOT_STRONGBOX');
    expect(artifact.attestationSecurityLevel).toBe(ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
  }, 120_000);

  it('a leaf attesting a DIFFERENT key from the one submitted is refused', async () => {
    const ceremony = await openCeremony({ attestedKeyPair: generateEcKeyPair() });
    expect(ceremony.submitted.result.body.attestation_outcome).not.toBe('VERIFIED');
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('NEGATIVE');
    expect(artifact.outcomeReason).toBe('LEAF_KEY_NOT_SUBMITTED_KEY');
  }, 120_000);

  it('a structurally perfect chain under an UNPINNED root is refused', async () => {
    const ceremony = await openCeremony({ rootKeyPair: generateEcKeyPair() });
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('NEGATIVE');
    const artifact = await artifactFor(ceremony.challengeId);
    // Every link verified. The chain simply does not reach a root the SERVER
    // chose — and a root the device supplied is not a trust anchor.
    expect(artifact.outcomeReason).toBe('CHAIN_NOT_ANCHORED_TO_PINNED_ROOT');
    expect(artifact.trustAnchorSetVersion).toBe('wp26-test-anchors/1');
  }, 120_000);

  it('an expired certificate is refused', async () => {
    const past = new Date(Date.now() - 10 * 86_400_000);
    const ceremony = await openCeremony({ notBefore: new Date(past.getTime() - 86_400_000), notAfter: past });
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('NEGATIVE');
    expect(artifact.outcomeReason).toBe('CERTIFICATE_EXPIRED');
  }, 120_000);

  it('trust material that is not configured is UNAVAILABLE — never VERIFIED, never NEGATIVE', async () => {
    trust.material = {
      configured: false,
      reason: 'TEST_PROVIDER_OUTAGE',
      trustAnchorSetVersion: 'wp26-test/none',
      revocationSnapshotVersion: 'wp26-test/none',
    };
    const ceremony = await openCeremony();
    expect(ceremony.submitted.result.status).toBe(201);
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('UNAVAILABLE');
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('UNAVAILABLE');
    expect(artifact.outcomeReason).toBe('TRUST_MATERIAL_UNAVAILABLE');
  }, 120_000);

  it('a STALE revocation snapshot is UNAVAILABLE — never "assume not revoked"', async () => {
    trust.material = configuredMaterial({
      revocationFetchedAt: new Date(Date.now() - ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS - 1_000),
    });
    const ceremony = await openCeremony();
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('UNAVAILABLE');
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('UNAVAILABLE');
    expect(artifact.outcomeReason).toBe('REVOCATION_SNAPSHOT_STALE');
  }, 120_000);

  it('a REVOKED certificate is negative device evidence', async () => {
    const revokedSerial = 4242;
    trust.material = configuredMaterial({
      revocations: new Map([[revokedSerial.toString(16), { status: 'REVOKED', reason: 'KEY_COMPROMISE' }]]),
    });
    const ceremony = await openCeremony({ leafSerial: revokedSerial });
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('REVOKED');
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('REVOKED');
    expect(artifact.outcomeReason).toBe('CERTIFICATE_REVOKED');
  }, 120_000);

  it('an IMPORTED key is refused: StrongBox storage is not StrongBox origin (D26-02)', async () => {
    const ceremony = await openCeremony({ keyDescription: { origin: 2 } });
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.outcome).toBe('NEGATIVE');
    expect(artifact.outcomeReason).toBe('KEY_ORIGIN_NOT_GENERATED');
  }, 120_000);

  it('an unlocked device or a failed verified boot is refused', async () => {
    const unlocked = await openCeremony({ keyDescription: { deviceLocked: false } });
    expect((await artifactFor(unlocked.challengeId)).outcomeReason).toBe('DEVICE_NOT_LOCKED');

    const badBoot = await openCeremony({ keyDescription: { verifiedBootState: 2 } });
    expect((await artifactFor(badBoot.challengeId)).outcomeReason).toBe('VERIFIED_BOOT_STATE_UNACCEPTABLE');
  }, 120_000);

  it('an unexpected package or signing identity is refused', async () => {
    const wrongPackage = await openCeremony({ keyDescription: { packageName: 'com.attacker.app' } });
    expect((await artifactFor(wrongPackage.challengeId)).outcomeReason).toBe('APPLICATION_PACKAGE_UNEXPECTED');

    const wrongSigner = await openCeremony({ keyDescription: { signingDigest: randomBytes(32) } });
    expect((await artifactFor(wrongSigner.challengeId)).outcomeReason).toBe('APPLICATION_SIGNING_IDENTITY_UNEXPECTED');
  }, 120_000);

  it('every artifact records the trust material it was judged against', async () => {
    const ceremony = await openCeremony();
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.verifierVersion).toBe('wp26.android-key-attestation.v1');
    expect(artifact.trustAnchorSetVersion).toBe('wp26-test-anchors/1');
    expect(artifact.revocationSnapshotVersion).toBe('wp26-test-revocations/1');
    expect(artifact.publicKeyThumbprint).toBe(deriveP256PublicKeyThumbprint(ceremony.submitted.canonicalPublicKey));
  }, 120_000);
});

// ===========================================================================
// 5. D23-03 — a software-backed key can never become TRUSTED
// ===========================================================================

describe('WP-26/D23-03 a SOFTWARE-backed key cannot become TRUSTED', () => {
  it('a TEE-attested device enrols, and is QUARANTINED — NEGATIVE is DEVICE EVIDENCE (C14-05)', async () => {
    const ceremony = await openCeremony({
      keyDescription: {
        attestationSecurityLevel: ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        keymasterSecurityLevel: ANDROID_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
      },
    });
    expect(ceremony.submitted.result.body.key_storage).toBe('SOFTWARE');
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;
    expect((await approve(enrollmentRequestId, fingerprint)).status).toBe(201);

    const finished = await proveAndCommit(
      enrollmentRequestId,
      fingerprint,
      ceremony.submitted.deviceKeyPair,
      ceremony.submitted.canonicalPublicKey,
    );
    // It ENROLS. Attestation deliberately does not gate the commit — refusing
    // outright would make a verifier outage an enrollment outage. What it does
    // is decide the trust the device starts at, and a TEE certificate offered
    // for a StrongBox profile is a NEGATIVE verdict, which is DEVICE evidence
    // and quarantines. This is the arm of C14-05 that is not an outage.
    expect(finished.commit.body.outcome).toBe('COMMITTED');
    expect(finished.commit.body.trust).not.toBe('TRUSTED');
    expect(finished.commit.body.trust).toBe('QUARANTINED');
    const key = await prisma.deviceKey.findFirst({
      where: { organisationId: fx.orgA, deviceId: finished.commit.body.device_id as string, status: 'CURRENT' },
    });
    expect(key?.keyStorage).toBe('SOFTWARE');
  }, 120_000);

  it('a device enrolled during a trust-material outage starts DEGRADED, never TRUSTED', async () => {
    // The OTHER arm of C14-05, and the one that must not be confused with the
    // first: an outage is not a statement about a device. The device enrols,
    // operates every ordinary path, and simply cannot be TRUSTED until real
    // verification returns.
    trust.material = {
      configured: false,
      reason: 'TEST_PROVIDER_OUTAGE',
      trustAnchorSetVersion: 'wp26-test/none',
      revocationSnapshotVersion: 'wp26-test/none',
    };
    const ceremony = await openCeremony();
    expect(ceremony.submitted.result.body.attestation_outcome).toBe('UNAVAILABLE');
    expect(ceremony.submitted.result.body.key_storage).toBe('SOFTWARE');
    const enrollmentRequestId = ceremony.submitted.result.body.enrollment_request_id as string;
    const fingerprint = ceremony.submitted.result.body.request_fingerprint as string;
    expect((await approve(enrollmentRequestId, fingerprint)).status).toBe(201);

    const finished = await proveAndCommit(
      enrollmentRequestId,
      fingerprint,
      ceremony.submitted.deviceKeyPair,
      ceremony.submitted.canonicalPublicKey,
    );
    expect(finished.commit.body.outcome).toBe('COMMITTED');
    expect(finished.commit.body.trust).toBe('DEGRADED');
    expect(finished.commit.body.trust).not.toBe('QUARANTINED');
  }, 120_000);
});

// ===========================================================================
// 6. D26-04B — the raw chain is restricted
// ===========================================================================

describe('WP-26/D26-04B the raw certificate chain never leaves the restricted store', () => {
  it('it is in the artifact row, and in NO audit payload and NO client-readable response', async () => {
    const ceremony = await openCeremony();
    const leafBase64 = ceremony.submitted.chain.chainBase64[0] as string;
    // A substring long enough to be unmistakable and short enough to survive any
    // re-encoding a leak would have gone through.
    const needle = leafBase64.slice(32, 96);
    expect(needle.length).toBe(64);

    // 1. It IS in the restricted column. If this fails the test below proves
    //    nothing, because there would be nothing to leak.
    const artifact = await artifactFor(ceremony.challengeId);
    expect(artifact.certificateChainDer).toEqual(ceremony.submitted.chain.chainBase64);

    // 2. It is in NO device security event payload, in either tenant.
    const events = await prisma.deviceSecurityEvent.findMany({ where: { organisationId: { in: [fx.orgA, fx.orgB] } } });
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect(JSON.stringify(event.payload)).not.toContain(needle);
    }

    // 3. It is in NO attestation observation, and the observation's reference is
    //    the OPAQUE artifact id rather than anything derived from the evidence.
    const observations = await prisma.deviceAttestationObservation.findMany({ where: { organisationId: fx.orgA } });
    expect(observations.length).toBeGreaterThan(0);
    for (const observation of observations) {
      expect(JSON.stringify(observation)).not.toContain(needle);
    }
    const forThisCeremony = observations.find((row) => row.attestationReference === artifact.id);
    expect(forThisCeremony).toBeDefined();

    // 4. It is in NO enrollment request row — not in the fingerprint, not in the
    //    stored reference, not anywhere.
    const requests = await prisma.enrollmentRequest.findMany({ where: { organisationId: fx.orgA } });
    for (const row of requests) {
      expect(JSON.stringify(row)).not.toContain(needle);
    }

    // 5. It is in NOTHING the server has said to a client during this whole
    //    suite — the mobile responses, the commander's queue, every refusal.
    const commanderQueue = await get(`${COMMAND}/pending?organisation_id=${fx.orgA}`, asSession(fx.cmdApproverA));
    expect(commanderQueue.status).toBe(200);
    for (const sent of responseTranscript) {
      expect(sent).not.toContain(needle);
    }
  }, 180_000);
});
