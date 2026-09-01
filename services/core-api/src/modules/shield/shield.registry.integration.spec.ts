import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS,
  canonicalDeviceKeyRotationPossessionStatement,
  canonicalDevicePossessionStatement,
  canonicalDeviceRequestProofStatement,
  deriveP256PublicKeyThumbprint,
  deviceSequenceNamespaceId,
  type DeviceAttestationOutcome,
  type DeviceCustody,
  type DeviceKeyStorage,
} from '@sentinel/contracts';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { PrismaService } from '../../prisma/prisma.service';
import { PATROL_SWEEP_SCHEDULER } from '../patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../patrol/patrol-sweep.scheduler.test-support';
import { DEVICE_ATTESTATION_EVALUATOR } from './attestation.evaluator';
import { DeviceEnrollmentService } from './device-enrollment.service';
import { DeviceKeyService } from './device-key.service';
import { DeviceRegistryService } from './device-registry.service';
import { DeviceTrustService } from './device-trust.service';
import { ShieldRepository } from './shield.repository';
import {
  generateTestDeviceKeyPair,
  offCurveP256PublicKey,
  SettableDeviceAttestationEvaluator,
  signCanonicalStatement,
  type TestDeviceKeyPair,
} from './shield.test-support';
import type { CommitEnrollmentOutcome } from './shield.types';

/**
 * WP-24 Shield acceptance suite — the locked device-registry rules, exercised
 * against the live stack through the REAL module graph (AppModule), the real
 * frozen evaluators and the real Postgres constraints.
 *
 * The module deliberately publishes NO HTTP surface (D24-13: there is still no
 * production facility that authenticates an incoming physical device), so
 * these tests call the services directly with a `Principal` built exactly as
 * the global DevAuthGuard builds it — the same `buildPrincipal`, so `hasAction`
 * is derived from the §62 role table and no test can assert an authority the
 * seeded roles do not grant.
 *
 * THE INVARIANT UNDER TEST (§62.1, carried through every M3 work package)
 * ---------------------------------------------------------------------
 *     USER AUTHORITY + DEVICE IDENTITY + CURRENT DEVICE TRUST
 *       + SITE/CONTEXT AUTHORITY must remain INDEPENDENT facts.
 *
 * A user login never manufactures trusted hardware. A registered device never
 * manufactures user authority.
 *
 * THIS IS NOT PROOF C (D24-15). Every "device" below is a P-256 keypair this
 * process generated. A successful enrollment proves the REGISTRY works; it
 * proves nothing whatsoever about hardware, and there is no client, no gateway
 * and no attestation vendor anywhere in this suite.
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

const tag = `wp24_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

const PROFILE = 'P256_ECDSA_SHA256';

const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  /** Issues bootstrap grants. Never approves — D24-03 forbids self-approval. */
  commanderIssuerA: `${tag}_cmdIssuerA`,
  /** Approves request fingerprints. A DIFFERENT human, by rule. */
  commanderApproverA: `${tag}_cmdApproverA`,
  /** A commander whose role is scoped to siteA2 only. */
  commanderSiteA2: `${tag}_cmdSiteA2`,
  /**
   * C16-06: a commander holding `site.commander` ORGANISATION-WIDE — a role
   * assignment with a NULL site id. This is what "genuine organisation-wide
   * authority" means, and it is deliberately a different fixture from a
   * commander who merely holds the action at some site.
   */
  commanderOrgWideA: `${tag}_cmdOrgWideA`,
  operativeAlpha: `${tag}_opAlpha`,
  operativeBravo: `${tag}_opBravo`,
  operatorA: `${tag}_operatorA`,
  adminA: `${tag}_adminA`,
  commanderIssuerB: `${tag}_cmdIssuerB`,
  commanderApproverB: `${tag}_cmdApproverB`,
  operativeB: `${tag}_opB`,
};

/** Semantically identical to what the global DevAuthGuard attaches to a request. */
function principalFor(userId: string, role: string, siteId: string | null, organisationId: string): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 5 }, organisation_id: organisationId, roles: [{ role, site_id: siteId }] });
}

interface TenantFixture {
  readonly organisationId: string;
  readonly siteId: string;
  readonly issuer: Principal;
  readonly approver: Principal;
  readonly intendedUserId: string;
  readonly intendedUser: Principal;
}

let app: INestApplication;
let prisma: PrismaService;
let enrollment: DeviceEnrollmentService;
let trust: DeviceTrustService;
let registry: DeviceRegistryService;
let deviceKeys: DeviceKeyService;
let repository: ShieldRepository;
let attestation: SettableDeviceAttestationEvaluator;
let A: TenantFixture;
let B: TenantFixture;
/** C16-06: genuine organisation-wide `site.commander`, holding every device.* action. */
let orgWideCommanderA: Principal;
/**
 * C16-05: the human who may restore trust. `site.commander` carries
 * `device.trust.restore`, and after C16-06 a trust change also needs authority
 * over the whole device — the devices under restoration test live at siteA1
 * only, so the siteA1 approver qualifies.
 */
let restorer: Principal;

async function seed(): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-24 Org A' },
      { id: fx.orgB, name: 'WP-24 Org B' },
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
    { id: fx.commanderIssuerA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.commanderApproverA, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.commanderSiteA2, org: fx.orgA, role: 'site.commander', site: fx.siteA2 },
    { id: fx.operativeAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.operativeBravo, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.operatorA, org: fx.orgA, role: 'operator', site: fx.siteA1 },
    { id: fx.adminA, org: fx.orgA, role: 'admin', site: fx.siteA1 },
    { id: fx.commanderIssuerB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.commanderApproverB, org: fx.orgB, role: 'site.commander', site: fx.siteB1 },
    { id: fx.operativeB, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
  ];
  await prisma.user.createMany({
    data: users.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: users.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });

  // C16-06: the ORG-WIDE commander. `site_id: null` is what makes the
  // assignment unrestricted, and it is the only thing that does.
  await prisma.user.create({
    data: {
      id: fx.commanderOrgWideA,
      organisationId: fx.orgA,
      email: `${fx.commanderOrgWideA}@example.invalid`,
      displayName: fx.commanderOrgWideA,
      clearance: 5,
    },
  });
  await prisma.userRole.create({ data: { userId: fx.commanderOrgWideA, role: 'site.commander', siteId: null } });
}

async function cleanup(): Promise<void> {
  const organisationId = { in: [fx.orgA, fx.orgB] };
  // History first (no lifecycle foreign keys at all, per the WP-17A
  // live-state / historical-artefact split), then live state in
  // reverse-dependency order.
  await prisma.deviceSecurityEvent.deleteMany({ where: { organisationId } });
  await prisma.deviceTrustTransition.deleteMany({ where: { organisationId } });
  await prisma.deviceAttestationObservation.deleteMany({ where: { organisationId } });
  await prisma.deviceNonceConsumption.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationVerification.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationChallenge.deleteMany({ where: { organisationId } });
  await prisma.deviceKeyRotationRequest.deleteMany({ where: { organisationId } });
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
    // D24-07: the attestation seam is replaceable by exactly ONE provider
    // swap. A spec can supply evidence and observe what the registry concludes;
    // it can never reach the trust rules, which live in frozen contracts.
    .overrideProvider(DEVICE_ATTESTATION_EVALUATOR)
    .useValue(attestation)
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();

  prisma = app.get(PrismaService);
  enrollment = app.get(DeviceEnrollmentService);
  trust = app.get(DeviceTrustService);
  registry = app.get(DeviceRegistryService);
  deviceKeys = app.get(DeviceKeyService);
  repository = app.get(ShieldRepository);

  await cleanup();
  await seed();

  A = {
    organisationId: fx.orgA,
    siteId: fx.siteA1,
    issuer: principalFor(fx.commanderIssuerA, 'site.commander', fx.siteA1, fx.orgA),
    approver: principalFor(fx.commanderApproverA, 'site.commander', fx.siteA1, fx.orgA),
    intendedUserId: fx.operativeAlpha,
    intendedUser: principalFor(fx.operativeAlpha, 'field.operative', fx.siteA1, fx.orgA),
  };
  orgWideCommanderA = buildPrincipal({
    user: { id: fx.commanderOrgWideA, clearance: 5 },
    organisation_id: fx.orgA,
    roles: [{ role: 'site.commander', site_id: null }],
  });
  B = {
    organisationId: fx.orgB,
    siteId: fx.siteB1,
    issuer: principalFor(fx.commanderIssuerB, 'site.commander', fx.siteB1, fx.orgB),
    approver: principalFor(fx.commanderApproverB, 'site.commander', fx.siteB1, fx.orgB),
    intendedUserId: fx.operativeB,
    intendedUser: principalFor(fx.operativeB, 'field.operative', fx.siteB1, fx.orgB),
  };
  restorer = A.approver;
}, 120_000);

afterAll(async () => {
  if (prisma !== undefined) await cleanup();
  if (app !== undefined) await app.close();
});

// ---------------------------------------------------------------------------
// Ceremony helpers — every step is a real service call, never a shortcut
// ---------------------------------------------------------------------------

interface CeremonyOptions {
  tenant?: TenantFixture;
  keyPair?: TestDeviceKeyPair;
  keyStorage?: DeviceKeyStorage;
  custody?: DeviceCustody;
  custodyRegimeId?: string | null;
  attestationOutcome?: DeviceAttestationOutcome;
}

interface PreparedCeremony {
  tenant: TenantFixture;
  keyPair: TestDeviceKeyPair;
  grantId: string;
  grantToken: string;
  enrollmentRequestId: string;
  requestFingerprint: string;
  challengeId: string;
  custodyRegimeId: string | null;
}

const traceId = (): string => `trace-${randomUUID()}`;

/** Steps 1..5: grant, request, approval, challenge, verified possession. */
async function prepareCeremony(options: CeremonyOptions = {}): Promise<PreparedCeremony> {
  const tenant = options.tenant ?? A;
  const keyPair = options.keyPair ?? generateTestDeviceKeyPair();
  const custody = options.custody ?? 'PERSONAL';
  const custodyRegimeId = options.custodyRegimeId ?? null;
  attestation.outcome = options.attestationOutcome ?? 'UNAVAILABLE';

  const grant = await enrollment.issueBootstrapGrant(tenant.issuer, {
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    intendedUserId: tenant.intendedUserId,
    traceId: traceId(),
  });
  if (grant.outcome !== 'ISSUED') throw new Error(`grant not issued: ${JSON.stringify(grant)}`);

  const request = await enrollment.createEnrollmentRequest({
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    intendedUserId: tenant.intendedUserId,
    bootstrapToken: grant.token,
    custody,
    publicKey: keyPair.publicKey,
    keyStorage: options.keyStorage ?? 'HARDWARE_BACKED',
    claimedSignatureProfile: PROFILE,
    custodyRegimeId,
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

  const challenge = await issueAndAnswerChallenge(tenant, request.enrollmentRequestId, request.requestFingerprint, keyPair);

  return {
    tenant,
    keyPair,
    grantId: grant.grantId,
    grantToken: grant.token,
    enrollmentRequestId: request.enrollmentRequestId,
    requestFingerprint: request.requestFingerprint,
    challengeId: challenge,
    custodyRegimeId,
  };
}

/** Issues a fresh challenge and answers it with `signingKey`. Returns the challenge id. */
async function issueAndAnswerChallenge(
  tenant: TenantFixture,
  enrollmentRequestId: string,
  requestFingerprint: string,
  signingKey: TestDeviceKeyPair,
  enrolledKey: TestDeviceKeyPair = signingKey,
): Promise<string> {
  const challenge = await enrollment.issuePossessionChallenge(tenant.intendedUser, {
    organisationId: tenant.organisationId,
    enrollmentRequestId,
    traceId: traceId(),
  });
  if (challenge.outcome !== 'ISSUED') throw new Error(`challenge refused: ${JSON.stringify(challenge)}`);

  // EXACTLY the bytes the contract defines. The thumbprint bound in is the
  // ENROLLED key's — an attacker signing with their own key still has to
  // produce a signature over the approved key's statement.
  const statement = canonicalDevicePossessionStatement({
    challenge_id: challenge.challengeId,
    enrollment_request_id: enrollmentRequestId,
    enrollment_request_fingerprint: requestFingerprint,
    nonce: challenge.nonce,
    public_key_thumbprint: deriveP256PublicKeyThumbprint(enrolledKey.publicKey),
    signature_profile: PROFILE,
  });

  await enrollment.verifyPossession({
    organisationId: tenant.organisationId,
    enrollmentRequestId,
    challengeId: challenge.challengeId,
    response: {
      schema_version: 1,
      challenge_id: challenge.challengeId,
      enrollment_request_id: enrollmentRequestId,
      claimed_signature_profile: PROFILE,
      signature: signCanonicalStatement(signingKey.privateKey, statement),
      answered_at: new Date().toISOString(),
    },
    traceId: traceId(),
  });

  return challenge.challengeId;
}

/** Step 6. */
async function commit(prepared: PreparedCeremony): Promise<CommitEnrollmentOutcome> {
  return enrollment.commitEnrollment(prepared.tenant.intendedUser, {
    organisationId: prepared.tenant.organisationId,
    enrollmentRequestId: prepared.enrollmentRequestId,
    challengeId: prepared.challengeId,
    // C16-01: THERE IS NO `custodyRegimeId` PARAMETER ANY MORE. The régime is
    // read from the APPROVAL row, so a commit cannot name one the approver
    // never saw.
    traceId: traceId(),
  });
}

interface EnrolledDevice {
  deviceId: string;
  keyId: string;
  keyVersion: number;
  trust: string;
  sequenceNamespaceId: string;
  keyPair: TestDeviceKeyPair;
  prepared: PreparedCeremony;
}

async function enrol(options: CeremonyOptions = {}): Promise<EnrolledDevice> {
  const prepared = await prepareCeremony(options);
  const committed = await commit(prepared);
  if (committed.outcome !== 'COMMITTED') throw new Error(`commit refused: ${JSON.stringify(committed)}`);
  return {
    deviceId: committed.deviceId,
    keyId: committed.keyId,
    keyVersion: committed.keyVersion,
    trust: committed.trust,
    sequenceNamespaceId: committed.sequenceNamespaceId,
    keyPair: prepared.keyPair,
    prepared,
  };
}

/** The D24-10A rotation ceremony, end to end, with both halves of the two-key proof. */
async function rotate(
  device: EnrolledDevice,
  options: { newKeyPair?: TestDeviceKeyPair; keyStorage?: DeviceKeyStorage } = {},
): Promise<{
  outcome: Awaited<ReturnType<DeviceKeyService['commitKeyRotation']>>;
  newKeyPair: TestDeviceKeyPair;
  /** C16-R4: everything an EXACT retry of this rotation needs, byte for byte. */
  rotationRequestId: string;
  challengeId: string;
  continuityProof: Record<string, unknown>;
}> {
  const newKeyPair = options.newKeyPair ?? generateTestDeviceKeyPair();
  const tenant = device.prepared.tenant;

  const request = await deviceKeys.requestKeyRotation(tenant.approver, {
    organisationId: tenant.organisationId,
    deviceId: device.deviceId,
    newPublicKey: newKeyPair.publicKey,
    newKeyStorage: options.keyStorage ?? 'HARDWARE_BACKED',
    traceId: traceId(),
  });
  if (request.outcome !== 'REQUESTED') throw new Error(`rotation not requested: ${JSON.stringify(request)}`);

  const challenge = await deviceKeys.issueRotationChallenge(tenant.approver, {
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    traceId: traceId(),
  });
  if (challenge.outcome !== 'ISSUED') throw new Error(`rotation challenge refused: ${JSON.stringify(challenge)}`);

  const standing = await registry.readDeviceStanding(tenant.approver, { organisationId: tenant.organisationId, deviceId: device.deviceId });
  if (standing.outcome !== 'FOUND') throw new Error('device vanished');

  // The NEW key proves possession.
  const possessionStatement = canonicalDeviceKeyRotationPossessionStatement({
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
      signature: signCanonicalStatement(newKeyPair.privateKey, possessionStatement),
      answered_at: new Date().toISOString(),
    },
    traceId: traceId(),
  });

  // The CURRENT key proves continuity, over the EXACT rotation-request
  // fingerprint. This is what stops a valid current-key proof being borrowed
  // for a different replacement key.
  const continuityProof = buildContinuityProof(device.keyPair, {
    organisationId: tenant.organisationId,
    siteId: tenant.siteId,
    actorUserId: tenant.intendedUserId,
    deviceId: device.deviceId,
    keyId: standing.standing.currentKeyId as string,
    keyVersion: standing.standing.currentKeyVersion as number,
    payloadDigest: request.rotationRequestFingerprint,
  });

  const outcome = await deviceKeys.commitKeyRotation(tenant.approver, {
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    challengeId: challenge.challengeId,
    continuityProof,
    traceId: traceId(),
  });

  return { outcome, newKeyPair, rotationRequestId: request.rotationRequestId, challengeId: challenge.challengeId, continuityProof };
}

/** C16-01: one server-issued custody regime, through the real service. */
async function defineRegime(issuer: Principal, organisationId: string, siteId: string): Promise<string> {
  const defined = await enrollment.defineCustodyRegime(issuer, {
    organisationId,
    siteId,
    name: `regime-${randomUUID()}`,
    traceId: traceId(),
  });
  if (defined.outcome !== 'DEFINED') throw new Error(`regime not defined: ${JSON.stringify(defined)}`);
  return defined.custodyRegimeId;
}

/**
 * C16-06: a SECOND active site association for a device.
 *
 * Written directly because WP-24 publishes no re-association service — the
 * multi-site case is a real shape of the schema (`device_site_scope_key` is
 * per site) and the ABAC rules must hold for it whether or not this work
 * package exposes a way to create it.
 */
async function associateExtraSite(deviceId: string, siteId: string): Promise<void> {
  const existing = await prisma.deviceSiteScope.findFirstOrThrow({ where: { deviceId } });
  await prisma.deviceSiteScope.create({
    data: {
      organisationId: existing.organisationId,
      deviceId,
      siteId,
      custody: existing.custody,
      assignedUserId: existing.assignedUserId,
      custodyRegimeId: existing.custodyRegimeId,
      associatedAt: new Date(),
    },
  });
}

/**
 * C16-05: pushes a device's whole attestation history back by `ageMs`.
 *
 * The grace is judged against the SERVER clock and the recorded evaluation
 * instants, and there is no way to move the server clock in a live suite. So
 * the evidence is aged instead, which exercises the same arithmetic from the
 * other side and keeps the authoritative clock authoritative.
 */
/**
 * C16-R5: the same ageing, but PRESERVING THE ORDER of the history.
 *
 * `ageAttestation` stamps every row with ONE instant, which is exactly right
 * when a fresh observation is about to be appended after it — and useless when
 * the point of the fixture is that NO further observation ever arrives. With
 * equal timestamps the "newest observation" is decided by the uuid tiebreak,
 * so which row is latest becomes a coin toss. Shifting each row by the same
 * delta keeps `VERIFIED -> UNAVAILABLE` in that order while moving the whole
 * history past the grace.
 */
async function ageAttestationPreservingOrder(deviceId: string, ageMs: number): Promise<void> {
  const rows = await prisma.deviceAttestationObservation.findMany({
    where: { deviceId },
    select: { id: true, evaluatedAt: true, observedAt: true },
  });
  for (const row of rows) {
    await prisma.deviceAttestationObservation.update({
      where: { id: row.id },
      data: {
        evaluatedAt: new Date(row.evaluatedAt.getTime() - ageMs),
        observedAt: new Date(row.observedAt.getTime() - ageMs),
      },
    });
  }
}

async function ageAttestation(deviceId: string, ageMs: number): Promise<void> {
  const at = new Date(Date.now() - ageMs);
  await prisma.deviceAttestationObservation.updateMany({
    where: { deviceId },
    data: { evaluatedAt: at, observedAt: at },
  });
}

function buildContinuityProof(
  signer: TestDeviceKeyPair,
  input: {
    organisationId: string;
    siteId: string;
    actorUserId: string;
    deviceId: string;
    keyId: string;
    keyVersion: number;
    payloadDigest: string;
  },
): Record<string, unknown> {
  const base = {
    schema_version: 1 as const,
    context_id: randomUUID(),
    organisation_id: input.organisationId,
    site_id: input.siteId,
    actor_user_id: input.actorUserId,
    device_id: input.deviceId,
    key_id: input.keyId,
    key_version: input.keyVersion,
    purpose: 'DEVICE_KEY_ROTATION' as const,
    payload_digest: input.payloadDigest,
    nonce: randomBytes(24).toString('base64url'),
    issued_at: new Date().toISOString(),
  };
  // C15-01: what the device signs binds the SERVER's profile, never its own
  // claim — the contract's statement builder performs that substitution.
  const statement = canonicalDeviceRequestProofStatement({ ...base, signature_profile: PROFILE });
  return { ...base, claimed_signature_profile: PROFILE, signature: signCanonicalStatement(signer.privateKey, statement) };
}

// ---------------------------------------------------------------------------

describe('WP-24 Shield device registry (live)', () => {
  // -------------------------------------------------------------------------
  // D24-04a — tenant integrity BELOW the service layer
  // -------------------------------------------------------------------------

  describe('D24-04a tenant integrity is enforced by the database, not only by services', () => {
    it('cross-org site binding is rejected BY THE DATABASE', async () => {
      // No service is involved. The composite (id, organisation_id) reference
      // means the row pairing org A with org B's site cannot exist at all —
      // a service check is a second line of defence, never the only one.
      await expect(
        prisma.enrollmentBootstrapGrant.create({
          data: {
            organisationId: fx.orgA,
            siteId: fx.siteB1,
            intendedUserId: fx.operativeAlpha,
            issuedByUserId: fx.commanderIssuerA,
            tokenDigest: randomBytes(32).toString('hex'),
            issuedAt: new Date(),
            expiresAt: new Date(Date.now() + 60_000),
          },
        }),
      ).rejects.toThrow();

      // And the same pairing through the service refuses safely, with the SAME
      // answer a nonexistent site gets.
      const refused = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteB1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      const invented = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: `${tag}_no_such_site`,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      const otherOwnSite = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA2,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      // ANOTHER TENANT REAL SITE, AN INVENTED ID, AND A REAL SITE IN THIS
      // TENANT THE CALLER DOES NOT HOLD ALL ANSWER THE SAME WAY. Authority is
      // evaluated before existence, so the refusal describes the CALLER scope
      // and never the estate — which is what stops this path being used to
      // discover that some id is a real site somewhere in the platform.
      expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'SITE_NOT_IN_SCOPE' });
      expect(invented).toEqual(refused);
      expect(otherOwnSite).toEqual(refused);
    });

    it('cross-org intended user is rejected by the database and by the service alike', async () => {
      await expect(
        prisma.enrollmentBootstrapGrant.create({
          data: {
            organisationId: fx.orgA,
            siteId: fx.siteA1,
            intendedUserId: fx.operativeB,
            issuedByUserId: fx.commanderIssuerA,
            tokenDigest: randomBytes(32).toString('hex'),
            issuedAt: new Date(),
            expiresAt: new Date(Date.now() + 60_000),
          },
        }),
      ).rejects.toThrow();

      expect(
        await enrollment.issueBootstrapGrant(A.issuer, {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeB,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'USER_NOT_FOUND' });
    });

    it('the composite candidate keys D24-04a depends on actually exist', async () => {
      expect(await repository.compositePairingExists('sites', fx.siteA1, fx.orgA)).toBe(true);
      expect(await repository.compositePairingExists('sites', fx.siteB1, fx.orgA)).toBe(false);
      expect(await repository.compositePairingExists('users', fx.operativeAlpha, fx.orgA)).toBe(true);
      expect(await repository.compositePairingExists('users', fx.operativeB, fx.orgA)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // D24-02 — authority is explicit and never inherited
  // -------------------------------------------------------------------------

  describe('D24-02 device-security authority is explicit, never inherited', () => {
    it('an unauthorised role cannot issue a bootstrap grant', async () => {
      for (const [label, principal] of [
        ['field.operative', A.intendedUser],
        ['operator', principalFor(fx.operatorA, 'operator', fx.siteA1, fx.orgA)],
        ['admin', principalFor(fx.adminA, 'admin', fx.siteA1, fx.orgA)],
      ] as const) {
        const refused = await enrollment.issueBootstrapGrant(principal, {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          traceId: traceId(),
        });
        expect(refused, label).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });
      }
    });

    it('operator READ cannot become operator WRITE', async () => {
      const device = await enrol();
      const operator = principalFor(fx.operatorA, 'operator', fx.siteA1, fx.orgA);

      // The read it DOES hold works — otherwise the refusals below would prove
      // nothing more than that the fixture is broken.
      const read = await registry.readDeviceStanding(operator, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(read.outcome).toBe('FOUND');

      // Every write refuses.
      expect(
        (await enrollment.issueBootstrapGrant(operator, {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
      expect(
        (await trust.changeDeviceTrust(operator, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'TRUSTED',
          reason: 'operator attempt',
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
      expect(
        (await trust.declareDisposition(operator, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'STOLEN',
          reason: 'operator attempt',
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
      expect(
        (await deviceKeys.requestKeyRotation(operator, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          newPublicKey: generateTestDeviceKeyPair().publicKey,
          newKeyStorage: 'HARDWARE_BACKED',
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
    });

    it('admin holds NO device write authority — and no device read either', async () => {
      // PLATFORM ADMINISTRATION IS NOT AUTHORITY OVER HARDWARE TRUST. An
      // attacker who reaches an administrative account must not acquire the
      // power to decide what hardware Sentinel believes.
      const device = await enrol();
      const admin = principalFor(fx.adminA, 'admin', fx.siteA1, fx.orgA);

      expect((await registry.readDeviceStanding(admin, { organisationId: fx.orgA, deviceId: device.deviceId })).outcome).toBe('REFUSED');
      expect((await registry.listDevices(admin, { organisationId: fx.orgA })).outcome).toBe('REFUSED');
      expect(
        (await enrollment.approveEnrollmentRequest(admin, {
          organisationId: fx.orgA,
          enrollmentRequestId: device.prepared.enrollmentRequestId,
          expectedRequestFingerprint: device.prepared.requestFingerprint,
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
      expect(
        (await trust.declareDisposition(admin, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'LOST',
          reason: 'admin attempt',
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');

      // The device is untouched by any of it.
      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(standing.outcome === 'FOUND' && standing.standing.revocationDisposition).toBeNull();
    });

    it('a site-scoped commander cannot reach a device at a site they do not hold', async () => {
      const device = await enrol();
      const otherSiteCommander = principalFor(fx.commanderSiteA2, 'site.commander', fx.siteA2, fx.orgA);
      expect(await registry.readDeviceStanding(otherSiteCommander, { organisationId: fx.orgA, deviceId: device.deviceId })).toEqual({
        outcome: 'REFUSED',
        refusal: 'DEVICE_NOT_FOUND',
      });
      expect(
        (await trust.changeDeviceTrust(otherSiteCommander, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'OFFLINE',
          reason: 'out of scope',
          traceId: traceId(),
        })),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });
    });
  });

  // -------------------------------------------------------------------------
  // D24-03 — the dual human/device binding
  // -------------------------------------------------------------------------

  describe('D24-03 enrollment requires a dual human/device binding', () => {
    it('the bootstrap ISSUER cannot approve the same request', async () => {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');
      const keyPair = generateTestDeviceKeyPair();
      const request = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: grant.token,
        custody: 'PERSONAL',
        publicKey: keyPair.publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('request');

      expect(
        await enrollment.approveEnrollmentRequest(A.issuer, {
          organisationId: fx.orgA,
          enrollmentRequestId: request.enrollmentRequestId,
          expectedRequestFingerprint: request.requestFingerprint,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ISSUER_MAY_NOT_APPROVE' });

      // The request is still REQUESTED: a refused approval advanced nothing.
      const row = await prisma.enrollmentRequest.findUniqueOrThrow({ where: { id: request.enrollmentRequestId } });
      expect(row.state).toBe('REQUESTED');
    });

    it('the intended user cannot approve their own request', async () => {
      // The intended user holds no approval action at all, but the separation
      // is asserted independently of the role table: even a commander who
      // happened to be the intended user must be refused.
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.commanderApproverA,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');
      const request = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.commanderApproverA,
        bootstrapToken: grant.token,
        custody: 'PERSONAL',
        publicKey: generateTestDeviceKeyPair().publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('request');

      expect(
        await enrollment.approveEnrollmentRequest(A.approver, {
          organisationId: fx.orgA,
          enrollmentRequestId: request.enrollmentRequestId,
          expectedRequestFingerprint: request.requestFingerprint,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'INTENDED_USER_MAY_NOT_APPROVE' });
    });

    it('C14-02: a stolen bootstrap grant plus an attacker key cannot win the approved enrollment', async () => {
      // The honest ceremony, approved and ready.
      const honest = await prepareCeremony();

      // The attacker holds the grant secret and generates their own keypair.
      const attackerKey = generateTestDeviceKeyPair();

      // C16-02 STOPS THIS EARLIER THAN IT USED TO. One grant opens exactly one
      // ceremony, so presenting the stolen secret with a different key is not a
      // second candidate the commit has to refuse later — it is refused on the
      // spot, and no second approval can ever be collected behind this grant.
      expect(
        await enrollment.createEnrollmentRequest({
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          bootstrapToken: honest.grantToken,
          custody: 'PERSONAL',
          publicKey: attackerKey.publicKey,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: PROFILE,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_CONFLICT' });

      // The ORIGINAL C14-02 property is asserted on its own terms, with a
      // grant the attacker has stolen BEFORE anyone used it. Possession of a
      // grant plus possession of a key is still not an enrollment: what is
      // missing is the independent human approval of THIS request's exact
      // fingerprint, and nothing the attacker holds can produce one.
      const stolen = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (stolen.outcome !== 'ISSUED') throw new Error('stolen grant');
      const attackerRequest = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: stolen.token,
        custody: 'PERSONAL',
        publicKey: attackerKey.publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (attackerRequest.outcome !== 'REQUESTED') throw new Error('attacker request');

      // It is a DIFFERENT request with a DIFFERENT fingerprint, and the
      // commander's approval of the honest one does not reach it.
      expect(attackerRequest.requestFingerprint).not.toBe(honest.requestFingerprint);
      expect(
        await enrollment.approveEnrollmentRequest(A.approver, {
          organisationId: fx.orgA,
          enrollmentRequestId: attackerRequest.enrollmentRequestId,
          expectedRequestFingerprint: honest.requestFingerprint,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' });

      // The ceremony has an ORDER and no step is skippable. Without a human
      // approval of THIS request the attacker cannot even obtain a possession
      // challenge, so there is nothing for their key to sign.
      expect(
        await enrollment.issuePossessionChallenge(A.intendedUser, {
          organisationId: fx.orgA,
          enrollmentRequestId: attackerRequest.enrollmentRequestId,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_STATE_INVALID' });

      // And forcing the commit anyway — with the honest ceremony's challenge,
      // or with any challenge id at all — dies on the missing approval.
      for (const challengeId of [honest.challengeId, randomUUID()]) {
        expect(
          await enrollment.commitEnrollment(A.intendedUser, {
            organisationId: fx.orgA,
            enrollmentRequestId: attackerRequest.enrollmentRequestId,
            challengeId,
            traceId: traceId(),
          }),
          challengeId,
        ).toEqual({ outcome: 'REFUSED', refusal: 'APPROVAL_MISSING' });
      }
      expect(attackerKey.publicKey).not.toBe(honest.keyPair.publicKey);
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: attackerRequest.enrollmentRequestId } })).toBe(0);
    });

    it('approval of a DIFFERENT request fingerprint refuses', async () => {
      const other = await prepareCeremony();

      // A request that has already been approved cannot be approved again at
      // all — a second approval is not a decision, and the state machine says
      // so before any fingerprint is compared.
      const approvedOnce = await prepareCeremonyStoppingAtApproval();
      expect(
        await enrollment.approveEnrollmentRequest(A.approver, {
          organisationId: fx.orgA,
          enrollmentRequestId: approvedOnce.enrollmentRequestId,
          expectedRequestFingerprint: approvedOnce.requestFingerprint,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ALREADY_APPROVED' });

      // ... and on an UNAPPROVED request, where the state does not mask it.
      const fresh = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (fresh.outcome !== 'ISSUED') throw new Error('grant');
      const request = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: fresh.token,
        custody: 'PERSONAL',
        publicKey: generateTestDeviceKeyPair().publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('request');
      expect(
        await enrollment.approveEnrollmentRequest(A.approver, {
          organisationId: fx.orgA,
          enrollmentRequestId: request.enrollmentRequestId,
          expectedRequestFingerprint: other.requestFingerprint,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' });
    });
  });

  // -------------------------------------------------------------------------
  // D24-03a — the bootstrap grant
  // -------------------------------------------------------------------------

  describe('D24-03a the bootstrap grant is single-use, scoped and burnable', () => {
    it('C16-02: a second, DIFFERENT enrollment under one grant is refused AT REQUEST TIME', async () => {
      const first = await enrol();

      // Before C16-02 this opened a whole second ceremony behind one grant,
      // collected its OWN human approval, and was only stopped at commit by the
      // replay identity. Two approved candidates behind one piece of provenance
      // is the problem; being refused at commit was the symptom.
      const secondRequest = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: first.prepared.grantToken,
        custody: 'PERSONAL',
        publicKey: generateTestDeviceKeyPair().publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      expect(secondRequest).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_CONFLICT' });

      // NEVER A SECOND REQUEST, AND NEVER A SECOND DEVICE.
      expect(await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgA, bootstrapGrantId: first.prepared.grantId } })).toBe(1);
      const grantDevices = await prisma.device.findMany({
        where: { organisationId: fx.orgA, enrollmentRequest: { bootstrapGrantId: first.prepared.grantId } },
      });
      expect(grantDevices.map((row) => row.id)).toEqual([first.deviceId]);
    });

    it('C16-02: an IDENTICAL repeat submission under one grant converges on the existing request', async () => {
      const prepared = await prepareCeremony();

      const repeat = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: prepared.grantToken,
        custody: 'PERSONAL',
        publicKey: prepared.keyPair.publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      // A dropped response is a RETRY, not a conflict: it converges on the
      // request that already exists rather than being told its own earlier
      // success was an error.
      expect(repeat.outcome).toBe('CONVERGED');
      if (repeat.outcome !== 'CONVERGED') throw new Error('unreachable');
      expect(repeat.enrollmentRequestId).toBe(prepared.enrollmentRequestId);
      expect(repeat.requestFingerprint).toBe(prepared.requestFingerprint);
      expect(await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgA, bootstrapGrantId: prepared.grantId } })).toBe(1);
    });

    it('C16-02: the DATABASE refuses a second request row under one grant', async () => {
      const prepared = await prepareCeremony();
      const existing = await prisma.enrollmentRequest.findUniqueOrThrow({ where: { id: prepared.enrollmentRequestId } });

      // No service involved. `enrollment_request_grant_key` is what holds when
      // the service is bypassed entirely.
      await expect(
        prisma.enrollmentRequest.create({
          data: {
            organisationId: fx.orgA,
            siteId: fx.siteA1,
            intendedUserId: fx.operativeAlpha,
            bootstrapGrantId: existing.bootstrapGrantId,
            custody: 'PERSONAL',
            custodyRegimeId: null,
            publicKey: generateTestDeviceKeyPair().publicKey,
            publicKeyThumbprint: 'x'.repeat(64),
            keyStorage: 'HARDWARE_BACKED',
            claimedSignatureProfile: PROFILE,
            serverSelectedSignatureProfile: PROFILE,
            requestFingerprint: 'y'.repeat(64),
            approvedSemanticsDigest: 'z'.repeat(64),
            attestationOutcome: 'UNAVAILABLE',
            attestationEvaluatedAt: new Date(),
            attestationReference: null,
            requestedAt: new Date(),
            state: 'REQUESTED',
          },
        }),
      ).rejects.toThrow(/enrollment_request_grant_key|Unique constraint/iu);
    });

    it('changed semantics behind a spent identity CONFLICTS and mutates nothing', async () => {
      const first = await enrol();
      const before = await prisma.deviceNonceConsumption.findFirstOrThrow({
        where: { organisationId: fx.orgA, ceremony: 'BOOTSTRAP_GRANT', storedOutcomeRef: first.deviceId },
      });

      // With one request per grant, a second ceremony can no longer be built
      // through the service — so the changed SEMANTICS are injected where the
      // conflict actually lives: the spent identity is made to record a
      // different statement fingerprint, exactly as a genuinely different
      // earlier ceremony would have. This is the D24-11 detection under test,
      // not the request table.
      await prisma.deviceNonceConsumption.update({
        where: { id: before.id },
        data: { statementFingerprint: `${'0'.repeat(63)}1` },
      });

      const refused = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: first.prepared.enrollmentRequestId,
        // The ceremony's OWN challenge — exactly what an honest retry presents.
        challengeId: first.prepared.challengeId,
        traceId: traceId(),
      });
      expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_REUSED' });

      // The stored consumption row still holds what the conflict was detected
      // against. A conflict never rewrites what the identity was spent on, and
      // C16-02's rollback did not take the pre-existing row with it: it was
      // never part of the refused transaction.
      const after = await prisma.deviceNonceConsumption.findUniqueOrThrow({ where: { id: before.id } });
      expect(after.storedOutcomeRef).toBe(first.deviceId);
      expect(after.statementFingerprint).toBe(`${'0'.repeat(63)}1`);

      // And exactly one device still exists for this ceremony.
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: first.prepared.enrollmentRequestId } })).toBe(1);
    });

    it('an EXPIRED grant refuses, and the refusal names the grant rather than the clock', async () => {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');
      // Rewind the whole window into the past, keeping its length inside the
      // contract's ceiling so the row still parses as a legal grant.
      const issuedAt = new Date(Date.now() - 20 * 60_000);
      await prisma.enrollmentBootstrapGrant.update({
        where: { id: grant.grantId },
        data: { issuedAt, expiresAt: new Date(issuedAt.getTime() + 600_000) },
      });

      expect(
        await enrollment.createEnrollmentRequest({
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          bootstrapToken: grant.token,
          custody: 'PERSONAL',
          publicKey: generateTestDeviceKeyPair().publicKey,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: PROFILE,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_UNUSABLE' });
    });

    it('presenting a grant in an UNEXPECTED context BURNS it and raises BOOTSTRAP_REPLAY_REFUSED', async () => {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');

      // A probe: the right secret, the wrong intended user.
      expect(
        await enrollment.createEnrollmentRequest({
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeBravo,
          bootstrapToken: grant.token,
          custody: 'PERSONAL',
          publicKey: generateTestDeviceKeyPair().publicKey,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: PROFILE,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'BOOTSTRAP_CONTEXT_MISMATCH' });

      // A probe is not a typo: the grant is burned, so the attacker cannot
      // keep trying it against every user and site in turn.
      const burned = await prisma.enrollmentBootstrapGrant.findUniqueOrThrow({ where: { id: grant.grantId } });
      expect(burned.consumedAt).not.toBeNull();

      const events = await prisma.deviceSecurityEvent.findMany({
        where: { organisationId: fx.orgA, eventType: 'BOOTSTRAP_REPLAY_REFUSED' },
      });
      expect(events.some((event) => (event.payload as Record<string, unknown>).grant_id === grant.grantId)).toBe(true);

      // And the burned grant now refuses even its own legitimate context.
      expect(
        (await enrollment.createEnrollmentRequest({
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          bootstrapToken: grant.token,
          custody: 'PERSONAL',
          publicKey: generateTestDeviceKeyPair().publicKey,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: PROFILE,
          custodyRegimeId: null,
          traceId: traceId(),
        })).outcome,
      ).toBe('REFUSED');
    });
  });

  // -------------------------------------------------------------------------
  // D24-05 / C15-03 — the cryptographic boundary in the live ceremony
  // -------------------------------------------------------------------------

  describe('D24-05 the runtime crypto boundary', () => {
    it('an off-curve P-256 public key cannot become an active key', async () => {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');
      const offCurve = offCurvePublicKeyFixture();

      expect(
        await enrollment.createEnrollmentRequest({
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          intendedUserId: fx.operativeAlpha,
          bootstrapToken: grant.token,
          custody: 'PERSONAL',
          publicKey: offCurve,
          keyStorage: 'HARDWARE_BACKED',
          claimedSignatureProfile: PROFILE,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' });

      // Nothing was persisted, so an off-curve point never reaches a key row.
      expect(await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgA, publicKey: offCurve } })).toBe(0);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, publicKey: offCurve } })).toBe(0);

      // The same key is refused on the rotation path too.
      const device = await enrol();
      expect(
        (await deviceKeys.requestKeyRotation(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          newPublicKey: offCurve,
          newKeyStorage: 'HARDWARE_BACKED',
          traceId: traceId(),
        })),
      ).toEqual({ outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' });
    });

    it('a possession verdict produced with a DIFFERENT key refuses the commit', async () => {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant');
      const enrolledKey = generateTestDeviceKeyPair();
      const attackerKey = generateTestDeviceKeyPair();

      const request = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: grant.token,
        custody: 'PERSONAL',
        publicKey: enrolledKey.publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('request');
      await enrollment.approveEnrollmentRequest(A.approver, {
        organisationId: fx.orgA,
        enrollmentRequestId: request.enrollmentRequestId,
        expectedRequestFingerprint: request.requestFingerprint,
        traceId: traceId(),
      });

      // The attacker answers the challenge with THEIR key over the approved
      // key's statement. The server's verdict is a recorded `false`.
      const challengeId = await issueAndAnswerChallenge(A, request.enrollmentRequestId, request.requestFingerprint, attackerKey, enrolledKey);
      const verdict = await prisma.possessionVerification.findFirstOrThrow({ where: { organisationId: fx.orgA, challengeId } });
      expect(verdict.verified).toBe(false);

      expect(
        await enrollment.commitEnrollment(A.intendedUser, {
          organisationId: fx.orgA,
          enrollmentRequestId: request.enrollmentRequestId,
          challengeId,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_NOT_PROVEN' });
    });

    it('C15-03: a verdict bound to a DIFFERENT challenge/request cannot be borrowed', async () => {
      const prepared = await prepareCeremony();

      // A second challenge for the same request, with a verdict deliberately
      // written to name a different request fingerprint — the shape a
      // "genuine true from another ceremony" would have if one could be filed
      // here at all.
      const second = await enrollment.issuePossessionChallenge(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: prepared.enrollmentRequestId,
        traceId: traceId(),
      });
      if (second.outcome !== 'ISSUED') throw new Error('challenge');
      await prisma.possessionVerification.create({
        data: {
          organisationId: fx.orgA,
          challengeId: second.challengeId,
          enrollmentRequestId: prepared.enrollmentRequestId,
          enrollmentRequestFingerprint: 'f'.repeat(64),
          publicKeyThumbprint: deriveP256PublicKeyThumbprint(prepared.keyPair.publicKey),
          possessionStatementFingerprint: 'e'.repeat(64),
          signatureProfile: PROFILE,
          verified: true,
          verifiedAt: new Date(),
        },
      });

      expect(
        await enrollment.commitEnrollment(A.intendedUser, {
          organisationId: fx.orgA,
          enrollmentRequestId: prepared.enrollmentRequestId,
          challengeId: second.challengeId,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_VERIFICATION_MISBOUND' });

      // A challenge with no verdict at all is likewise not a passing one.
      const third = await enrollment.issuePossessionChallenge(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: prepared.enrollmentRequestId,
        traceId: traceId(),
      });
      if (third.outcome !== 'ISSUED') throw new Error('challenge');
      expect(
        await enrollment.commitEnrollment(A.intendedUser, {
          organisationId: fx.orgA,
          enrollmentRequestId: prepared.enrollmentRequestId,
          challengeId: third.challengeId,
          custodyRegimeId: null,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_VERIFICATION_NOT_FOUND' });
    });
  });

  // -------------------------------------------------------------------------
  // D24-06 / D24-11 — the commit, convergence and replay
  // -------------------------------------------------------------------------

  describe('D24-06 the commit is one transaction, and a retry converges', () => {
    it('a committed enrollment produces exactly the state D24-04 requires', async () => {
      const device = await enrol();
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.organisationId).toBe(fx.orgA);
      expect(row.enrolledByUserId).toBe(fx.commanderIssuerA);
      expect(row.intendedUserId).toBe(fx.operativeAlpha);
      // DERIVED, never caller-selected (D24-04).
      expect(row.sequenceNamespaceId).toBe(deviceSequenceNamespaceId({ organisation_id: fx.orgA, device_id: device.deviceId }));

      const key = await prisma.deviceKey.findFirstOrThrow({ where: { organisationId: fx.orgA, deviceId: device.deviceId } });
      expect(key.status).toBe('CURRENT');
      expect(key.keyVersion).toBe(1);
      // C15-02: the registry persists the ACTUAL key, not merely its name.
      expect(key.publicKey).toBe(device.keyPair.publicKey);
      expect(key.publicKeyThumbprint).toBe(deriveP256PublicKeyThumbprint(device.keyPair.publicKey));
      expect(key.signatureProfile).toBe(PROFILE);

      const scope = await prisma.deviceSiteScope.findFirstOrThrow({ where: { organisationId: fx.orgA, deviceId: device.deviceId } });
      expect(scope.siteId).toBe(fx.siteA1);
      expect(scope.assignedUserId).toBe(fx.operativeAlpha);
      expect(scope.custodyRegimeId).toBeNull();

      const transitions = await repository.listTrustTransitions(fx.orgA, device.deviceId);
      expect(transitions).toHaveLength(1);
      expect(transitions[0]?.newTrust).toBe(device.trust);
    });

    it('an exact retry CONVERGES on the same device identity', async () => {
      const prepared = await prepareCeremony();
      const first = await commit(prepared);
      expect(first.outcome).toBe('COMMITTED');
      const second = await commit(prepared);
      expect(second.outcome).toBe('CONVERGED');
      expect(second.outcome === 'CONVERGED' && second.deviceId).toBe(first.outcome === 'COMMITTED' && first.deviceId);
    });

    it('a duplicate enrollment commit creates exactly ONE device', async () => {
      const prepared = await prepareCeremony();
      const outcomes = [await commit(prepared), await commit(prepared), await commit(prepared)];
      expect(outcomes.map((outcome) => outcome.outcome)).toEqual(['COMMITTED', 'CONVERGED', 'CONVERGED']);
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } })).toBe(1);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: outcomes[0].outcome === 'COMMITTED' ? outcomes[0].deviceId : '' } })).toBe(1);
    });

    it('D24-11: the durable replay row keys on the IDENTITY and records what it was spent on', async () => {
      const device = await enrol();
      const rows = await prisma.deviceNonceConsumption.findMany({
        where: { organisationId: fx.orgA, storedOutcomeRef: device.deviceId },
        orderBy: { ceremony: 'asc' },
      });
      expect(rows.map((row) => row.ceremony)).toEqual(['BOOTSTRAP_GRANT', 'POSSESSION_CHALLENGE']);
      for (const row of rows) {
        expect(row.replayIdentityDigest).toMatch(/^[0-9a-f]{64}$/u);
        // The canonical replay KEY is kept beside its digest: a hash cannot be
        // queried, audited or reasoned about.
        expect(row.replayKey).toContain('sentinel.device.');
        expect(row.statementFingerprint).toBe(device.prepared.requestFingerprint);
      }
    });
  });

  // -------------------------------------------------------------------------
  // D24-07 / D24-08 — attestation and trust
  // -------------------------------------------------------------------------

  describe('D24-07 / D24-08 attestation is evidence and trust is the server conclusion', () => {
    it('a SOFTWARE-backed key can never become TRUSTED, even with current verified attestation', async () => {
      const device = await enrol({ keyStorage: 'SOFTWARE', attestationOutcome: 'VERIFIED' });
      expect(device.trust).toBe('DEGRADED');
      expect(
        await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'TRUSTED',
          reason: 'attempted promotion of a software key',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'KEY_STORAGE_NOT_HARDWARE_BACKED' });
    });

    it('attestation UNAVAILABLE cannot create a FIRST TRUSTED device', async () => {
      // C15-08: a brand-new identity has no "before" to ride on, so an outage
      // at enrollment means DEGRADED — never an inherited standing.
      const device = await enrol({ attestationOutcome: 'UNAVAILABLE', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('DEGRADED');

      const observations = await repository.listAttestationObservations(fx.orgA, device.deviceId);
      expect(observations.map((row) => row.outcome)).toContain('UNAVAILABLE');

      // And it cannot be promoted while the provider stays unavailable.
      expect(
        (await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'TRUSTED',
          reason: 'promotion during an outage',
          traceId: traceId(),
        })),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ATTESTATION_NOT_QUALIFYING' });
    });

    it('a hardware key with CURRENT verified attestation enrols TRUSTED', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('TRUSTED');
    });

    it('attestation NEGATIVE quarantines a TRUSTED device', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('TRUSTED');

      attestation.outcome = 'NEGATIVE';
      const recorded = await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      expect(recorded.outcome).toBe('RECORDED');

      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(standing.outcome === 'FOUND' && standing.standing.trust).toBe('QUARANTINED');

      // Every trust change wrote a transition, including this one.
      const transitions = await repository.listTrustTransitions(fx.orgA, device.deviceId);
      expect(transitions.at(-1)?.newTrust).toBe('QUARANTINED');
      expect(transitions.at(-1)?.reason).toBe('ATTESTATION_NEGATIVE');
      attestation.outcome = 'UNAVAILABLE';
    });

    it('a device cannot self-promote: no principal it could hold changes its own trust', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      // The device's own operative — the most authority anything speaking for
      // this hardware could ever carry in this work package.
      expect(
        await trust.changeDeviceTrust(A.intendedUser, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'TRUSTED',
          reason: 'self promotion',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });
      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(standing.outcome === 'FOUND' && standing.standing.trust).toBe('TRUSTED');
    });

    it('restoration out of QUARANTINED needs device.trust.restore AND qualifying evidence', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await trust.changeDeviceTrust(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'QUARANTINED',
        reason: 'suspicion',
        traceId: traceId(),
      });

      // A principal holding device.trust.manage but NOT device.trust.restore
      // cannot climb back out. There is no such role in §62 today, so the
      // principal is built directly to prove the SERVICE, not the table.
      const manageOnly = buildPrincipal({
        user: { id: fx.commanderApproverA, clearance: 5 },
        organisation_id: fx.orgA,
        roles: [{ role: 'operator', site_id: fx.siteA1 }],
      });
      expect((await trust.changeDeviceTrust(manageOnly, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'TRUSTED',
        reason: 'unauthorised restoration',
        traceId: traceId(),
      })).outcome).toBe('REFUSED');

      // The commander holds both, and current verified evidence exists.
      attestation.outcome = 'VERIFIED';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      expect(
        await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'TRUSTED',
          reason: 'controlled restoration',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'CHANGED', previousTrust: 'QUARANTINED', newTrust: 'TRUSTED' });
      attestation.outcome = 'UNAVAILABLE';
    });
  });

  // -------------------------------------------------------------------------
  // D24-09 — lost, stolen, compromised, and the two independent checks
  // -------------------------------------------------------------------------

  describe('D24-09 lost, stolen and compromised are three different facts', () => {
    it('LOST and STOLEN produce different state and different disposition', async () => {
      const lost = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const stolen = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      const lostOutcome = await trust.declareDisposition(A.approver, {
        organisationId: fx.orgA,
        deviceId: lost.deviceId,
        disposition: 'LOST',
        reason: 'left on a train',
        traceId: traceId(),
      });
      const stolenOutcome = await trust.declareDisposition(A.approver, {
        organisationId: fx.orgA,
        deviceId: stolen.deviceId,
        disposition: 'STOLEN',
        reason: 'taken',
        traceId: traceId(),
      });

      expect(lostOutcome.outcome === 'DECLARED' && lostOutcome.restorationPathRemains).toBe(true);
      expect(stolenOutcome.outcome === 'DECLARED' && stolenOutcome.restorationPathRemains).toBe(false);

      const lostStanding = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: lost.deviceId });
      const stolenStanding = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: stolen.deviceId });
      if (lostStanding.outcome !== 'FOUND' || stolenStanding.outcome !== 'FOUND') throw new Error('standing');

      // LOST: quarantined, credential intact, key untouched, restoration open.
      expect(lostStanding.standing.trust).toBe('QUARANTINED');
      expect(lostStanding.standing.revocationDisposition).toBe('LOST');
      expect(lostStanding.standing.revokedAt).toBeNull();
      expect(lostStanding.standing.currentKeyStatus).toBe('CURRENT');
      expect(lostStanding.standing.deviceLevelWithdrawn).toBe(false);

      // STOLEN: the credential is revoked at BOTH levels.
      expect(stolenStanding.standing.revocationDisposition).toBe('STOLEN');
      expect(stolenStanding.standing.revokedAt).not.toBeNull();
      expect(stolenStanding.standing.currentKeyStatus).toBe('REVOKED');
      expect(stolenStanding.standing.credentialAdmitsNewOperations).toBe(false);

      // A stolen credential climbs nowhere.
      expect(
        (await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: stolen.deviceId,
          to: 'TRUSTED',
          reason: 'recovered?',
          traceId: traceId(),
        })),
      ).toEqual({ outcome: 'REFUSED', refusal: 'CREDENTIAL_REVOKED' });
    });

    it('COMPROMISED is terminal at both the device and the key level', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const declared = await trust.declareDisposition(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        disposition: 'COMPROMISED_KEY',
        reason: 'credential believed copied',
        traceId: traceId(),
      });
      expect(declared.outcome === 'DECLARED' && declared.newTrust).toBe('COMPROMISED');
      expect(declared.outcome === 'DECLARED' && declared.keyStatus).toBe('COMPROMISED');

      // No transition out, in any direction, ever.
      for (const to of ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'OFFLINE'] as const) {
        expect(
          (await trust.changeDeviceTrust(A.approver, {
            organisationId: fx.orgA,
            deviceId: device.deviceId,
            to,
            reason: 'rehabilitation attempt',
            traceId: traceId(),
          })),
          to,
        ).toEqual({ outcome: 'REFUSED', refusal: 'SOURCE_STATE_TERMINAL' });
      }
      expect(
        (await trust.declareDisposition(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'LOST',
          reason: 'second thoughts',
          traceId: traceId(),
        })),
      ).toEqual({ outcome: 'REFUSED', refusal: 'SOURCE_STATE_TERMINAL' });
    });

    it('KEY compromise blocks new operations even before the DEVICE row catches up', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      // The world BETWEEN the two writes, constructed directly: the key has
      // moved and the device row has not. No caller may assume they moved
      // together (C15-R4-final, applied to the device side).
      await prisma.deviceKey.updateMany({
        where: { organisationId: fx.orgA, keyId: device.keyId },
        data: { status: 'COMPROMISED', revokedAt: new Date(), revocationDisposition: 'COMPROMISED_KEY' },
      });

      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      if (standing.outcome !== 'FOUND') throw new Error('standing');
      expect(standing.standing.deviceLevelWithdrawn).toBe(false);
      expect(standing.standing.keyLevelWithdrawn).toBe(true);
      expect(standing.standing.credentialAdmitsNewOperations).toBe(false);
      expect(await registry.credentialAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(false);
    });

    it('DEVICE revocation blocks new operations even before the KEY row catches up', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await prisma.device.updateMany({
        where: { id: device.deviceId, organisationId: fx.orgA },
        data: { revokedAt: new Date(), revocationDisposition: 'STOLEN' },
      });

      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      if (standing.outcome !== 'FOUND') throw new Error('standing');
      expect(standing.standing.currentKeyStatus).toBe('CURRENT');
      expect(standing.standing.keyLevelWithdrawn).toBe(false);
      expect(standing.standing.deviceLevelWithdrawn).toBe(true);
      expect(standing.standing.credentialAdmitsNewOperations).toBe(false);
      expect(await registry.credentialAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // D24-10 / D24-10A — rotation
  // -------------------------------------------------------------------------

  describe('D24-10 rotation preserves identity and never resets it', () => {
    it('a routine rotation preserves the device id and the sequence namespace, and advances the key', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const { outcome } = await rotate(device);
      if (outcome.outcome !== 'ROTATED') throw new Error(`rotation refused: ${JSON.stringify(outcome)}`);

      // Identity is preserved.
      expect(outcome.deviceId).toBe(device.deviceId);
      expect(outcome.sequenceNamespaceId).toBe(device.sequenceNamespaceId);

      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.sequenceNamespaceId).toBe(deviceSequenceNamespaceId({ organisation_id: fx.orgA, device_id: device.deviceId }));

      // The version increments by exactly one.
      expect(outcome.fromKeyVersion).toBe(1);
      expect(outcome.toKeyVersion).toBe(2);
      expect(row.currentKeyVersion).toBe(2);
      expect(row.currentKeyId).toBe(outcome.toKeyId);

      // The old key becomes ROTATED, carries a rotation instant, and is never
      // CURRENT again. It may still verify what it legitimately signed; it
      // authorises nothing new.
      const old = await prisma.deviceKey.findFirstOrThrow({ where: { organisationId: fx.orgA, keyId: outcome.fromKeyId } });
      expect(old.status).toBe('ROTATED');
      expect(old.rotatedAt).not.toBeNull();
      expect(old.revokedAt).toBeNull();
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId, status: 'CURRENT' } })).toBe(1);
    });

    it('a second rotation from the SAME device keeps the namespace and reaches version 3', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const first = await rotate(device);
      if (first.outcome.outcome !== 'ROTATED') throw new Error('first rotation');

      // The device now signs continuity with its NEW key.
      const rotatedDevice: EnrolledDevice = { ...device, keyPair: first.newKeyPair, keyId: first.outcome.toKeyId, keyVersion: 2 };
      const second = await rotate(rotatedDevice);
      if (second.outcome.outcome !== 'ROTATED') throw new Error(`second rotation: ${JSON.stringify(second.outcome)}`);

      expect(second.outcome.toKeyVersion).toBe(3);
      expect(second.outcome.sequenceNamespaceId).toBe(device.sequenceNamespaceId);
      const versions = await prisma.deviceKey.findMany({
        where: { organisationId: fx.orgA, deviceId: device.deviceId },
        orderBy: { keyVersion: 'asc' },
        select: { keyVersion: true, status: true },
      });
      expect(versions).toEqual([
        { keyVersion: 1, status: 'ROTATED' },
        { keyVersion: 2, status: 'ROTATED' },
        { keyVersion: 3, status: 'CURRENT' },
      ]);
    });

    it('a rotation continuity proof signed by the WRONG key refuses', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const impostor = generateTestDeviceKeyPair();
      const { outcome } = await rotate({ ...device, keyPair: impostor });
      expect(outcome).toEqual({ outcome: 'REFUSED', refusal: 'CONTINUITY_NOT_PROVEN' });
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyVersion).toBe(1);
    });

    it('a rotation against a MOVED registry is STALE_ROTATION, never a helpful rotation', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      // Open a rotation, then let the registry move underneath it.
      const request = await deviceKeys.requestKeyRotation(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        newPublicKey: generateTestDeviceKeyPair().publicKey,
        newKeyStorage: 'HARDWARE_BACKED',
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('rotation request');
      const challenge = await deviceKeys.issueRotationChallenge(A.approver, {
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        traceId: traceId(),
      });
      if (challenge.outcome !== 'ISSUED') throw new Error('rotation challenge');

      // The NEW key proves possession honestly — so the refusal below is about
      // the moved registry and not about a half-finished ceremony.
      const newKeyPair = generateTestDeviceKeyPair();
      await deviceKeys.verifyRotationPossession({
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        challengeId: challenge.challengeId,
        response: {
          schema_version: 1,
          challenge_id: challenge.challengeId,
          rotation_request_id: request.rotationRequestId,
          claimed_signature_profile: PROFILE,
          signature: signCanonicalStatement(
            newKeyPair.privateKey,
            canonicalDeviceKeyRotationPossessionStatement({
              organisation_id: fx.orgA,
              device_id: device.deviceId,
              rotation_request_id: request.rotationRequestId,
              rotation_request_fingerprint: request.rotationRequestFingerprint,
              current_key_id: device.keyId,
              current_key_version: 1,
              proposed_key_id: request.proposedKeyId,
              proposed_key_version: request.proposedKeyVersion,
              new_public_key_thumbprint: deriveP256PublicKeyThumbprint(newKeyPair.publicKey),
              rotation_challenge_id: challenge.challengeId,
              nonce: challenge.nonce,
              signature_profile: PROFILE,
            }),
          ),
          answered_at: new Date().toISOString(),
        },
        traceId: traceId(),
      });

      // Now the world moves underneath the ceremony.
      await trust.declareDisposition(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        disposition: 'STOLEN',
        reason: 'stolen mid-ceremony',
        traceId: traceId(),
      });

      const committed = await deviceKeys.commitKeyRotation(A.approver, {
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        challengeId: challenge.challengeId,
        continuityProof: buildContinuityProof(device.keyPair, {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          actorUserId: fx.operativeAlpha,
          deviceId: device.deviceId,
          keyId: device.keyId,
          keyVersion: 1,
          payloadDigest: request.rotationRequestFingerprint,
        }),
        traceId: traceId(),
      });
      // NEVER a helpful rotation from whatever key happens to be current now.
      expect(committed).toEqual({ outcome: 'REFUSED', refusal: 'STALE_ROTATION' });
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyVersion).toBe(1);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId } })).toBe(1);
    });

    it('an exact rotation retry NEVER rotates twice — the registry has moved', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const newKeyPair = generateTestDeviceKeyPair();

      const request = await deviceKeys.requestKeyRotation(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        newPublicKey: newKeyPair.publicKey,
        newKeyStorage: 'HARDWARE_BACKED',
        traceId: traceId(),
      });
      if (request.outcome !== 'REQUESTED') throw new Error('rotation request');
      const challenge = await deviceKeys.issueRotationChallenge(A.approver, {
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        traceId: traceId(),
      });
      if (challenge.outcome !== 'ISSUED') throw new Error('rotation challenge');

      const possessionStatement = canonicalDeviceKeyRotationPossessionStatement({
        organisation_id: fx.orgA,
        device_id: device.deviceId,
        rotation_request_id: request.rotationRequestId,
        rotation_request_fingerprint: request.rotationRequestFingerprint,
        current_key_id: device.keyId,
        current_key_version: 1,
        proposed_key_id: request.proposedKeyId,
        proposed_key_version: request.proposedKeyVersion,
        new_public_key_thumbprint: deriveP256PublicKeyThumbprint(newKeyPair.publicKey),
        rotation_challenge_id: challenge.challengeId,
        nonce: challenge.nonce,
        signature_profile: PROFILE,
      });
      await deviceKeys.verifyRotationPossession({
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        challengeId: challenge.challengeId,
        response: {
          schema_version: 1,
          challenge_id: challenge.challengeId,
          rotation_request_id: request.rotationRequestId,
          claimed_signature_profile: PROFILE,
          signature: signCanonicalStatement(newKeyPair.privateKey, possessionStatement),
          answered_at: new Date().toISOString(),
        },
        traceId: traceId(),
      });

      const proof = buildContinuityProof(device.keyPair, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        actorUserId: fx.operativeAlpha,
        deviceId: device.deviceId,
        keyId: device.keyId,
        keyVersion: 1,
        payloadDigest: request.rotationRequestFingerprint,
      });
      const commitArgs = {
        organisationId: fx.orgA,
        rotationRequestId: request.rotationRequestId,
        challengeId: challenge.challengeId,
        continuityProof: proof,
        traceId: traceId(),
      };

      const first = await deviceKeys.commitKeyRotation(A.approver, commitArgs);
      expect(first.outcome).toBe('ROTATED');

      // C16-03: AN EXACT RETRY CONVERGES ON WHAT ACTUALLY COMMITTED.
      //
      // It used to answer STALE_ROTATION, because the frozen evaluator checks a
      // moved registry at step 3 and the replay fact only at step 5 — and once
      // a rotation lands the registry HAS moved. Safe, but untruthful: the
      // caller's own earlier attempt succeeded, and it was told a concurrent
      // change had invalidated its request. The runtime now resolves the
      // durable replay outcome BEFORE the evaluator, so the honest answer is
      // reachable without changing the contract.
      const retry = await deviceKeys.commitKeyRotation(A.approver, commitArgs);
      expect(retry.outcome).toBe('CONVERGED');
      if (retry.outcome !== 'CONVERGED') throw new Error('unreachable');

      // THE KEY RETURNED IS THE ONE ACTUALLY IN THE DATABASE, read back from
      // the registry rather than echoed from the request.
      const live = await prisma.deviceKey.findFirstOrThrow({
        where: { organisationId: fx.orgA, deviceId: device.deviceId, status: 'CURRENT' },
      });
      expect(retry.toKeyId).toBe(live.keyId);
      expect(retry.toKeyVersion).toBe(live.keyVersion);
      expect(retry.deviceId).toBe(device.deviceId);
      expect(retry.storedOutcomeRef).toBe(live.id);

      // Exactly one new key version exists, and NO THIRD VERSION was created.
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId } })).toBe(2);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId, keyVersion: 3 } })).toBe(0);
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyVersion).toBe(2);

      // C16-03: and a duplicate whose stored reference does NOT resolve to a
      // committed rotation fails closed rather than manufacturing convergence.
      const consumption = await prisma.deviceNonceConsumption.findFirstOrThrow({
        where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION', storedOutcomeRef: live.id },
      });
      await prisma.deviceNonceConsumption.update({
        where: { id: consumption.id },
        data: { storedOutcomeRef: randomUUID() },
      });
      const unresolvable = await deviceKeys.commitKeyRotation(A.approver, commitArgs);
      expect(unresolvable).toEqual({ outcome: 'REFUSED', refusal: 'ROTATION_OUTCOME_UNRESOLVABLE' });
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId } })).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // D24-12 — the audit trail
  // -------------------------------------------------------------------------

  describe('D24-12 the security audit is allowlisted and append-only', () => {
    it('no security event anywhere contains a raw bootstrap token', async () => {
      const device = await enrol();
      const events = await prisma.deviceSecurityEvent.findMany({ where: { organisationId: fx.orgA } });
      expect(events.length).toBeGreaterThan(3);
      const serialised = JSON.stringify(events.map((event) => event.payload));
      expect(serialised).not.toContain(device.prepared.grantToken);
      // The digest is not the token, and the token is not recoverable from it.
      const grant = await prisma.enrollmentBootstrapGrant.findUniqueOrThrow({ where: { id: device.prepared.grantId } });
      expect(grant.tokenDigest).not.toBe(device.prepared.grantToken);
      expect(serialised).not.toContain(grant.tokenDigest);
    });

    it('no security event contains private-key material, a nonce or a signature', async () => {
      const device = await enrol();
      await rotate(device);
      const events = await prisma.deviceSecurityEvent.findMany({ where: { organisationId: fx.orgA } });
      const privatePem = device.keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      const serialised = JSON.stringify(events.map((event) => event.payload));

      expect(serialised).not.toContain(privatePem);
      expect(serialised).not.toContain('BEGIN PRIVATE KEY');

      // No nonce ever reaches the trail either: a challenge nonce is a live
      // secret for the length of its window, and an audit stream is read by
      // more people than the ceremony is.
      const nonces = await prisma.possessionChallenge.findMany({ where: { organisationId: fx.orgA }, select: { nonce: true } });
      for (const { nonce } of nonces) expect(serialised).not.toContain(nonce);

      for (const event of events) {
        for (const key of Object.keys(event.payload as Record<string, unknown>)) {
          expect(/private|secret|token|nonce|password|credential/iu.test(key), `${event.eventType}.${key}`).toBe(false);
        }
      }
    });

    it('the trail actually covers the ceremony — otherwise the assertions above are vacuous', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await rotate(device);
      await trust.declareDisposition(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        disposition: 'LOST',
        reason: 'coverage fixture',
        traceId: traceId(),
      });
      const types = new Set((await prisma.deviceSecurityEvent.findMany({ where: { organisationId: fx.orgA } })).map((row) => row.eventType));
      for (const expected of [
        'BOOTSTRAP_ISSUED',
        'ENROLLMENT_REQUESTED',
        'ENROLLMENT_APPROVED',
        'POSSESSION_VERIFIED',
        'BOOTSTRAP_CONSUMED',
        'DEVICE_ENROLLED',
        'TRUST_CHANGED',
        'KEY_ROTATED',
        'DEVICE_LOST',
        'DEVICE_QUARANTINED',
      ]) {
        expect(types.has(expected), expected).toBe(true);
      }
    });

    it('append-only history cannot be mutated through the repository API', async () => {
      const device = await enrol();
      const eventsBefore = await repository.listSecurityEvents(fx.orgA, device.deviceId);
      const transitionsBefore = await repository.listTrustTransitions(fx.orgA, device.deviceId);
      const observationsBefore = await repository.listAttestationObservations(fx.orgA, device.deviceId);
      expect(eventsBefore.length).toBeGreaterThan(0);
      expect(transitionsBefore.length).toBeGreaterThan(0);
      expect(observationsBefore.length).toBeGreaterThan(0);

      // There is no method on the repository that could mutate any of them.
      const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(repository));
      const mutators = methods.filter((name) =>
        /^(update|delete|upsert|mutate|amend|redact|purge)/iu.test(name) &&
        /(securityevent|trusttransition|attestationobservation)/iu.test(name),
      );
      expect(mutators).toEqual([]);
      // The only writers are appends.
      expect(methods).toContain('appendTrustTransition');
      expect(methods).toContain('appendAttestationObservation');

      // Further activity APPENDS and never rewrites: every earlier row comes
      // back byte-identical, in the same order, as a prefix of the new list.
      await trust.changeDeviceTrust(A.approver, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'OFFLINE',
        reason: 'append-only check',
        traceId: traceId(),
      });
      const eventsAfter = await repository.listSecurityEvents(fx.orgA, device.deviceId);
      const transitionsAfter = await repository.listTrustTransitions(fx.orgA, device.deviceId);
      expect(eventsAfter.slice(0, eventsBefore.length)).toEqual(eventsBefore);
      expect(transitionsAfter.slice(0, transitionsBefore.length)).toEqual(transitionsBefore);
      expect(eventsAfter.length).toBeGreaterThan(eventsBefore.length);
      expect(transitionsAfter.length).toBeGreaterThan(transitionsBefore.length);
    });
  });

  // -------------------------------------------------------------------------
  // The isolation matrix
  // -------------------------------------------------------------------------

  describe('isolation: a foreign-tenant resource and a nonexistent one are indistinguishable', () => {
    it('device reads answer identically for a foreign device and an invented id', async () => {
      const foreign = await enrol({ tenant: B, attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const invented = randomUUID();

      const foreignAnswer = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: foreign.deviceId });
      const inventedAnswer = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: invented });
      expect(foreignAnswer).toEqual(inventedAnswer);
      expect(foreignAnswer).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });

      // Naming the OTHER organisation outright is refused the same way, so the
      // refusal cannot be used to confirm that the id belongs to org B.
      expect(await registry.readDeviceStanding(A.approver, { organisationId: fx.orgB, deviceId: foreign.deviceId })).toEqual(inventedAnswer);

      // The roster never leaks across tenants either.
      const roster = await registry.listDevices(A.approver, { organisationId: fx.orgA });
      expect(roster.outcome === 'FOUND' && roster.devices.every((standing) => standing.organisationId === fx.orgA)).toBe(true);
      expect(roster.outcome === 'FOUND' && roster.devices.some((standing) => standing.deviceId === foreign.deviceId)).toBe(false);
    });

    it('enrollment approval answers identically for a foreign request and an invented id', async () => {
      const foreign = await prepareCeremony({ tenant: B });
      const invented = randomUUID();
      const foreignAnswer = await enrollment.approveEnrollmentRequest(A.approver, {
        organisationId: fx.orgA,
        enrollmentRequestId: foreign.enrollmentRequestId,
        expectedRequestFingerprint: foreign.requestFingerprint,
        traceId: traceId(),
      });
      const inventedAnswer = await enrollment.approveEnrollmentRequest(A.approver, {
        organisationId: fx.orgA,
        enrollmentRequestId: invented,
        expectedRequestFingerprint: foreign.requestFingerprint,
        traceId: traceId(),
      });
      expect(foreignAnswer).toEqual(inventedAnswer);
      expect(foreignAnswer).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' });
    });

    it('trust, revocation and rotation answer identically for a foreign device and an invented id', async () => {
      const foreign = await enrol({ tenant: B, attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const invented = randomUUID();
      const probes: Array<[unknown, unknown]> = [
        [
          await trust.changeDeviceTrust(A.approver, { organisationId: fx.orgA, deviceId: foreign.deviceId, to: 'OFFLINE', reason: 'x', traceId: traceId() }),
          await trust.changeDeviceTrust(A.approver, { organisationId: fx.orgA, deviceId: invented, to: 'OFFLINE', reason: 'x', traceId: traceId() }),
        ],
        [
          await trust.declareDisposition(A.approver, { organisationId: fx.orgA, deviceId: foreign.deviceId, disposition: 'LOST', reason: 'x', traceId: traceId() }),
          await trust.declareDisposition(A.approver, { organisationId: fx.orgA, deviceId: invented, disposition: 'LOST', reason: 'x', traceId: traceId() }),
        ],
        [
          await deviceKeys.requestKeyRotation(A.approver, {
            organisationId: fx.orgA,
            deviceId: foreign.deviceId,
            newPublicKey: generateTestDeviceKeyPair().publicKey,
            newKeyStorage: 'HARDWARE_BACKED',
            traceId: traceId(),
          }),
          await deviceKeys.requestKeyRotation(A.approver, {
            organisationId: fx.orgA,
            deviceId: invented,
            newPublicKey: generateTestDeviceKeyPair().publicKey,
            newKeyStorage: 'HARDWARE_BACKED',
            traceId: traceId(),
          }),
        ],
      ];
      for (const [foreignAnswer, inventedAnswer] of probes) expect(foreignAnswer).toEqual(inventedAnswer);

      // ... and nothing happened to the foreign device.
      const untouched = await registry.readDeviceStanding(B.approver, { organisationId: fx.orgB, deviceId: foreign.deviceId });
      expect(untouched.outcome === 'FOUND' && untouched.standing.trust).toBe('TRUSTED');
      expect(untouched.outcome === 'FOUND' && untouched.standing.revocationDisposition).toBeNull();
    });
  });

  // ==========================================================================
  // C16 CORRECTION BATCH
  //
  // Eight blockers found in adversarial review of the WP-24 runtime. Each block
  // below drives the REAL services against the live stack and asserts the
  // property that was missing, not merely that the new code runs.
  // ==========================================================================

  describe('C16-01 the CONTROLLED_SHARED custody regime is approval-bound', () => {
    it('the regime id is SERVER-generated, and defining one needs device.enrollment.issue at that site', async () => {
      const defined = await enrollment.defineCustodyRegime(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        name: `regime-${randomUUID()}`,
        traceId: traceId(),
      });
      expect(defined.outcome).toBe('DEFINED');
      if (defined.outcome !== 'DEFINED') throw new Error('unreachable');
      // A uuid this process never chose. There is no parameter through which
      // one could have been supplied.
      expect(defined.custodyRegimeId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);

      // A field operative holds no device.enrollment.issue at all.
      expect(
        await enrollment.defineCustodyRegime(A.intendedUser, {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          name: `regime-${randomUUID()}`,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });

      // A commander scoped to siteA2 cannot define a regime at siteA1.
      expect(
        await enrollment.defineCustodyRegime(principalFor(fx.commanderSiteA2, 'site.commander', fx.siteA2, fx.orgA), {
          organisationId: fx.orgA,
          siteId: fx.siteA1,
          name: `regime-${randomUUID()}`,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'SITE_NOT_IN_SCOPE' });
    });

    it('CONTROLLED_SHARED without a regime refuses; PERSONAL with a regime refuses', async () => {
      const regime = await defineRegime(A.issuer, fx.orgA, fx.siteA1);

      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: null })).rejects.toThrow(
        /CUSTODY_REGIME_REQUIRED/u,
      );
      await expect(prepareCeremony({ custody: 'PERSONAL', custodyRegimeId: regime })).rejects.toThrow(
        /CUSTODY_REGIME_NOT_PERMITTED/u,
      );
    });

    it('a regime from another organisation, another site, or a retired one all refuse', async () => {
      const foreign = await defineRegime(B.issuer, fx.orgB, fx.siteB1);
      const wrongSite = await defineRegime(orgWideCommanderA, fx.orgA, fx.siteA2);
      const retired = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      await prisma.deviceCustodyRegime.update({ where: { id: retired }, data: { retiredAt: new Date() } });

      // Another tenant's regime and an invented id are INDISTINGUISHABLE.
      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: foreign })).rejects.toThrow(
        /CUSTODY_REGIME_NOT_FOUND/u,
      );
      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: randomUUID() })).rejects.toThrow(
        /CUSTODY_REGIME_NOT_FOUND/u,
      );
      // Right tenant, wrong site: custody is a site fact and does not widen.
      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: wrongSite })).rejects.toThrow(
        /CUSTODY_REGIME_NOT_FOUND/u,
      );
      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: retired })).rejects.toThrow(
        /CUSTODY_REGIME_RETIRED/u,
      );

      // A régime id is UNTRUSTED INPUT. A value that is not even a uuid must
      // answer NOT_FOUND like any other absent régime, never surface the
      // uuid-column comparison as a driver fault: a refusal is data in this
      // module, and an exception is not a refusal.
      await expect(prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: "not-a-uuid'; drop" })).rejects.toThrow(
        /CUSTODY_REGIME_NOT_FOUND/u,
      );
    });

    it('a controlled-shared enrollment commits under the regime the APPROVER bound', async () => {
      const regime = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const device = await enrol({ custody: 'CONTROLLED_SHARED', custodyRegimeId: regime });

      const scope = await prisma.deviceSiteScope.findFirstOrThrow({
        where: { organisationId: fx.orgA, deviceId: device.deviceId },
      });
      expect(scope.custody).toBe('CONTROLLED_SHARED');
      expect(scope.custodyRegimeId).toBe(regime);
      // C15-08: a shared device names no permanent assignee.
      expect(scope.assignedUserId).toBeNull();

      const approval = await prisma.enrollmentApproval.findFirstOrThrow({
        where: { organisationId: fx.orgA, enrollmentRequestId: device.prepared.enrollmentRequestId },
      });
      expect(approval.approvedCustodyRegimeId).toBe(regime);
      expect(approval.approvedSemanticsDigest).toHaveLength(64);
    });

    it('THE BLOCKER: a regime mutated after approval refuses the commit and creates no device', async () => {
      const approved = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const substituted = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const prepared = await prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: approved });

      // A service-bypassing writer — or a later edit — swaps the regime behind
      // the standing approval. The FROZEN request fingerprint does not move,
      // because `DeviceEnrollmentRequestSchema` has no regime field at all; if
      // the approval bound only that fingerprint, this commit would succeed and
      // the device would be governed by a regime no human ever approved.
      const before = await prisma.enrollmentRequest.findUniqueOrThrow({ where: { id: prepared.enrollmentRequestId } });
      await prisma.enrollmentRequest.update({
        where: { id: prepared.enrollmentRequestId },
        data: { custodyRegimeId: substituted },
      });
      const after = await prisma.enrollmentRequest.findUniqueOrThrow({ where: { id: prepared.enrollmentRequestId } });
      expect(after.requestFingerprint).toBe(before.requestFingerprint);

      expect(await commit(prepared)).toEqual({ outcome: 'REFUSED', refusal: 'APPROVED_SEMANTICS_MISMATCH' });

      // ZERO DEVICES.
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } })).toBe(0);
    });
  });

  describe('C16-02 a replay row never outlives the effect it claims', () => {
    it('THE BLOCKER: a refused enrollment leaves ZERO consumption rows', async () => {
      // A ceremony refused at the gate. The bootstrap issuer commits it, so
      // `ISSUER_MAY_NOT_APPROVE`... no: that is prevalidated. This one is
      // refused by the CONTRACT, after both identities have been consumed —
      // the possession verdict is bound to a key that is not the approved one.
      const keyPair = generateTestDeviceKeyPair();
      const attacker = generateTestDeviceKeyPair();
      const prepared = await prepareCeremony({ keyPair });

      // Answer a FRESH challenge with the attacker's key over the approved
      // key's statement: a real, recorded `verified: false` verdict.
      const badChallenge = await issueAndAnswerChallenge(
        prepared.tenant,
        prepared.enrollmentRequestId,
        prepared.requestFingerprint,
        attacker,
        keyPair,
      );

      const before = await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } });
      const refused = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: prepared.enrollmentRequestId,
        challengeId: badChallenge,
        traceId: traceId(),
      });
      expect(refused.outcome).toBe('REFUSED');
      if (refused.outcome !== 'REFUSED') throw new Error('unreachable');
      expect(refused.refusal).toBe('POSSESSION_NOT_PROVEN');

      // THE ASSERTION THAT WAS MISSING. Before C16-02 this transaction
      // committed two FIRST_SEEN rows naming a device that was never created,
      // and a later exact retry converged toward it.
      const after = await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } });
      expect(after).toBe(before);
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } })).toBe(0);

      // The D24-12 trail survives the rollback: the refusal is still recorded.
      const events = await repository.listSecurityEvents(fx.orgA, null);
      const refusals = events.filter(
        (event) =>
          event.eventType === 'ENROLLMENT_REFUSED' &&
          (event.payload as { enrollment_request_id?: string }).enrollment_request_id === prepared.enrollmentRequestId,
      );
      expect(refusals.length).toBeGreaterThan(0);
    });

    it('THE BLOCKER: a stored outcome ref pointing at no device refuses rather than converging', async () => {
      const device = await enrol();
      const consumption = await prisma.deviceNonceConsumption.findFirstOrThrow({
        where: { organisationId: fx.orgA, ceremony: 'POSSESSION_CHALLENGE', storedOutcomeRef: device.deviceId },
      });
      const phantom = randomUUID();
      await prisma.deviceNonceConsumption.updateMany({
        where: { organisationId: fx.orgA, storedOutcomeRef: device.deviceId },
        data: { storedOutcomeRef: phantom },
      });
      expect(consumption.storedOutcomeRef).toBe(device.deviceId);

      const retried = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: device.prepared.enrollmentRequestId,
        challengeId: device.prepared.challengeId,
        traceId: traceId(),
      });
      // NEVER a CONVERGED answer naming hardware that does not exist.
      expect(retried).toEqual({ outcome: 'REFUSED', refusal: 'REPLAY_OUTCOME_UNRESOLVABLE' });
    });

    it('THE BLOCKER: dual replay identities pointing at DIFFERENT outcomes refuse', async () => {
      const device = await enrol();
      const other = await enrol();

      await prisma.deviceNonceConsumption.updateMany({
        where: { organisationId: fx.orgA, ceremony: 'BOOTSTRAP_GRANT', storedOutcomeRef: device.deviceId },
        data: { storedOutcomeRef: other.deviceId },
      });

      const retried = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: device.prepared.enrollmentRequestId,
        challengeId: device.prepared.challengeId,
        traceId: traceId(),
      });
      // The store is telling two stories about one ceremony. Converging on
      // either would hand the caller someone else's enrolment.
      expect(retried).toEqual({ outcome: 'REFUSED', refusal: 'REPLAY_OUTCOME_DIVERGED' });
    });

    it('a resolvable exact retry still CONVERGES on the one real device', async () => {
      const device = await enrol();
      const retried = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: device.prepared.enrollmentRequestId,
        challengeId: device.prepared.challengeId,
        traceId: traceId(),
      });
      expect(retried).toEqual({ outcome: 'CONVERGED', deviceId: device.deviceId });
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: device.prepared.enrollmentRequestId } })).toBe(1);
    });
  });

  describe('C16-04 no partial security-state commits', () => {
    it('THE BLOCKER: a failed final pointer CAS leaves the old key CURRENT and no new key row', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      // FAULT INJECTION. The pointer compare-and-set reports zero rows, exactly
      // as it would if another path had moved the device between the lock and
      // the write. Before C16-04 the refusal RETURNED, which committed the old
      // key as ROTATED and the new key as CURRENT — two live keys and a device
      // pointing at neither.
      const consumptionsBefore = await prisma.deviceNonceConsumption.count({
        where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION' },
      });
      const spy = vi.spyOn(repository, 'advanceDeviceCurrentKey').mockResolvedValue(0);
      let outcome: Awaited<ReturnType<DeviceKeyService['commitKeyRotation']>>;
      try {
        outcome = (await rotate(device)).outcome;
      } finally {
        spy.mockRestore();
      }
      expect(outcome).toEqual({ outcome: 'REFUSED', refusal: 'STALE_ROTATION' });

      const keys = await prisma.deviceKey.findMany({ where: { organisationId: fx.orgA, deviceId: device.deviceId } });
      expect(keys).toHaveLength(1);
      expect(keys[0]?.status).toBe('CURRENT');
      expect(keys[0]?.rotatedAt).toBeNull();
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyId).toBe(device.keyId);
      expect(row.currentKeyVersion).toBe(1);

      // AND NO PARTIAL-SUCCESS AUDIT EVENT.
      const events = await repository.listSecurityEvents(fx.orgA, device.deviceId);
      expect(events.filter((event) => event.eventType === 'KEY_ROTATED')).toHaveLength(0);
      // The replay identity was not spent either: the consumption row this
      // transaction wrote went with the rollback.
      expect(await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION' } })).toBe(
        consumptionsBefore,
      );
    });

    it('THE BLOCKER: a failed key withdrawal leaves device trust and revocation untouched', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      const spy = vi.spyOn(repository, 'withdrawDeviceKey').mockResolvedValue(0);
      let outcome: Awaited<ReturnType<DeviceTrustService['declareDisposition']>>;
      try {
        outcome = await trust.declareDisposition(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'STOLEN',
          reason: 'fault injection',
          traceId: traceId(),
        });
      } finally {
        spy.mockRestore();
      }
      expect(outcome).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_CREDENTIAL_WITHDRAWN' });

      // NOTHING MOVED. Before C16-04 the trust change, the transition record
      // and the device-level revocation had all already been written.
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.trust).toBe('TRUSTED');
      expect(row.revokedAt).toBeNull();
      expect(row.revocationDisposition).toBeNull();
      const key = await prisma.deviceKey.findFirstOrThrow({ where: { organisationId: fx.orgA, keyId: device.keyId } });
      expect(key.status).toBe('CURRENT');
      expect(key.revokedAt).toBeNull();
      const events = await repository.listSecurityEvents(fx.orgA, device.deviceId);
      expect(events.filter((event) => event.eventType === 'DEVICE_REVOKED' || event.eventType === 'DEVICE_STOLEN')).toHaveLength(0);
    });
  });

  describe('C16-05 attestation ages, and a negative is never un-said', () => {
    it('THE BLOCKER: recording UNAVAILABLE inside the grace keeps TRUSTED; past it, TRUSTED degrades', async () => {
      // THE EXACT MILLISECOND BOUNDARY IS ASSERTED IN `attestation.standing.spec.ts`,
      // against the pure resolver, because only there can it be asserted
      // honestly. Here the ages are written from THIS PROCESS's clock and
      // judged against POSTGRES's `clock_timestamp()`, and those are two
      // different clocks: the container's can sit tens of milliseconds either
      // side of the host's, and the offset moves. A `grace + 1 ms` fixture is
      // therefore a coin toss wearing the costume of a precise test — it
      // failed exactly that way during this batch — so both sides are placed
      // TEN MINUTES clear of the boundary and this test asserts the BEHAVIOUR:
      // ageing happens at all, and it happens on the correct side of the
      // grace. The millisecond is the unit spec's job.
      const inside = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(inside.trust).toBe('TRUSTED');
      await ageAttestation(inside.deviceId, DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS - 600_000);
      attestation.outcome = 'UNAVAILABLE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: inside.deviceId, traceId: traceId() });
      // Ten minutes inside the six-hour grace: still last-known-good, still TRUSTED.
      expect((await prisma.device.findUniqueOrThrow({ where: { id: inside.deviceId } })).trust).toBe('TRUSTED');

      const outside = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(outside.trust).toBe('TRUSTED');
      await ageAttestation(outside.deviceId, DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS + 600_000);
      attestation.outcome = 'UNAVAILABLE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: outside.deviceId, traceId: traceId() });
      // Past the grace the platform can no longer vouch for it. Before C16-05
      // recording UNAVAILABLE did nothing at all and this device stayed TRUSTED
      // for ever — the outage never aged into anything.
      expect((await prisma.device.findUniqueOrThrow({ where: { id: outside.deviceId } })).trust).toBe('DEGRADED');
      // DEGRADED, not QUARANTINED: an expired attestation is ignorance, and
      // nothing has accused this device of anything.
      const transitions = await repository.listTrustTransitions(fx.orgA, outside.deviceId);
      expect(transitions.at(-1)?.reason).toBe('ATTESTATION_STANDING_EXPIRED');
    });

    it('THE BLOCKER: VERIFIED -> NEGATIVE -> UNAVAILABLE stays negative until a NEW verified result', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('TRUSTED');

      attestation.outcome = 'NEGATIVE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('QUARANTINED');

      // The provider then goes down. Before C16-05 the "latest VERIFIED" lookup
      // rediscovered the pre-negative result and reported LAST_KNOWN_GOOD — the
      // outage ERASED the negative evidence — so a restoration would find
      // qualifying evidence where there was none.
      attestation.outcome = 'UNAVAILABLE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });

      const stillRefused = await trust.changeDeviceTrust(restorer, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'TRUSTED',
        reason: 'attempted restoration during outage',
        traceId: traceId(),
      });
      expect(stillRefused).toEqual({ outcome: 'REFUSED', refusal: 'ATTESTATION_NOT_QUALIFYING' });
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('QUARANTINED');

      // Only a NEW verified observation lets it climb back.
      attestation.outcome = 'VERIFIED';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      const restored = await trust.changeDeviceTrust(restorer, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'TRUSTED',
        reason: 'restored on fresh evidence',
        traceId: traceId(),
      });
      expect(restored.outcome).toBe('CHANGED');
    });

    it('THE BLOCKER: a key revoked concurrently with a restoration attempt fails closed', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      attestation.outcome = 'NEGATIVE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      attestation.outcome = 'VERIFIED';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });

      // The credential is withdrawn between the caller's pre-read and the
      // decision. The upward transition re-reads and LOCKS the key inside its
      // own transaction, so it sees the revocation rather than the stale row.
      await prisma.deviceKey.updateMany({
        where: { organisationId: fx.orgA, keyId: device.keyId },
        data: { status: 'REVOKED', revokedAt: new Date(), revocationDisposition: 'STOLEN' },
      });

      const refused = await trust.changeDeviceTrust(restorer, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        to: 'TRUSTED',
        reason: 'restoration racing a revocation',
        traceId: traceId(),
      });
      expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'CREDENTIAL_REVOKED' });
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('QUARANTINED');
    });
  });

  describe('C16-06 multi-site ABAC does not leak and does not over-reach', () => {
    it('THE BLOCKER: a reader scoped to site A sees ONLY A on an A+B device', async () => {
      const device = await enrol();
      await associateExtraSite(device.deviceId, fx.siteA2);

      const scoped = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(scoped.outcome).toBe('FOUND');
      if (scoped.outcome !== 'FOUND') throw new Error('unreachable');
      // Holding site A1 is not a way to learn the device is ALSO at A2.
      expect([...scoped.standing.siteIds].sort()).toEqual([fx.siteA1]);

      const orgWide = await registry.readDeviceStanding(orgWideCommanderA, { organisationId: fx.orgA, deviceId: device.deviceId });
      expect(orgWide.outcome).toBe('FOUND');
      if (orgWide.outcome !== 'FOUND') throw new Error('unreachable');
      expect([...orgWide.standing.siteIds].sort()).toEqual([fx.siteA1, fx.siteA2].sort());
    });

    it('THE BLOCKER: holding ONE of a devices sites cannot rotate, revoke or change its trust', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await associateExtraSite(device.deviceId, fx.siteA2);

      // The commander holds siteA1 only. Rotation replaces the ONE credential
      // the siteA2 deployment also depends on.
      expect(
        await deviceKeys.requestKeyRotation(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          newPublicKey: generateTestDeviceKeyPair().publicKey,
          newKeyStorage: 'HARDWARE_BACKED',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });

      expect(
        await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'OFFLINE',
          reason: 'partial authority',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });

      expect(
        await trust.declareDisposition(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          disposition: 'LOST',
          reason: 'partial authority',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });

      // AN ORG-WIDE COMMANDER CAN.
      const rotation = await deviceKeys.requestKeyRotation(orgWideCommanderA, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        newPublicKey: generateTestDeviceKeyPair().publicKey,
        newKeyStorage: 'HARDWARE_BACKED',
        traceId: traceId(),
      });
      expect(rotation.outcome).toBe('REQUESTED');
      expect(
        (
          await trust.changeDeviceTrust(orgWideCommanderA, {
            organisationId: fx.orgA,
            deviceId: device.deviceId,
            to: 'OFFLINE',
            reason: 'org-wide authority',
            traceId: traceId(),
          })
        ).outcome,
      ).toBe('CHANGED');
    });

    it('THE BLOCKER: a device with NO active site scope refuses a site-scoped commander and admits an org-wide one', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await prisma.deviceSiteScope.updateMany({
        where: { organisationId: fx.orgA, deviceId: device.deviceId },
        data: { releasedAt: new Date() },
      });

      // The old `siteIds.length === 0 -> authorised` shortcut made an unscoped
      // device reachable by anyone holding the action anywhere in the tenant.
      expect(
        await trust.changeDeviceTrust(A.approver, {
          organisationId: fx.orgA,
          deviceId: device.deviceId,
          to: 'OFFLINE',
          reason: 'unscoped device',
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' });
      expect(
        (await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId })).outcome,
      ).toBe('REFUSED');

      expect(
        (
          await trust.changeDeviceTrust(orgWideCommanderA, {
            organisationId: fx.orgA,
            deviceId: device.deviceId,
            to: 'OFFLINE',
            reason: 'unscoped device, org-wide authority',
            traceId: traceId(),
          })
        ).outcome,
      ).toBe('CHANGED');
      expect(
        (await registry.readDeviceStanding(orgWideCommanderA, { organisationId: fx.orgA, deviceId: device.deviceId })).outcome,
      ).toBe('FOUND');
    });
  });

  describe('C16-07 credentialAdmitsNewOperations is not operational authorisation', () => {
    it('THE BLOCKER: every unhealthy trust state with a HEALTHY key passes the credential check and fails deviceMayAct', async () => {
      for (const unhealthy of ['QUARANTINED', 'SUSPICIOUS', 'OFFLINE', 'COMPROMISED'] as const) {
        const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
        // Trust is moved DIRECTLY so the key stays perfectly healthy: this test
        // is about the two questions being independent, not about how a device
        // reaches each state.
        await prisma.device.update({ where: { id: device.deviceId }, data: { trust: unhealthy } });

        const key = await prisma.deviceKey.findFirstOrThrow({ where: { organisationId: fx.orgA, keyId: device.keyId } });
        expect(key.status).toBe('CURRENT');
        expect(key.revokedAt).toBeNull();

        // COMPROMISED is the one state that is ALSO a device-level withdrawal
        // (D23-05 makes it terminal for the identity), so the credential check
        // correctly refuses it. The other three are the overclaim C16-07 names.
        expect(await registry.credentialAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(unhealthy !== 'COMPROMISED');

        // AND NONE OF THEM MAY ACT.
        expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(false);
        expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'FIELD_OPERATION')).toBe(false);
      }
    });

    it('a TRUSTED device with a healthy key may act for both purposes', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('TRUSTED');
      expect(await registry.credentialAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(true);
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(true);
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'FIELD_OPERATION')).toBe(true);
      // W21-05 mirrored: DEGRADED may work the field and may NOT fire Whisper.
      await prisma.device.update({ where: { id: device.deviceId }, data: { trust: 'DEGRADED' } });
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'FIELD_OPERATION')).toBe(true);
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(false);
    });
  });

  describe('C16-08 registry invariants are enforced by the database', () => {
    it('THE BLOCKER: a second CURRENT key for one device is rejected by Postgres', async () => {
      const device = await enrol();
      await expect(
        prisma.$executeRawUnsafe(
          `INSERT INTO device_keys (id, organisation_id, device_id, key_id, key_version, public_key,
             public_key_thumbprint, signature_profile, key_storage, status, registered_at, updated_at)
           VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, 'CURRENT', now(), now())`,
          randomUUID(),
          fx.orgA,
          device.deviceId,
          `dup-${randomUUID()}`,
          99,
          generateTestDeviceKeyPair().publicKey,
          'a'.repeat(64),
          PROFILE,
          'HARDWARE_BACKED',
        ),
        // Postgres reports a unique violation on the PARTIAL index by naming
        // its columns; the raw driver surfaces the message rather than the
        // index name, so the assertion names what the message actually says.
      ).rejects.toThrow(/Key \(organisation_id, device_id\)/u);
    });

    it('THE BLOCKER: a possession verification naming another requests challenge is rejected by Postgres', async () => {
      const first = await prepareCeremony();
      const second = await prepareCeremony();

      // A FRESH challenge for `second`, deliberately unanswered: a challenge
      // that already carries a verdict would hit
      // `possession_verification_challenge_key` first and prove nothing about
      // the tuple constraint under test.
      const spare = await enrollment.issuePossessionChallenge(second.tenant.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: second.enrollmentRequestId,
        traceId: traceId(),
      });
      if (spare.outcome !== 'ISSUED') throw new Error('spare challenge');

      // A verdict for `second`'s challenge, filed against `first`'s request.
      // No service is involved: this is referential integrity, not a check.
      await expect(
        prisma.$executeRawUnsafe(
          `INSERT INTO device_possession_verifications (id, organisation_id, challenge_id, enrollment_request_id,
             enrollment_request_fingerprint, public_key_thumbprint, possession_statement_fingerprint,
             signature_profile, verified, verified_at, updated_at)
           VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, true, now(), now())`,
          randomUUID(),
          fx.orgA,
          spare.challengeId,
          first.enrollmentRequestId,
          first.requestFingerprint,
          'b'.repeat(64),
          'c'.repeat(64),
          PROFILE,
        ),
      ).rejects.toThrow(/device_possession_verifications_challenge_id_organisation__fkey|foreign key/iu);

      // And the same challenge filed under ANOTHER TENANT is refused too.
      await expect(
        prisma.$executeRawUnsafe(
          `INSERT INTO device_possession_verifications (id, organisation_id, challenge_id, enrollment_request_id,
             enrollment_request_fingerprint, public_key_thumbprint, possession_statement_fingerprint,
             signature_profile, verified, verified_at, updated_at)
           VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, true, now(), now())`,
          randomUUID(),
          fx.orgB,
          first.challengeId,
          first.enrollmentRequestId,
          first.requestFingerprint,
          'b'.repeat(64),
          'c'.repeat(64),
          PROFILE,
        ),
      ).rejects.toThrow(/fkey|foreign key/iu);
    });

    it('THE BLOCKER: a rotation verification naming an inconsistent challenge/request is rejected by Postgres', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const other = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      const requestA = await deviceKeys.requestKeyRotation(orgWideCommanderA, {
        organisationId: fx.orgA,
        deviceId: device.deviceId,
        newPublicKey: generateTestDeviceKeyPair().publicKey,
        newKeyStorage: 'HARDWARE_BACKED',
        traceId: traceId(),
      });
      if (requestA.outcome !== 'REQUESTED') throw new Error('rotation request');
      const requestB = await deviceKeys.requestKeyRotation(orgWideCommanderA, {
        organisationId: fx.orgA,
        deviceId: other.deviceId,
        newPublicKey: generateTestDeviceKeyPair().publicKey,
        newKeyStorage: 'HARDWARE_BACKED',
        traceId: traceId(),
      });
      if (requestB.outcome !== 'REQUESTED') throw new Error('rotation request B');
      const challengeB = await deviceKeys.issueRotationChallenge(orgWideCommanderA, {
        organisationId: fx.orgA,
        rotationRequestId: requestB.rotationRequestId,
        traceId: traceId(),
      });
      if (challengeB.outcome !== 'ISSUED') throw new Error('rotation challenge B');

      // Device A's rotation request, device B's challenge. The four-column
      // composite reference makes the tuple unrepresentable.
      await expect(
        prisma.$executeRawUnsafe(
          `INSERT INTO device_key_rotation_verifications (id, organisation_id, device_id, rotation_request_id,
             rotation_request_fingerprint, rotation_challenge_id, current_key_id, current_key_version,
             proposed_key_id, proposed_key_version, new_public_key_thumbprint, signature_profile,
             canonical_statement_fingerprint, verified, verified_at, updated_at)
           VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6::uuid, $7, 1, $8, 2, $9, $10, $11, true, now(), now())`,
          randomUUID(),
          fx.orgA,
          device.deviceId,
          requestA.rotationRequestId,
          requestA.rotationRequestFingerprint,
          challengeB.challengeId,
          device.keyId,
          requestA.proposedKeyId,
          'd'.repeat(64),
          PROFILE,
          'e'.repeat(64),
        ),
      ).rejects.toThrow(/fkey|foreign key/iu);
    });
  });

  // ==========================================================================
  // C16-R RESIDUAL BATCH
  //
  // Five residuals from the final adversarial pass over the C16 batch. Each
  // block drives the REAL services against the live stack and asserts the
  // property that was missing — never merely that the new code runs.
  // ==========================================================================

  describe('C16-R1 the approval OWN regime record is bound at commit', () => {
    it('THE BLOCKER: mutating ONLY the approval regime refuses, with zero devices and zero consumption rows', async () => {
      const approved = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const substituted = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const prepared = await prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: approved });

      // THE ATTACK THE OLD CODE LOST. `performCommit` reads the régime from the
      // APPROVAL row; the C16-01 check recomputes the digest from the REQUEST.
      // So a writer that moves the APPROVAL's own régime A -> B and leaves the
      // stored digest alone changed nothing the frozen fingerprint could see,
      // nothing the request-derived digest could see — and everything the
      // device would actually be governed by. The existing C16-01 regression
      // mutates the REQUEST, which is the other row entirely.
      const approvalBefore = await prisma.enrollmentApproval.findFirstOrThrow({
        where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId },
      });
      expect(approvalBefore.approvedCustodyRegimeId).toBe(approved);
      await prisma.enrollmentApproval.update({
        where: { id: approvalBefore.id },
        data: { approvedCustodyRegimeId: substituted },
      });
      const approvalAfter = await prisma.enrollmentApproval.findUniqueOrThrow({ where: { id: approvalBefore.id } });
      // The digest is UNTOUCHED. That is the whole point: nothing derived from
      // the request can detect this.
      expect(approvalAfter.approvedSemanticsDigest).toBe(approvalBefore.approvedSemanticsDigest);

      const consumptionsBefore = await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } });
      // Reported as ITSELF: the two records disagree, and an operator is told
      // that rather than being handed a digest mismatch to work backwards from.
      expect(await commit(prepared)).toEqual({ outcome: 'REFUSED', refusal: 'APPROVED_CUSTODY_REGIME_MISMATCH' });

      expect(
        await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } }),
      ).toBe(0);
      // AND NEITHER ONE-SHOT IDENTITY WAS SPENT. The refusal is reached before
      // the first consumption write, so nothing was burned for an effect that
      // never happened.
      expect(await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } })).toBe(consumptionsBefore);
    });

    it('an approval rewritten to disagree with its OWN digest refuses', async () => {
      const approved = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const prepared = await prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: approved });

      // Both records still name the same régime, so the direct comparison
      // passes. What moved is the approval's record of WHICH CUSTODY it
      // approved — a field only the approval's own recomputation reads.
      const approval = await prisma.enrollmentApproval.findFirstOrThrow({
        where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId },
      });
      await prisma.enrollmentApproval.update({ where: { id: approval.id }, data: { approvedCustody: 'PERSONAL' } });

      expect(await commit(prepared)).toEqual({ outcome: 'REFUSED', refusal: 'APPROVAL_RECORD_INCONSISTENT' });
      expect(
        await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } }),
      ).toBe(0);
    });

    it('THE BLOCKER: a regime retired AFTER approval but BEFORE commit refuses', async () => {
      const regime = await defineRegime(A.issuer, fx.orgA, fx.siteA1);
      const prepared = await prepareCeremony({ custody: 'CONTROLLED_SHARED', custodyRegimeId: regime });

      // The régime was live when the request was opened and when the human
      // approved. It is withdrawn before the commit — which is precisely the
      // window D24-06 exists for, and the régime was the one authority-bearing
      // row nothing re-read under lock at commit.
      await prisma.deviceCustodyRegime.update({ where: { id: regime }, data: { retiredAt: new Date() } });

      const consumptionsBefore = await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } });
      expect(await commit(prepared)).toEqual({ outcome: 'REFUSED', refusal: 'CUSTODY_REGIME_RETIRED' });
      expect(
        await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: prepared.enrollmentRequestId } }),
      ).toBe(0);
      expect(await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } })).toBe(consumptionsBefore);
    });
  });

  describe('C16-R2 the grant to request first-use race never leaks a driver exception', () => {
    /** One submission, expressed once so a "repeat" is genuinely byte-identical. */
    function submissionFor(grantToken: string, keyPair: TestDeviceKeyPair, keyStorage: DeviceKeyStorage = 'HARDWARE_BACKED') {
      return {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: grantToken,
        custody: 'PERSONAL' as const,
        publicKey: keyPair.publicKey,
        keyStorage,
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      };
    }

    async function freshGrant(): Promise<string> {
      const grant = await enrollment.issueBootstrapGrant(A.issuer, {
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        traceId: traceId(),
      });
      if (grant.outcome !== 'ISSUED') throw new Error('grant not issued');
      return grant.token;
    }

    it('THE BLOCKER: the LOSER of the race CONVERGES instead of surfacing a Prisma P2002', async () => {
      const token = await freshGrant();
      const keyPair = generateTestDeviceKeyPair();

      const first = await enrollment.createEnrollmentRequest(submissionFor(token, keyPair));
      expect(first.outcome).toBe('REQUESTED');
      if (first.outcome !== 'REQUESTED') throw new Error('unreachable');

      // FAULT INJECTION, and it is the race exactly. The read-before-write is
      // forced to answer "no request yet" once — which is what BOTH callers see
      // when two first submissions arrive together — so the insert is attempted
      // against a row that already exists.
      const spy = vi.spyOn(repository, 'findEnrollmentRequestByGrant').mockResolvedValueOnce(null);
      let escaped: unknown = null;
      let second: Awaited<ReturnType<DeviceEnrollmentService['createEnrollmentRequest']>> | null = null;
      try {
        second = await enrollment.createEnrollmentRequest(submissionFor(token, keyPair));
      } catch (error) {
        escaped = error;
      } finally {
        spy.mockRestore();
      }

      // NOTHING ESCAPED. Before C16-R2 this was a raw
      // `PrismaClientKnownRequestError` (P2002) thrown out of a security
      // ceremony — a refusal nobody classified and no caller could handle.
      expect((escaped as { name?: string } | null)?.name).not.toBe('PrismaClientKnownRequestError');
      expect(escaped).toBeNull();

      expect(second).toEqual({
        outcome: 'CONVERGED',
        enrollmentRequestId: first.enrollmentRequestId,
        requestFingerprint: first.requestFingerprint,
        serverSelectedSignatureProfile: PROFILE,
        attestationOutcome: first.attestationOutcome,
      });

      // EXACTLY ONE request behind the grant, and the loser wrote no second
      // attestation observation and no second ENROLLMENT_REQUESTED event.
      const row = await prisma.enrollmentRequest.findUniqueOrThrow({ where: { id: first.enrollmentRequestId } });
      expect(
        await prisma.enrollmentRequest.count({ where: { organisationId: fx.orgA, bootstrapGrantId: row.bootstrapGrantId } }),
      ).toBe(1);
      expect(
        await prisma.deviceAttestationObservation.count({ where: { enrollmentRequestId: first.enrollmentRequestId } }),
      ).toBe(1);
      const events = await repository.listSecurityEvents(fx.orgA, null);
      expect(
        events.filter(
          (event) =>
            event.eventType === 'ENROLLMENT_REQUESTED' &&
            (event.payload as { enrollment_request_id?: string }).enrollment_request_id === first.enrollmentRequestId,
        ),
      ).toHaveLength(1);
    });

    it('THE BLOCKER: a MATERIALLY DIFFERENT losing submission is the named conflict, not a driver fault', async () => {
      const token = await freshGrant();
      const first = await enrollment.createEnrollmentRequest(submissionFor(token, generateTestDeviceKeyPair()));
      expect(first.outcome).toBe('REQUESTED');

      const spy = vi.spyOn(repository, 'findEnrollmentRequestByGrant').mockResolvedValueOnce(null);
      let escaped: unknown = null;
      let second: Awaited<ReturnType<DeviceEnrollmentService['createEnrollmentRequest']>> | null = null;
      try {
        // A DIFFERENT key: this is the thing `enrollment_request_grant_key`
        // exists to stop, and it must be reported as the ceremony's own refusal.
        second = await enrollment.createEnrollmentRequest(submissionFor(token, generateTestDeviceKeyPair()));
      } catch (error) {
        escaped = error;
      } finally {
        spy.mockRestore();
      }
      expect(escaped).toBeNull();
      expect(second).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_CONFLICT' });
    });

    it('two genuinely simultaneous first submissions produce one REQUESTED and one CONVERGED', async () => {
      const token = await freshGrant();
      const keyPair = generateTestDeviceKeyPair();
      // No fault injection at all: the real race, driven concurrently. Whether
      // the loser reaches the collision or merely reads the winner's row first,
      // those two legal answers are the only two answers.
      const [left, right] = await Promise.all([
        enrollment.createEnrollmentRequest(submissionFor(token, keyPair)),
        enrollment.createEnrollmentRequest(submissionFor(token, keyPair)),
      ]);
      expect([left.outcome, right.outcome].sort()).toEqual(['CONVERGED', 'REQUESTED']);
    });
  });

  describe('C16-R3 no ordinary refusal, and no ignored CAS count, after the first consumption', () => {
    it('THE BLOCKER: a failed enrollment-state CAS leaves no device, no key, no scope, no consumption and no success audit', async () => {
      const prepared = await prepareCeremony({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      const before = {
        devices: await prisma.device.count({ where: { organisationId: fx.orgA } }),
        keys: await prisma.deviceKey.count({ where: { organisationId: fx.orgA } }),
        scopes: await prisma.deviceSiteScope.count({ where: { organisationId: fx.orgA } }),
        consumptions: await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } }),
      };

      // FAULT INJECTION. The POSSESSION_PROVEN -> ENROLLED compare-and-set
      // reports zero rows, exactly as it would if the request had left that
      // state between the `FOR UPDATE` read and the write. The count used to be
      // DISCARDED, so the device, its key, its scope, its trust transition and
      // its DEVICE_ENROLLED audit all committed against a ceremony the state
      // machine says never completed.
      const spy = vi.spyOn(repository, 'advanceEnrollmentState').mockResolvedValue(0);
      let outcome: CommitEnrollmentOutcome;
      try {
        outcome = await commit(prepared);
      } finally {
        spy.mockRestore();
      }
      expect(outcome).toEqual({ outcome: 'REFUSED', refusal: 'ENROLLMENT_STATE_INVALID' });

      expect(await prisma.device.count({ where: { organisationId: fx.orgA } })).toBe(before.devices);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA } })).toBe(before.keys);
      expect(await prisma.deviceSiteScope.count({ where: { organisationId: fx.orgA } })).toBe(before.scopes);
      // The two one-shot identities were consumed BEFORE the CAS, so this is
      // the assertion that proves the rollback reached them.
      expect(await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA } })).toBe(before.consumptions);

      const events = await repository.listSecurityEvents(fx.orgA, null);
      const success = events.filter(
        (event) =>
          (event.eventType === 'DEVICE_ENROLLED' || event.eventType === 'BOOTSTRAP_CONSUMED') &&
          (event.payload as { enrollment_request_id?: string }).enrollment_request_id === prepared.enrollmentRequestId,
      );
      expect(success).toEqual([]);
      // The D24-12 trail still records the refusal itself.
      expect(
        events.filter(
          (event) =>
            event.eventType === 'ENROLLMENT_REFUSED' &&
            (event.payload as { enrollment_request_id?: string }).enrollment_request_id === prepared.enrollmentRequestId,
        ).length,
      ).toBeGreaterThan(0);
    });

    it('THE BLOCKER: a failed FINAL rotation-state CAS leaves the original key CURRENT and no successor', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const consumptionsBefore = await prisma.deviceNonceConsumption.count({
        where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION' },
      });

      // Only the FINAL transition is made to fail; the challenge step keeps its
      // real behaviour, so this is the last fenced CAS in the effect and not a
      // ceremony that never started.
      const original = repository.setRotationRequestState.bind(repository);
      const spy = vi
        .spyOn(repository, 'setRotationRequestState')
        .mockImplementation(async (tx, organisationId, id, from, to) =>
          to === 'ROTATED' ? 0 : original(tx, organisationId, id, from, to),
        );
      let outcome: Awaited<ReturnType<DeviceKeyService['commitKeyRotation']>>;
      try {
        outcome = (await rotate(device)).outcome;
      } finally {
        spy.mockRestore();
      }
      expect(outcome).toEqual({ outcome: 'REFUSED', refusal: 'ROTATION_STATE_INVALID' });

      const keys = await prisma.deviceKey.findMany({ where: { organisationId: fx.orgA, deviceId: device.deviceId } });
      expect(keys).toHaveLength(1);
      expect(keys[0]?.keyId).toBe(device.keyId);
      expect(keys[0]?.status).toBe('CURRENT');
      expect(keys[0]?.rotatedAt).toBeNull();
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyId).toBe(device.keyId);
      expect(row.currentKeyVersion).toBe(1);
      expect(
        await prisma.deviceNonceConsumption.count({ where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION' } }),
      ).toBe(consumptionsBefore);
      const events = await repository.listSecurityEvents(fx.orgA, device.deviceId);
      expect(events.filter((event) => event.eventType === 'KEY_ROTATED')).toHaveLength(0);
    });
  });

  describe('C16-R4 rotation convergence answers did-it-commit, not is-it-still-current', () => {
    it('THE BLOCKER: an exact retry of R1 CONVERGES after R2 superseded it', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });

      const r1 = await rotate(device);
      if (r1.outcome.outcome !== 'ROTATED') throw new Error(`R1 refused: ${JSON.stringify(r1.outcome)}`);
      expect(r1.outcome.toKeyVersion).toBe(2);

      // R2 rotates v2 -> v3, which is ordinary history and not an attack.
      const afterR1: EnrolledDevice = {
        ...device,
        keyId: r1.outcome.toKeyId,
        keyVersion: r1.outcome.toKeyVersion,
        keyPair: r1.newKeyPair,
      };
      const r2 = await rotate(afterR1);
      if (r2.outcome.outcome !== 'ROTATED') throw new Error(`R2 refused: ${JSON.stringify(r2.outcome)}`);
      expect(r2.outcome.toKeyVersion).toBe(3);

      // THE EXACT NETWORK RETRY OF R1. It really did commit — its replay row is
      // the durable proof — but v2 is now ROTATED, so the old "still CURRENT
      // and still the device pointer" conditions called it unresolvable and
      // refused a ceremony that had succeeded.
      const retried = await deviceKeys.commitKeyRotation(A.approver, {
        organisationId: fx.orgA,
        rotationRequestId: r1.rotationRequestId,
        challengeId: r1.challengeId,
        continuityProof: r1.continuityProof,
        traceId: traceId(),
      });
      expect(retried).toMatchObject({
        outcome: 'CONVERGED',
        deviceId: device.deviceId,
        toKeyId: r1.outcome.toKeyId,
        toKeyVersion: 2,
        // AND IT SAYS SO. The converged key is NOT current, and the outcome
        // reports that rather than letting a caller assume otherwise.
        committedKeyLifecycleState: 'ROTATED',
      });

      // THE REGISTRY IS UNMOVED. Convergence is a statement about history and
      // grants no current key authority.
      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      if (standing.outcome !== 'FOUND') throw new Error('device vanished');
      expect(standing.standing.currentKeyId).toBe(r2.outcome.toKeyId);
      expect(standing.standing.currentKeyVersion).toBe(3);
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId } })).toBe(3);
    });

    it('a stored reference naming ANOTHER key still fails closed', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const other = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      const r1 = await rotate(device);
      if (r1.outcome.outcome !== 'ROTATED') throw new Error('R1 refused');

      const otherKeyRow = await prisma.deviceKey.findFirstOrThrow({
        where: { organisationId: fx.orgA, deviceId: other.deviceId },
      });
      // The reference this rotation actually stored is the KEY ROW id of the
      // key it committed — resolved precisely rather than by "the newest
      // rotation row", so this test cannot quietly rewrite someone else's.
      const committedKeyRow = await prisma.deviceKey.findFirstOrThrow({
        where: { organisationId: fx.orgA, deviceId: device.deviceId, keyId: r1.outcome.toKeyId },
      });
      const updated = await prisma.deviceNonceConsumption.updateMany({
        where: { organisationId: fx.orgA, ceremony: 'KEY_ROTATION', storedOutcomeRef: committedKeyRow.id },
        data: { storedOutcomeRef: otherKeyRow.id },
      });
      expect(updated.count).toBe(1);

      // Dropping "still CURRENT" did NOT drop the binding to this device, this
      // tenant, this proposed key id and this proposed version.
      expect(
        await deviceKeys.commitKeyRotation(A.approver, {
          organisationId: fx.orgA,
          rotationRequestId: r1.rotationRequestId,
          challengeId: r1.challengeId,
          continuityProof: r1.continuityProof,
          traceId: traceId(),
        }),
      ).toEqual({ outcome: 'REFUSED', refusal: 'ROTATION_OUTCOME_UNRESOLVABLE' });
    });
  });

  describe('C16-R5 the six-hour ceiling is authority-driven, not event-driven', () => {
    it('THE BLOCKER: evidence that ages out with NO further observation still stops the device acting', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      expect(device.trust).toBe('TRUSTED');

      // VERIFIED -> UNAVAILABLE, INSIDE the grace. Nothing moves, correctly:
      // an outage is an absence of evidence, and last-known-good still carries
      // TRUSTED (C14-05).
      attestation.outcome = 'UNAVAILABLE';
      await trust.recordAttestationObservation({ organisationId: fx.orgA, deviceId: device.deviceId, traceId: traceId() });
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('TRUSTED');
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(true);

      // ... AND THEN NOTHING EVER OBSERVES THIS DEVICE AGAIN. The evidence
      // simply ages past six hours. No job runs at 6h + 1ms, no observation
      // arrives, so the C16-05 ageing branch — which only fires when an
      // observation is RECORDED — never executes.
      await ageAttestationPreservingOrder(device.deviceId, DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS + 600_000);

      // THE PERSISTED ROW STILL SAYS TRUSTED. That is not a bug being asserted;
      // it is the premise. Nothing ran, so nothing could have written.
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('TRUSTED');

      // AND THE ANSWER IS ALREADY NO. Authorisation resolves the standing
      // against authoritative server time rather than trusting the column.
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(false);

      // THE TWO QUESTIONS STAY SEPARATE (C16-07). The CREDENTIAL is untouched:
      // no revocation, a healthy CURRENT key. Expired attestation is ignorance,
      // not a withdrawn credential.
      expect(await registry.credentialAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(true);

      // DEGRADED, not QUARANTINED: the field is still open to it (W21-05
      // mirrored), Whisper is not.
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'FIELD_OPERATION')).toBe(true);

      // AND THE READ SURFACE NEVER ADVERTISES A TRUSTED IT WOULD REFUSE.
      const standing = await registry.readDeviceStanding(A.approver, { organisationId: fx.orgA, deviceId: device.deviceId });
      if (standing.outcome !== 'FOUND') throw new Error('device vanished');
      expect(standing.standing.trust).toBe('DEGRADED');
      // The raw column is still visible, and is still TRUSTED, so an operator
      // can see that the durable row has not caught up.
      expect(standing.standing.persistedTrust).toBe('TRUSTED');
      expect(standing.standing.credentialAdmitsNewOperations).toBe(true);

      attestation.outcome = 'UNAVAILABLE';
    });

    it('a device still inside the grace keeps acting, and no read wrote anything', async () => {
      const device = await enrol({ attestationOutcome: 'VERIFIED', keyStorage: 'HARDWARE_BACKED' });
      await ageAttestationPreservingOrder(device.deviceId, DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS - 600_000);

      const transitionsBefore = (await repository.listTrustTransitions(fx.orgA, device.deviceId)).length;
      expect(await registry.deviceMayAct(fx.orgA, device.deviceId, 'WHISPER_DEVICE_ACTION')).toBe(true);

      // A READ THAT NOTICES EXPIRY DOES NOT WRITE, and neither does one that
      // does not: the durable TRUSTED -> DEGRADED move belongs to the
      // observation path, and an authorisation check that mutated would race it.
      expect((await repository.listTrustTransitions(fx.orgA, device.deviceId)).length).toBe(transitionsBefore);
      expect((await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } })).trust).toBe('TRUSTED');
    });
  });
});

// ---------------------------------------------------------------------------
// Small fixture helpers kept out of the ceremony helpers above
// ---------------------------------------------------------------------------

/** A structurally perfect, off-curve point. See `shield.test-support.ts`. */
function offCurvePublicKeyFixture(): string {
  return offCurveP256PublicKey();
}

/** A ceremony taken as far as the human approval and no further. */
async function prepareCeremonyStoppingAtApproval(): Promise<{ enrollmentRequestId: string; requestFingerprint: string }> {
  const grant = await enrollment.issueBootstrapGrant(A.issuer, {
    organisationId: fx.orgA,
    siteId: fx.siteA1,
    intendedUserId: fx.operativeAlpha,
    traceId: traceId(),
  });
  if (grant.outcome !== 'ISSUED') throw new Error('grant');
  const request = await enrollment.createEnrollmentRequest({
    organisationId: fx.orgA,
    siteId: fx.siteA1,
    intendedUserId: fx.operativeAlpha,
    bootstrapToken: grant.token,
    custody: 'PERSONAL',
    publicKey: generateTestDeviceKeyPair().publicKey,
    keyStorage: 'HARDWARE_BACKED',
    claimedSignatureProfile: PROFILE,
    custodyRegimeId: null,
    traceId: traceId(),
  });
  if (request.outcome !== 'REQUESTED') throw new Error('request');
  const approval = await enrollment.approveEnrollmentRequest(A.approver, {
    organisationId: fx.orgA,
    enrollmentRequestId: request.enrollmentRequestId,
    expectedRequestFingerprint: request.requestFingerprint,
    traceId: traceId(),
  });
  if (approval.outcome !== 'APPROVED') throw new Error('approval');
  return { enrollmentRequestId: request.enrollmentRequestId, requestFingerprint: request.requestFingerprint };
}

