import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  canonicalDeviceKeyRotationPossessionStatement,
  canonicalDevicePossessionStatement,
  canonicalDeviceRequestProofStatement,
  deriveP256PublicKeyThumbprint,
  deviceSequenceNamespaceId,
  type DeviceAttestationOutcome,
  type DeviceCustody,
  type DeviceKeyStorage,
} from '@sentinel/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
  B = {
    organisationId: fx.orgB,
    siteId: fx.siteB1,
    issuer: principalFor(fx.commanderIssuerB, 'site.commander', fx.siteB1, fx.orgB),
    approver: principalFor(fx.commanderApproverB, 'site.commander', fx.siteB1, fx.orgB),
    intendedUserId: fx.operativeB,
    intendedUser: principalFor(fx.operativeB, 'field.operative', fx.siteB1, fx.orgB),
  };
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
    custodyRegimeId: prepared.custodyRegimeId,
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
): Promise<{ outcome: Awaited<ReturnType<DeviceKeyService['commitKeyRotation']>>; newKeyPair: TestDeviceKeyPair }> {
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

  const outcome = await deviceKeys.commitKeyRotation(tenant.approver, {
    organisationId: tenant.organisationId,
    rotationRequestId: request.rotationRequestId,
    challengeId: challenge.challengeId,
    // The CURRENT key proves continuity, over the EXACT rotation-request
    // fingerprint. This is what stops a valid current-key proof being borrowed
    // for a different replacement key.
    continuityProof: buildContinuityProof(device.keyPair, {
      organisationId: tenant.organisationId,
      siteId: tenant.siteId,
      actorUserId: tenant.intendedUserId,
      deviceId: device.deviceId,
      keyId: standing.standing.currentKeyId as string,
      keyVersion: standing.standing.currentKeyVersion as number,
      payloadDigest: request.rotationRequestFingerprint,
    }),
    traceId: traceId(),
  });

  return { outcome, newKeyPair };
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
      const attackerRequest = await enrollment.createEnrollmentRequest({
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
            custodyRegimeId: null,
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
    it('a second, DIFFERENT enrollment under one grant refuses and creates no device', async () => {
      const first = await enrol();

      // A second ceremony under the same grant: same replay identity, DIFFERENT
      // statement fingerprint (a different key). That is reuse with changed
      // meaning, and it is a conflict rather than a convergence.
      const secondKey = generateTestDeviceKeyPair();
      const secondRequest = await enrollment.createEnrollmentRequest({
        organisationId: fx.orgA,
        siteId: fx.siteA1,
        intendedUserId: fx.operativeAlpha,
        bootstrapToken: first.prepared.grantToken,
        custody: 'PERSONAL',
        publicKey: secondKey.publicKey,
        keyStorage: 'HARDWARE_BACKED',
        claimedSignatureProfile: PROFILE,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      if (secondRequest.outcome !== 'REQUESTED') throw new Error('second request');
      const approval = await enrollment.approveEnrollmentRequest(A.approver, {
        organisationId: fx.orgA,
        enrollmentRequestId: secondRequest.enrollmentRequestId,
        expectedRequestFingerprint: secondRequest.requestFingerprint,
        traceId: traceId(),
      });
      expect(approval.outcome).toBe('APPROVED');
      const challengeId = await issueAndAnswerChallenge(A, secondRequest.enrollmentRequestId, secondRequest.requestFingerprint, secondKey);

      const refused = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: secondRequest.enrollmentRequestId,
        challengeId,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_REUSED' });

      // NEVER A SECOND DEVICE.
      expect(await prisma.device.count({ where: { organisationId: fx.orgA, enrollmentRequestId: secondRequest.enrollmentRequestId } })).toBe(0);
      const grantDevices = await prisma.device.findMany({
        where: { organisationId: fx.orgA, enrollmentRequest: { bootstrapGrantId: first.prepared.grantId } },
      });
      expect(grantDevices.map((row) => row.id)).toEqual([first.deviceId]);
    });

    it('changed semantics behind a spent grant CONFLICTS and mutates nothing', async () => {
      const first = await enrol();
      const before = await prisma.deviceNonceConsumption.findFirstOrThrow({
        where: { organisationId: fx.orgA, ceremony: 'BOOTSTRAP_GRANT', storedOutcomeRef: first.deviceId },
      });

      const changed = await prepareCeremonyReusingGrant(first.prepared.grantToken);
      const refused = await enrollment.commitEnrollment(A.intendedUser, {
        organisationId: fx.orgA,
        enrollmentRequestId: changed.enrollmentRequestId,
        challengeId: changed.challengeId,
        custodyRegimeId: null,
        traceId: traceId(),
      });
      expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_REUSED' });

      // The stored consumption row still points at the FIRST device. A
      // conflict never rewrites what the identity was spent on.
      const after = await prisma.deviceNonceConsumption.findUniqueOrThrow({ where: { id: before.id } });
      expect(after.storedOutcomeRef).toBe(first.deviceId);
      expect(after.statementFingerprint).toBe(before.statementFingerprint);
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
      expect(stolenStanding.standing.admitsNewOperations).toBe(false);

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
      expect(standing.standing.admitsNewOperations).toBe(false);
      expect(await registry.deviceAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(false);
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
      expect(standing.standing.admitsNewOperations).toBe(false);
      expect(await registry.deviceAdmitsNewOperations(fx.orgA, device.deviceId)).toBe(false);
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

      // D24-10A asks that the same identity with the same fingerprint "never
      // rotates twice". It is upheld here by STALE_ROTATION rather than by the
      // contract's CONVERGE arm, and that is a property of the FROZEN
      // evaluator's ORDERING rather than a choice this runtime made:
      // `evaluateDeviceKeyRotation` re-reads the registry and refuses a moved
      // world at step 3, while the replay fact it would converge on is only
      // consulted at step 5. Once a rotation has landed the registry HAS moved
      // by definition, so a retry can never reach convergence. The effect the
      // rule protects — no second rotation, no burned key version — holds
      // either way, and it is recorded here rather than papered over.
      const retry = await deviceKeys.commitKeyRotation(A.approver, commitArgs);
      expect(retry).toEqual({ outcome: 'REFUSED', refusal: 'STALE_ROTATION' });

      // Exactly one new key version exists, and no version was burned twice.
      expect(await prisma.deviceKey.count({ where: { organisationId: fx.orgA, deviceId: device.deviceId } })).toBe(2);
      const row = await prisma.device.findUniqueOrThrow({ where: { id: device.deviceId } });
      expect(row.currentKeyVersion).toBe(2);
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

/** A fully prepared ceremony that deliberately reuses an already-spent grant. */
async function prepareCeremonyReusingGrant(token: string): Promise<{ enrollmentRequestId: string; challengeId: string }> {
  const keyPair = generateTestDeviceKeyPair();
  const request = await enrollment.createEnrollmentRequest({
    organisationId: fx.orgA,
    siteId: fx.siteA1,
    intendedUserId: fx.operativeAlpha,
    bootstrapToken: token,
    custody: 'PERSONAL',
    publicKey: keyPair.publicKey,
    keyStorage: 'HARDWARE_BACKED',
    claimedSignatureProfile: PROFILE,
    custodyRegimeId: null,
    traceId: traceId(),
  });
  if (request.outcome !== 'REQUESTED') throw new Error('reuse request');
  await enrollment.approveEnrollmentRequest(A.approver, {
    organisationId: fx.orgA,
    enrollmentRequestId: request.enrollmentRequestId,
    expectedRequestFingerprint: request.requestFingerprint,
    traceId: traceId(),
  });
  const challengeId = await issueAndAnswerChallenge(A, request.enrollmentRequestId, request.requestFingerprint, keyPair);
  return { enrollmentRequestId: request.enrollmentRequestId, challengeId };
}
