import { randomUUID } from 'node:crypto';
import { Test, type TestingModule } from '@nestjs/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS,
  canonicalEdgeEnrolmentPossessionStatement,
} from '@sentinel/contracts';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { ConfigModule } from '../../config/config.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { PrismaService } from '../../prisma/prisma.service';
import { generateTestDeviceKeyPair, offCurveP256PublicKey, signCanonicalStatement, type TestDeviceKeyPair } from '../shield/shield.test-support';
import { EdgeEnrolmentService } from './edge-enrolment.service';
import { EdgeRegistryModule } from './edge-registry.module';
import { EdgeRegistryService } from './edge-registry.service';
import { EDGE_SERVER_SELECTED_SIGNATURE_PROFILE } from './edge-registry.constants';

/**
 * ============================================================================
 * WP-29B / migration 26 — THE EDGE ENROLMENT CEREMONY, AGAINST A REAL DATABASE.
 *
 * This suite exists because the properties migration 26 claims are DATABASE
 * properties: composite tenant foreign keys, a single-use authority, one key
 * per ceremony, and a withdrawal that preserves provenance rather than erasing
 * it. None of them can be demonstrated against a mock, because a mock is a
 * second implementation of the very constraints under test.
 *
 * It boots only `ConfigModule`, `PrismaModule` and `EdgeRegistryModule` rather
 * than the whole `AppModule`: the ceremony needs Postgres and nothing else, and
 * a suite that also required NATS, Redis and S3 to be up would be a suite
 * people skip.
 *
 * TENANT ISOLATION IS BY A UNIQUE RUN TAG, and cleanup deletes only rows this
 * run created. The database is shared.
 * ============================================================================
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: process.env.DATABASE_URL ?? 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  DEV_AUTH_ENABLED: 'true',
};

const tag = `wp29b_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
const ORG = `${tag}_org`;
const OTHER_ORG = `${tag}_org_other`;
const SITE = `${tag}_site`;
const SITE_TWO = `${tag}_site_two`;
const OTHER_ORG_SITE = `${tag}_site_foreign`;
const COMMANDER = `${tag}_commander`;
const OPERATOR = `${tag}_operator`;

let moduleRef: TestingModule;
let prisma: PrismaService;
let enrolment: EdgeEnrolmentService;
let registry: EdgeRegistryService;

function principal(userId: string, role: string, organisationId = ORG, siteId: string | null = null): Principal {
  // Built through the SAME `buildPrincipal` the global DevAuthGuard uses, so no
  // test can assert an authority the §62 role table does not grant.
  return buildPrincipal({ user: { id: userId, clearance: 3 }, organisation_id: organisationId, roles: [{ role, site_id: siteId }] });
}

async function cleanup(): Promise<void> {
  for (const organisationId of [ORG, OTHER_ORG]) {
    await prisma.edgeSecurityEvent.deleteMany({ where: { organisationId } });
    await prisma.edgeRegistryKey.deleteMany({ where: { organisationId } });
    await prisma.edgePossessionVerification.deleteMany({ where: { organisationId } });
    await prisma.edgePossessionChallenge.deleteMany({ where: { organisationId } });
    await prisma.edgeEnrolmentRequest.deleteMany({ where: { organisationId } });
    await prisma.edgeNode.deleteMany({ where: { organisationId } });
    await prisma.edgeEnrolmentAuthority.deleteMany({ where: { organisationId } });
    await prisma.deviceNonceConsumption.deleteMany({ where: { organisationId } });
  }
}

beforeAll(async () => {
  Object.assign(process.env, STACK_ENV);
  moduleRef = await Test.createTestingModule({ imports: [ConfigModule, PrismaModule, EdgeRegistryModule] }).compile();
  prisma = moduleRef.get(PrismaService);
  enrolment = moduleRef.get(EdgeEnrolmentService);
  registry = moduleRef.get(EdgeRegistryService);

  await prisma.organisation.create({ data: { id: ORG, name: `${tag} org` } });
  await prisma.organisation.create({ data: { id: OTHER_ORG, name: `${tag} other org` } });
  await prisma.site.create({ data: { id: SITE, organisationId: ORG, name: 'site' } });
  await prisma.site.create({ data: { id: SITE_TWO, organisationId: ORG, name: 'site two' } });
  await prisma.site.create({ data: { id: OTHER_ORG_SITE, organisationId: OTHER_ORG, name: 'foreign site' } });
  await prisma.user.create({ data: { id: COMMANDER, organisationId: ORG, email: `${COMMANDER}@t.test`, displayName: 'C', clearance: 3 } });
  await prisma.user.create({ data: { id: OPERATOR, organisationId: ORG, email: `${OPERATOR}@t.test`, displayName: 'O', clearance: 1 } });
}, 60_000);

afterAll(async () => {
  await cleanup();
  // Leases before devices; users and sites last. Restrict means the order is
  // not cosmetic — a wrong order is refused by the database rather than
  // silently cascading.
  await prisma.user.deleteMany({ where: { organisationId: ORG } });
  await prisma.site.deleteMany({ where: { organisationId: ORG } });
  await prisma.site.deleteMany({ where: { organisationId: OTHER_ORG } });
  await prisma.organisation.deleteMany({ where: { id: { in: [ORG, OTHER_ORG] } } });
  await moduleRef.close();
}, 60_000);

beforeEach(async () => {
  await cleanup();
});

/** Drives the ceremony to a live registry key and returns everything it produced. */
async function enrolEdge(keyPair: TestDeviceKeyPair = generateTestDeviceKeyPair(), siteId = SITE) {
  const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
    organisationId: ORG,
    siteId,
    traceId: randomUUID(),
  });
  if (issued.outcome !== 'ISSUED') throw new Error(`authority not issued: ${issued.refusal}`);

  const requested = await enrolment.requestEnrolment({
    organisationId: ORG,
    claimedSiteId: siteId,
    authoritySecret: issued.secret,
    offeredPublicKey: keyPair.publicKey,
    traceId: randomUUID(),
  });
  if (requested.outcome !== 'REQUESTED') throw new Error(`enrolment not requested: ${requested.refusal}`);

  const challenge = await enrolment.issuePossessionChallenge({
    organisationId: ORG,
    enrolmentRequestId: requested.enrolmentRequestId,
    traceId: randomUUID(),
  });
  if (challenge.outcome !== 'ISSUED') throw new Error(`challenge not issued: ${challenge.refusal}`);

  const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } });
  const signature = signCanonicalStatement(
    keyPair.privateKey,
    canonicalEdgeEnrolmentPossessionStatement({
      challenge_id: challenge.challengeId,
      enrolment_request_id: requested.enrolmentRequestId,
      enrolment_request_fingerprint: request.requestFingerprint,
      nonce: challenge.nonce,
      public_key_thumbprint: request.offeredPublicKeyThumbprint,
      edge_id: requested.edgeId,
      organisation_id: ORG,
      site_id: siteId,
      signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
    }),
  );

  return { issued, requested, challenge, signature, keyPair, siteId };
}

// ---------------------------------------------------------------------------

describe('actor authority', () => {
  it('refuses a role that does not hold edge.enrolment.authorise', async () => {
    // `operator` holds `device.registry.read` and nothing else. Deliberately
    // NOT reusing a device permission is the whole point of the new capability.
    const result = await enrolment.issueEnrolmentAuthority(principal(OPERATOR, 'operator'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });
  });

  it('refuses even admin, which holds org/site/user administration', async () => {
    // Platform administration is not authority over what Sentinel trusts.
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'admin'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });
  });

  it('refuses a site-scoped commander acting at another site', async () => {
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander', ORG, SITE_TWO), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });
  });

  it('admits a site-scoped commander at their own site', async () => {
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander', ORG, SITE), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    expect(result.outcome).toBe('ISSUED');
  });
});

describe('tenant and site integrity', () => {
  it('refuses an unknown organisation', async () => {
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander', `${tag}_nope`), {
      organisationId: `${tag}_nope`,
      siteId: SITE,
      traceId: randomUUID(),
    });
    // The principal's own tenant is checked first, which is the tighter answer.
    expect(result.outcome).toBe('REFUSED');
  });

  it('refuses a missing organisation the principal claims to belong to', async () => {
    await prisma.organisation.create({ data: { id: `${tag}_ghost`, name: 'ghost' } });
    await prisma.organisation.delete({ where: { id: `${tag}_ghost` } });
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander', `${tag}_ghost`), {
      organisationId: `${tag}_ghost`,
      siteId: SITE,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'ORGANISATION_NOT_FOUND' });
  });

  it('refuses a site belonging to ANOTHER tenant', async () => {
    // The composite FK would refuse this too; refusing before the write means
    // the answer is a named refusal rather than a driver fault.
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: OTHER_ORG_SITE,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'SITE_NOT_IN_ORGANISATION' });
  });

  it('refuses a site that does not exist at all', async () => {
    const result = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: `${tag}_no_such_site`,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'SITE_NOT_IN_ORGANISATION' });
  });

  it('lets the DATABASE refuse a cross-tenant Edge, not just the service', async () => {
    // The defence that survives a service-bypassing writer. `edges` binds
    // (site_id, organisation_id) compositely, so an org-A Edge at an org-B site
    // is a foreign-key violation.
    await expect(
      prisma.edgeNode.create({
        data: {
          id: randomUUID(),
          organisationId: ORG,
          siteId: OTHER_ORG_SITE,
          enrolmentState: 'PENDING',
          edgeTrust: 'SUSPENDED',
          enrolledByUserId: COMMANDER,
        },
      }),
    ).rejects.toThrow();
  });
});

describe('the enrolment authority is single-use and bounded', () => {
  it('resolves nothing for an unknown secret', async () => {
    const result = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: 'not-a-real-secret',
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' });
  });

  it('refuses a secret presented in the WRONG TENANT', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    // The digest lookup is scoped `(organisation_id, secret_digest)`, so a
    // foreign tenant simply resolves nothing.
    const result = await enrolment.requestEnrolment({
      organisationId: OTHER_ORG,
      claimedSiteId: OTHER_ORG_SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' });
  });

  it('refuses a WRONG SITE claim and BURNS the authority', async () => {
    // D24-03a: a probe is not a typo, and an authority that survives being
    // probed is one an attacker may keep trying.
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');

    const probed = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE_TWO,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(probed).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_SITE_MISMATCH' });

    const burned = await prisma.edgeEnrolmentAuthority.findUniqueOrThrow({ where: { id: issued.authorityId } });
    expect(burned.consumedAt).not.toBeNull();

    // And the honest presenter now gets nothing either, which is the cost the
    // rule accepts deliberately.
    const after = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(after).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_ALREADY_CONSUMED' });
  });

  it('refuses an EXPIRED authority', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    // Reach past the ceiling by moving the window, not by waiting ten minutes.
    await prisma.edgeEnrolmentAuthority.update({
      where: { id: issued.authorityId },
      data: {
        issuedAt: new Date(Date.now() - 2 * EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS),
        expiresAt: new Date(Date.now() - EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS),
      },
    });
    const result = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_USABLE' });
  });

  it('refuses a REVOKED authority', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const revoked = await enrolment.revokeEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      authorityId: issued.authorityId,
      traceId: randomUUID(),
    });
    expect(revoked.outcome).toBe('REVOKED');

    const result = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_USABLE' });
  });

  it('refuses a SECOND request under one authority, at the database', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const first = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    expect(first.outcome).toBe('REQUESTED');

    // `edge_enrolment_request_authority_key` makes this a unique violation, so
    // a service-bypassing writer cannot open a second ceremony either.
    await expect(
      enrolment.requestEnrolment({
        organisationId: ORG,
        claimedSiteId: SITE,
        authoritySecret: issued.secret,
        offeredPublicKey: generateTestDeviceKeyPair().publicKey,
        traceId: randomUUID(),
      }),
    ).rejects.toThrow();
    expect(await prisma.edgeNode.count({ where: { organisationId: ORG } })).toBe(1);
  });

  it('stores only a digest and never the secret', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const row = await prisma.edgeEnrolmentAuthority.findUniqueOrThrow({ where: { id: issued.authorityId } });
    // A structure with nowhere to put a raw secret cannot leak one.
    expect(Object.keys(row)).not.toContain('secret');
    expect(JSON.stringify(row)).not.toContain(issued.secret);
    const events = await prisma.edgeSecurityEvent.findMany({ where: { organisationId: ORG } });
    expect(JSON.stringify(events)).not.toContain(issued.secret);
  });
});

describe('the offered key must import', () => {
  it('refuses a structurally perfect OFF-CURVE point', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const result = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: offCurveP256PublicKey(),
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' });
    expect(await prisma.edgeNode.count({ where: { organisationId: ORG } })).toBe(0);
  });
});

describe('a created row is NOT a trusted Edge', () => {
  it('creates the Edge PENDING and SUSPENDED, with no registry key', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const requested = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    if (requested.outcome !== 'REQUESTED') throw new Error('setup');

    const edge = await prisma.edgeNode.findUniqueOrThrow({ where: { id: requested.edgeId } });
    expect(edge.enrolmentState).toBe('PENDING');
    expect(edge.edgeTrust).toBe('SUSPENDED');
    expect(edge.activatedAt).toBeNull();
    expect(await prisma.edgeRegistryKey.count({ where: { edgeId: requested.edgeId } })).toBe(0);
  });

  it('resolves NO registry record for a pending Edge, so nothing it signs can verify', async () => {
    const issued = await enrolment.issueEnrolmentAuthority(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      siteId: SITE,
      traceId: randomUUID(),
    });
    if (issued.outcome !== 'ISSUED') throw new Error('setup');
    const requested = await enrolment.requestEnrolment({
      organisationId: ORG,
      claimedSiteId: SITE,
      authoritySecret: issued.secret,
      offeredPublicKey: generateTestDeviceKeyPair().publicKey,
      traceId: randomUUID(),
    });
    if (requested.outcome !== 'REQUESTED') throw new Error('setup');
    expect(await registry.currentRegistryKeyId(ORG, requested.edgeId)).toBeNull();
  });

  it('SERVER-RESOLVES the site from the authority rather than believing the Edge', async () => {
    const { requested, siteId } = await enrolEdge();
    const edge = await prisma.edgeNode.findUniqueOrThrow({ where: { id: requested.edgeId } });
    expect(edge.siteId).toBe(siteId);
    expect(requested.siteId).toBe(siteId);
  });
});

describe('possession proof', () => {
  it('refuses a proof signed with the WRONG KEY', async () => {
    const { requested, challenge, keyPair } = await enrolEdge();
    const impostor = generateTestDeviceKeyPair();
    expect(impostor.publicKey).not.toBe(keyPair.publicKey);
    const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } });
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');

    const forged = signCanonicalStatement(
      impostor.privateKey,
      canonicalEdgeEnrolmentPossessionStatement({
        challenge_id: challenge.challengeId,
        enrolment_request_id: requested.enrolmentRequestId,
        enrolment_request_fingerprint: request.requestFingerprint,
        nonce: challenge.nonce,
        public_key_thumbprint: request.offeredPublicKeyThumbprint,
        edge_id: requested.edgeId,
        organisation_id: ORG,
        site_id: SITE,
        signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      }),
    );
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature: forged,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' });
    expect(await prisma.edgeRegistryKey.count({ where: { organisationId: ORG } })).toBe(0);
  });

  it('refuses a proof signed over ANOTHER SITE, even by the right key', async () => {
    // The binding the coordinator named: a proof from Edge/site X must never
    // produce a registry record for site Y.
    const { requested, challenge, keyPair } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } });
    const wrongSite = signCanonicalStatement(
      keyPair.privateKey,
      canonicalEdgeEnrolmentPossessionStatement({
        challenge_id: challenge.challengeId,
        enrolment_request_id: requested.enrolmentRequestId,
        enrolment_request_fingerprint: request.requestFingerprint,
        nonce: challenge.nonce,
        public_key_thumbprint: request.offeredPublicKeyThumbprint,
        edge_id: requested.edgeId,
        organisation_id: ORG,
        site_id: SITE_TWO,
        signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      }),
    );
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature: wrongSite,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' });
  });

  it("refuses ANOTHER ceremony's challenge", async () => {
    const first = await enrolEdge();
    const second = await enrolEdge(generateTestDeviceKeyPair(), SITE_TWO);
    if (first.challenge.outcome !== 'ISSUED' || second.challenge.outcome !== 'ISSUED') throw new Error('setup');

    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: first.requested.enrolmentRequestId,
      challengeId: second.challenge.challengeId,
      signature: first.signature,
      traceId: randomUUID(),
    });
    // MISBOUND is its own refusal: the challenge exists, and it belongs to a
    // different request.
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'CHALLENGE_MISBOUND' });
  });

  it('refuses a challenge that does not exist', async () => {
    const { requested, signature } = await enrolEdge();
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: randomUUID(),
      signature,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'CHALLENGE_NOT_FOUND' });
  });

  it('refuses an EXPIRED challenge', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    await prisma.edgePossessionChallenge.update({
      where: { id: challenge.challengeId },
      data: { issuedAt: new Date(Date.now() - 600_000), expiresAt: new Date(Date.now() - 300_000) },
    });
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'CHALLENGE_EXPIRED' });
  });

  it('records the FALSE verdict, and a challenge answered wrongly stays answered', async () => {
    const { requested, challenge, keyPair } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } });
    const impostor = generateTestDeviceKeyPair();
    const forged = signCanonicalStatement(impostor.privateKey, 'not the statement at all');

    const refused = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature: forged,
      traceId: randomUUID(),
    });
    expect(refused).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' });

    const verdict = await prisma.edgePossessionVerification.findFirstOrThrow({ where: { challengeId: challenge.challengeId } });
    expect(verdict.verified).toBe(false);
    expect(verdict.enrolmentRequestFingerprint).toBe(request.requestFingerprint);

    // ONE VERDICT PER CHALLENGE. A challenge that could be answered until one
    // answer is `true` is not a challenge.
    const retried = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature: (await enrolEdgeSignatureFor(requested.enrolmentRequestId, challenge.challengeId, keyPair)),
      traceId: randomUUID(),
    });
    expect(retried).toEqual({ outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' });
    expect(await prisma.edgePossessionVerification.count({ where: { challengeId: challenge.challengeId } })).toBe(1);
  });
});

/** Re-derives a correct signature for an existing request/challenge pair. */
async function enrolEdgeSignatureFor(requestId: string, challengeId: string, keyPair: TestDeviceKeyPair): Promise<string> {
  const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requestId } });
  const challenge = await prisma.edgePossessionChallenge.findUniqueOrThrow({ where: { id: challengeId } });
  return signCanonicalStatement(
    keyPair.privateKey,
    canonicalEdgeEnrolmentPossessionStatement({
      challenge_id: challenge.id,
      enrolment_request_id: request.id,
      enrolment_request_fingerprint: request.requestFingerprint,
      nonce: challenge.nonce,
      public_key_thumbprint: request.offeredPublicKeyThumbprint,
      edge_id: request.edgeId,
      organisation_id: request.organisationId,
      site_id: request.siteId,
      signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
    }),
  );
}

describe('a successful enrolment', () => {
  it('produces an ACTIVE, TRUSTED Edge with a CURRENT registry key', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    expect(result.outcome).toBe('ENROLLED');
    if (result.outcome !== 'ENROLLED') return;

    const edge = await prisma.edgeNode.findUniqueOrThrow({ where: { id: result.edgeId } });
    expect(edge.enrolmentState).toBe('ACTIVE');
    expect(edge.edgeTrust).toBe('TRUSTED');
    expect(edge.activatedAt).not.toBeNull();

    const key = await prisma.edgeRegistryKey.findUniqueOrThrow({ where: { organisationId_edgeKeyId: { organisationId: ORG, edgeKeyId: result.edgeKeyId } } });
    expect(key.status).toBe('CURRENT');
    expect(key.edgeKeyVersion).toBe(1);
    expect(key.revokedAt).toBeNull();

    // The authority is spent and the request is closed.
    const authority = await prisma.edgeEnrolmentAuthority.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId ? (await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } })).authorityId : '' } });
    expect(authority.consumedAt).not.toBeNull();
    const request = await prisma.edgeEnrolmentRequest.findUniqueOrThrow({ where: { id: requested.enrolmentRequestId } });
    expect(request.state).toBe('ACTIVATED');
  });

  it('resolves a record the FROZEN EdgeRegistryKeyRecordSchema accepts', async () => {
    // The whole point of migration 26: `evaluateOfflineOperationAdmissibility`
    // now has something to resolve.
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (result.outcome !== 'ENROLLED') throw new Error('setup');

    const record = await registry.resolveEdgeRegistryKeyRecord(ORG, result.edgeKeyId);
    expect(record).not.toBeNull();
    expect(record?.edge_trust).toBe('TRUSTED');
    expect(record?.status).toBe('CURRENT');
    expect(record?.organisation_id).toBe(ORG);
    // The one-site narrowing, made visible.
    expect(record?.authorised_site_ids).toEqual([SITE]);
    expect(record?.revoked_at).toBeNull();
  });

  it('resolves NOTHING for another tenant asking about the same key id', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (result.outcome !== 'ENROLLED') throw new Error('setup');
    expect(await registry.resolveEdgeRegistryKeyRecord(OTHER_ORG, result.edgeKeyId)).toBeNull();
  });

  it('writes an audit trail that answers who, where, which key and when', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const result = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (result.outcome !== 'ENROLLED') throw new Error('setup');

    const events = await prisma.edgeSecurityEvent.findMany({ where: { organisationId: ORG }, orderBy: { occurredAt: 'asc' } });
    const types = events.map((event) => event.eventType);
    expect(types).toContain('EDGE_AUTHORITY_ISSUED');
    expect(types).toContain('EDGE_ENROLMENT_REQUESTED');
    expect(types).toContain('EDGE_POSSESSION_VERIFIED');
    expect(types).toContain('EDGE_AUTHORITY_CONSUMED');
    expect(types).toContain('EDGE_ENROLLED');

    const enrolled = events.find((event) => event.eventType === 'EDGE_ENROLLED');
    expect(enrolled?.actorUserId).toBe(COMMANDER);
    expect(enrolled?.siteId).toBe(SITE);
    expect(enrolled?.edgeKeyId).toBe(result.edgeKeyId);
    expect(enrolled?.edgeKeyVersion).toBe(1);
    // NO PRIVATE KEY AND NO SECRET, anywhere in the trail.
    const serialised = JSON.stringify(events);
    expect(serialised).not.toContain('PRIVATE KEY');
    expect(serialised).not.toContain(challenge.nonce);
  });
});

describe('a retry converges and never mints a second identity', () => {
  it('answers CONVERGED with the SAME edge id', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const call = () =>
      enrolment.completeEnrolment({
        organisationId: ORG,
        enrolmentRequestId: requested.enrolmentRequestId,
        challengeId: challenge.challengeId,
        signature,
        traceId: randomUUID(),
      });

    const first = await call();
    const second = await call();
    expect(first.outcome).toBe('ENROLLED');
    expect(second.outcome).toBe('CONVERGED');
    if (first.outcome !== 'ENROLLED' || second.outcome !== 'CONVERGED') return;
    expect(second.edgeId).toBe(first.edgeId);

    // THE PROPERTY THAT MATTERS: one Edge, one key, one verdict.
    expect(await prisma.edgeNode.count({ where: { organisationId: ORG } })).toBe(1);
    expect(await prisma.edgeRegistryKey.count({ where: { organisationId: ORG } })).toBe(1);
    expect(await prisma.edgePossessionVerification.count({ where: { organisationId: ORG } })).toBe(1);
  });

  it('spends both one-shot identities in Shield\'s ONE replay store', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    const consumptions = await prisma.deviceNonceConsumption.findMany({ where: { organisationId: ORG } });
    const ceremonies = consumptions.map((row) => row.ceremony).sort();
    expect(ceremonies).toEqual(['EDGE_ENROLMENT_AUTHORITY', 'EDGE_POSSESSION_CHALLENGE']);
    // Both name the SAME committed outcome, so a retry of either converges on
    // the Edge that exists.
    expect(new Set(consumptions.map((row) => row.storedOutcomeRef)).size).toBe(1);
  });
});

describe('withdrawal preserves historical provenance', () => {
  it('withdraws the Edge, revokes the key, and deletes nothing', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const enrolled = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (enrolled.outcome !== 'ENROLLED') throw new Error('setup');

    const withdrawn = await enrolment.withdrawEdge(principal(COMMANDER, 'site.commander'), {
      organisationId: ORG,
      edgeId: enrolled.edgeId,
      traceId: randomUUID(),
    });
    expect(withdrawn).toEqual({ outcome: 'WITHDRAWN', edgeId: enrolled.edgeId });

    const edge = await prisma.edgeNode.findUniqueOrThrow({ where: { id: enrolled.edgeId } });
    expect(edge.enrolmentState).toBe('WITHDRAWN');
    expect(edge.edgeTrust).toBe('REVOKED');
    expect(edge.withdrawnAt).not.toBeNull();
    // THE ROW IS STILL THERE, with its ceremony intact — which is precisely
    // when somebody asks which box witnessed a shift's work.
    expect(edge.enrolledByUserId).toBe(COMMANDER);
    expect(await prisma.edgeRegistryKey.count({ where: { edgeId: enrolled.edgeId } })).toBe(1);
    expect(await prisma.edgeEnrolmentRequest.count({ where: { edgeId: enrolled.edgeId } })).toBe(1);
    expect(await prisma.edgePossessionVerification.count({ where: { organisationId: ORG } })).toBe(1);

    const key = await prisma.edgeRegistryKey.findUniqueOrThrow({ where: { organisationId_edgeKeyId: { organisationId: ORG, edgeKeyId: enrolled.edgeKeyId } } });
    expect(key.status).toBe('REVOKED');
    expect(key.revokedAt).not.toBeNull();
    // The public key is STILL READABLE, so receipts this Edge legitimately
    // signed can still be checked after the fact.
    expect(key.publicKey.length).toBeGreaterThan(0);
  });

  it('makes the resolved record refuse new work while staying resolvable', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const enrolled = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (enrolled.outcome !== 'ENROLLED') throw new Error('setup');
    await enrolment.withdrawEdge(principal(COMMANDER, 'site.commander'), { organisationId: ORG, edgeId: enrolled.edgeId, traceId: randomUUID() });

    const record = await registry.resolveEdgeRegistryKeyRecord(ORG, enrolled.edgeKeyId);
    expect(record).not.toBeNull();
    // Two independent facts, and the frozen evaluator asks each on its own:
    // EDGE_CREDENTIAL_REVOKED on the instant, EDGE_NOT_TRUSTED on the trust.
    expect(record?.revoked_at).not.toBeNull();
    expect(record?.edge_trust).toBe('REVOKED');
    expect(record?.status).toBe('REVOKED');
  });

  it('refuses withdrawal without the edge.revoke capability', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const enrolled = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (enrolled.outcome !== 'ENROLLED') throw new Error('setup');
    const result = await enrolment.withdrawEdge(principal(OPERATOR, 'operator'), {
      organisationId: ORG,
      edgeId: enrolled.edgeId,
      traceId: randomUUID(),
    });
    expect(result).toEqual({ outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' });
  });

  it('refuses a SECOND withdrawal, because WITHDRAWN is terminal', async () => {
    const { requested, challenge, signature } = await enrolEdge();
    if (challenge.outcome !== 'ISSUED') throw new Error('setup');
    const enrolled = await enrolment.completeEnrolment({
      organisationId: ORG,
      enrolmentRequestId: requested.enrolmentRequestId,
      challengeId: challenge.challengeId,
      signature,
      traceId: randomUUID(),
    });
    if (enrolled.outcome !== 'ENROLLED') throw new Error('setup');
    const withdraw = () => enrolment.withdrawEdge(principal(COMMANDER, 'site.commander'), { organisationId: ORG, edgeId: enrolled.edgeId, traceId: randomUUID() });
    expect((await withdraw()).outcome).toBe('WITHDRAWN');
    expect(await withdraw()).toEqual({ outcome: 'REFUSED', refusal: 'EDGE_STATE_INVALID' });
  });

  it('refuses to delete a site an Edge still references', async () => {
    // `onDelete: Restrict`, not a cascade. Historical identity survives a
    // cleanup of the thing it points at, by REFUSING the cleanup.
    await enrolEdge();
    await expect(prisma.site.delete({ where: { id: SITE } })).rejects.toThrow();
  });
});
