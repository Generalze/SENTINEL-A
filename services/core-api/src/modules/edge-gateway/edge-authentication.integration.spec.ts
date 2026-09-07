import { createSign, generateKeyPairSync, randomUUID } from 'node:crypto';
import { Test, type TestingModule } from '@nestjs/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  canonicalEdgeTrustedTimeAnchorStatement,
  encodeCanonicalP256Signature,
  canonicalDeviceEdgeReceiptStatement,
  canonicalEdgeEnrolmentPossessionStatement,
  canonicalEdgeRequestStatement,
  edgeRequestBodyDigest,
  EdgeRequestRouteSchema,
  EDGE_REQUEST_EMPTY_BODY_DIGEST,
  EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS,
  type DeviceEdgeReceiptStatementInput,
  type EdgeRequestMethod,
  type EdgeRequestPurpose,
  type EdgeRequestStatementInput,
} from '@sentinel/contracts';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { ConfigModule } from '../../config/config.module';
import { PrismaModule } from '../../prisma/prisma.module';
import { PrismaService } from '../../prisma/prisma.service';
import { generateTestDeviceKeyPair, signCanonicalStatement, type TestDeviceKeyPair } from '../shield/shield.test-support';
import { EdgeEnrolmentService } from '../edge-registry/edge-enrolment.service';
import { EdgeRegistryService } from '../edge-registry/edge-registry.service';
import { EDGE_SERVER_SELECTED_SIGNATURE_PROFILE, EDGE_TRUST_SUSPENDED } from '../edge-registry/edge-registry.constants';
import { EdgeAuthenticationService, type AuthenticatedEdgeContext } from './edge-authentication.service';
import { EdgeGatewayModule } from './edge-gateway.module';
import { CentralEdgeTrustedTimeVerifier } from '../edge-trusted-time/central-edge-trusted-time.verifier';
import { CentralTrustedTimeKeyringProvider } from '../edge-trusted-time/central-trusted-time-verification.keyring';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { EdgeEvidenceStandingService } from './edge-evidence-standing.service';
import { EdgeReceiptObservationService } from './edge-receipt-observation.service';
import { EdgeWitnessService } from './edge-witness.service';

/**
 * ============================================================================
 * WP-29B EDGE-B — THE EDGE→CENTRAL AUTHENTICATION BOUNDARY, AGAINST A REAL
 * DATABASE.
 *
 * This suite is live rather than mocked because the properties under test are
 * DATABASE properties or are only meaningful against real rows: a tenant
 * DERIVED from a registry lookup rather than supplied, a one-shot request
 * identity enforced by a unique index in Sentinel's single anti-replay store,
 * a revocation that takes effect between two requests, and a refusal boundary
 * that must look identical for a foreign tenant and for a key that never
 * existed. A mock of any of those is a second implementation of the thing under
 * test.
 *
 * It boots only `ConfigModule`, `PrismaModule` and `EdgeGatewayModule` — the
 * round-3 minimal-module pattern. The boundary needs Postgres and nothing else,
 * and a suite that also required NATS, Redis and S3 is a suite people skip.
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

const tag = `wp29b_edgeb_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
const ORG = `${tag}_org`;
const OTHER_ORG = `${tag}_org_other`;
const SITE = `${tag}_site`;
const SITE_TWO = `${tag}_site_two`;
const OTHER_ORG_SITE = `${tag}_site_foreign`;
const COMMANDER = `${tag}_commander`;
const OTHER_COMMANDER = `${tag}_commander_foreign`;

const ROUTE = '/edge/v1/trusted-time-anchor';

let moduleRef: TestingModule;
let prisma: PrismaService;
let enrolment: EdgeEnrolmentService;
let registry: EdgeRegistryService;
let auth: EdgeAuthenticationService;
let witness: EdgeWitnessService;

function principal(userId: string, organisationId = ORG, siteId: string | null = null): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 3 }, organisation_id: organisationId, roles: [{ role: 'site.commander', site_id: siteId }] });
}

async function cleanupEdgeRows(): Promise<void> {
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

/** An Edge that completed the round-3 ceremony: ACTIVE, TRUSTED, one CURRENT key. */
interface EnrolledEdge {
  readonly edgeId: string;
  readonly edgeKeyId: string;
  readonly organisationId: string;
  readonly siteId: string;
  readonly keyPair: TestDeviceKeyPair;
}

async function enrolEdge(organisationId = ORG, siteId = SITE, commander = COMMANDER): Promise<EnrolledEdge> {
  const keyPair = generateTestDeviceKeyPair();
  const issued = await enrolment.issueEnrolmentAuthority(principal(commander, organisationId), { organisationId, siteId, traceId: randomUUID() });
  if (issued.outcome !== 'ISSUED') throw new Error(`authority not issued: ${issued.refusal}`);

  const requested = await enrolment.requestEnrolment({
    organisationId,
    claimedSiteId: siteId,
    authoritySecret: issued.secret,
    offeredPublicKey: keyPair.publicKey,
    traceId: randomUUID(),
  });
  if (requested.outcome !== 'REQUESTED') throw new Error(`enrolment not requested: ${requested.refusal}`);

  const challenge = await enrolment.issuePossessionChallenge({ organisationId, enrolmentRequestId: requested.enrolmentRequestId, traceId: randomUUID() });
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
      organisation_id: organisationId,
      site_id: siteId,
      signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
    }),
  );
  const completed = await enrolment.completeEnrolment({
    organisationId,
    enrolmentRequestId: requested.enrolmentRequestId,
    challengeId: challenge.challengeId,
    signature,
    traceId: randomUUID(),
  });
  if (completed.outcome !== 'ENROLLED') throw new Error(`enrolment not completed: ${JSON.stringify(completed)}`);

  return { edgeId: completed.edgeId, edgeKeyId: completed.edgeKeyId, organisationId, siteId, keyPair };
}

interface ProofOverrides {
  readonly edgeId?: string;
  readonly registryKeyId?: string;
  readonly requestId?: string;
  readonly method?: EdgeRequestMethod;
  readonly route?: string;
  readonly body?: string;
  readonly purpose?: EdgeRequestPurpose;
  readonly trustedTimeAnchorId?: string | null;
  readonly edgeTrustedTimestamp?: string | null;
  readonly signWith?: TestDeviceKeyPair;
}

/**
 * Builds a proof the way a conforming Edge would.
 *
 * It signs the statement built from the SERVER-selected profile, exactly as the
 * resolver will reconstruct it. Nothing here re-implements the canonical form —
 * it calls the contract's own builder, so a fixture that drifted from the
 * contract would stop signing the bytes the resolver checks and the tests would
 * fail loudly rather than quietly passing against a private copy.
 */
function buildProof(edge: EnrolledEdge, overrides: ProofOverrides = {}) {
  const body = overrides.body ?? '';
  const statementInput: EdgeRequestStatementInput = {
    schema_version: 1,
    edge_id: overrides.edgeId ?? edge.edgeId,
    registry_key_id: overrides.registryKeyId ?? edge.edgeKeyId,
    request_id: overrides.requestId ?? randomUUID().replace(/-/gu, ''),
    method: overrides.method ?? 'POST',
    route: EdgeRequestRouteSchema.parse(overrides.route ?? ROUTE),
    body_digest: body === '' ? EDGE_REQUEST_EMPTY_BODY_DIGEST : edgeRequestBodyDigest(body),
    purpose: overrides.purpose ?? 'TRUSTED_TIME_ANCHOR',
    trusted_time_anchor_id: overrides.trustedTimeAnchorId ?? null,
    edge_trusted_timestamp: overrides.edgeTrustedTimestamp ?? null,
    signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
  };
  const signer = overrides.signWith ?? edge.keyPair;
  const signature = signCanonicalStatement(signer.privateKey, canonicalEdgeRequestStatement(statementInput));
  return {
    proof: {
      schema_version: statementInput.schema_version,
      edge_id: statementInput.edge_id,
      registry_key_id: statementInput.registry_key_id,
      request_id: statementInput.request_id,
      method: statementInput.method,
      route: statementInput.route as string,
      body_digest: statementInput.body_digest,
      purpose: statementInput.purpose,
      trusted_time_anchor_id: statementInput.trusted_time_anchor_id,
      edge_trusted_timestamp: statementInput.edge_trusted_timestamp,
      claimed_signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      signature,
    },
    method: statementInput.method as string,
    route: statementInput.route as string,
    body,
    traceId: randomUUID(),
  };
}

/** Authenticates and returns the context, throwing if the fixture did not authenticate. */
async function authenticated(edge: EnrolledEdge, overrides: ProofOverrides = {}): Promise<AuthenticatedEdgeContext> {
  const result = await auth.authenticate(buildProof(edge, overrides));
  if (result.outcome !== 'AUTHENTICATED') throw new Error('fixture failed to authenticate');
  return result.context;
}

/**
 * Builds an Edge receipt the way a conforming Edge would, through the
 * contract's own statement builder. The result is deliberately `unknown`: the
 * witness service parses what it is given, and a fixture typed as an
 * already-parsed receipt would be a fixture that skipped the boundary under
 * test.
 */
function buildReceipt(edge: EnrolledEdge, overrides: { signWith?: TestDeviceKeyPair; edgeId?: string; edgeKeyId?: string; keyVersion?: number } = {}): unknown {
  const statementInput: DeviceEdgeReceiptStatementInput = {
    schema_version: 1,
    edge_id: overrides.edgeId ?? edge.edgeId,
    edge_key_id: overrides.edgeKeyId ?? edge.edgeKeyId,
    edge_key_version: overrides.keyVersion ?? 1,
    witnessed_operation_fingerprint: 'a'.repeat(64),
    edge_trusted_time: '2026-09-06T12:00:00.000Z',
    edge_monotonic_position: 4_211,
    edge_signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
  };
  const signer = overrides.signWith ?? edge.keyPair;
  return {
    schema_version: statementInput.schema_version,
    edge_id: statementInput.edge_id,
    edge_key_id: statementInput.edge_key_id,
    edge_key_version: statementInput.edge_key_version,
    witnessed_operation_fingerprint: statementInput.witnessed_operation_fingerprint,
    edge_trusted_time: statementInput.edge_trusted_time,
    edge_monotonic_position: statementInput.edge_monotonic_position,
    claimed_edge_signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
    edge_signature: signCanonicalStatement(signer.privateKey, canonicalDeviceEdgeReceiptStatement(statementInput)),
  };
}

beforeAll(async () => {
  Object.assign(process.env, STACK_ENV);
  moduleRef = await Test.createTestingModule({ imports: [ConfigModule, PrismaModule, EdgeGatewayModule] }).compile();
  prisma = moduleRef.get(PrismaService);
  enrolment = moduleRef.get(EdgeEnrolmentService);
  registry = moduleRef.get(EdgeRegistryService);
  auth = moduleRef.get(EdgeAuthenticationService);
  witness = moduleRef.get(EdgeWitnessService);

  await prisma.organisation.create({ data: { id: ORG, name: `${tag} org` } });
  await prisma.organisation.create({ data: { id: OTHER_ORG, name: `${tag} other org` } });
  await prisma.site.create({ data: { id: SITE, organisationId: ORG, name: 'site' } });
  await prisma.site.create({ data: { id: SITE_TWO, organisationId: ORG, name: 'site two' } });
  await prisma.site.create({ data: { id: OTHER_ORG_SITE, organisationId: OTHER_ORG, name: 'foreign site' } });
  await prisma.user.create({ data: { id: COMMANDER, organisationId: ORG, email: `${COMMANDER}@t.test`, displayName: 'C', clearance: 3 } });
  await prisma.user.create({ data: { id: OTHER_COMMANDER, organisationId: OTHER_ORG, email: `${OTHER_COMMANDER}@t.test`, displayName: 'F', clearance: 3 } });
}, 60_000);

afterAll(async () => {
  await cleanupEdgeRows();
  await prisma.user.deleteMany({ where: { organisationId: { in: [ORG, OTHER_ORG] } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: [ORG, OTHER_ORG] } } });
  await prisma.organisation.deleteMany({ where: { id: { in: [ORG, OTHER_ORG] } } });
  await moduleRef.close();
}, 60_000);

beforeEach(async () => {
  await cleanupEdgeRows();
});

// ---------------------------------------------------------------------------

describe('WP-29B EDGE-B the resolver admits a conforming Edge and nothing else', () => {
  it('authenticates a valid proof and builds the context from SERVER state', async () => {
    const edge = await enrolEdge();
    const result = await auth.authenticate(buildProof(edge));
    expect(result.outcome).toBe('AUTHENTICATED');
    if (result.outcome !== 'AUTHENTICATED') return;
    // Every field traced to the registry row, not to the request.
    expect(result.context.edgeId).toBe(edge.edgeId);
    expect(result.context.organisationId).toBe(ORG);
    expect(result.context.siteId).toBe(SITE);
    expect(result.context.registryKeyId).toBe(edge.edgeKeyId);
    expect(result.context.signatureProfile).toBe(EDGE_SERVER_SELECTED_SIGNATURE_PROFILE);
  });

  it('derives the tenant and site from the registry even when the BODY claims otherwise', async () => {
    const edge = await enrolEdge();
    // The body is bound by its digest and is otherwise opaque to the resolver.
    // A hostile Edge naming another tenant in it changes nothing, because
    // nothing in the resolver reads a tenant from a request — and the proof
    // schema has no field it could have put one in.
    const body = JSON.stringify({ organisation_id: OTHER_ORG, site_id: OTHER_ORG_SITE, authorised_site_ids: [SITE_TWO] });
    const result = await auth.authenticate(buildProof(edge, { body }));
    expect(result.outcome).toBe('AUTHENTICATED');
    if (result.outcome !== 'AUTHENTICATED') return;
    expect(result.context.organisationId).toBe(ORG);
    expect(result.context.siteId).toBe(SITE);
  });

  it('gives an Edge at a different site that site, and never the other one', async () => {
    const edge = await enrolEdge(ORG, SITE_TWO);
    const context = await authenticated(edge);
    expect(context.siteId).toBe(SITE_TWO);
  });

  it('holds the single-site invariant: the registry record names exactly one site, and it is the Edge row s', async () => {
    const edge = await enrolEdge();
    const record = await registry.resolveEdgeRegistryKeyRecord(ORG, edge.edgeKeyId);
    expect(record).not.toBeNull();
    expect(record?.authorised_site_ids).toEqual([SITE]);
    const edgeRow = await prisma.edgeNode.findUniqueOrThrow({ where: { id: edge.edgeId } });
    expect(record?.authorised_site_ids[0]).toBe(edgeRow.siteId);
  });

  it('refuses a proof signed by a key that is not the registered one', async () => {
    const edge = await enrolEdge();
    const impostor = generateTestDeviceKeyPair();
    const judged = await auth.authenticateForAudit(buildProof(edge, { signWith: impostor }));
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('POSSESSION_NOT_PROVEN');
  });

  it('refuses a proof that names a DIFFERENT Edge than the key belongs to', async () => {
    const edge = await enrolEdge();
    const other = await enrolEdge(ORG, SITE_TWO);
    // Signed correctly, by the right key, for the wrong principal. Binding
    // `edge_id` into the statement is what makes this a contradiction rather
    // than a lookup somebody could skip.
    const judged = await auth.authenticateForAudit(buildProof(edge, { edgeId: other.edgeId }));
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('EDGE_IDENTITY_MISMATCH');
  });

  it('refuses a body that is not the body that was signed', async () => {
    const edge = await enrolEdge();
    const built = buildProof(edge, { body: '{"edge_boot_id":"boot-a"}' });
    const judged = await auth.authenticateForAudit({ ...built, body: '{"edge_boot_id":"boot-b"}' });
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('BODY_DIGEST_MISMATCH');
  });

  it('refuses a proof presented against a route or a verb it did not sign', async () => {
    const edge = await enrolEdge();
    const built = buildProof(edge, { route: '/edge/v1/heartbeat', purpose: 'EDGE_HEARTBEAT' });
    const routeSwap = await auth.authenticateForAudit({ ...built, route: '/edge/v1/key-rotation' });
    expect(routeSwap.outcome).toBe('REFUSED');
    if (routeSwap.outcome === 'REFUSED') expect(routeSwap.refusal).toBe('REQUEST_BINDING_MISMATCH');

    const verbSwap = await auth.authenticateForAudit({ ...built, method: 'DELETE' });
    expect(verbSwap.outcome).toBe('REFUSED');
    if (verbSwap.outcome === 'REFUSED') expect(verbSwap.refusal).toBe('REQUEST_BINDING_MISMATCH');
  });

  it('refuses a request served on a non-canonical route, before any lookup', async () => {
    const edge = await enrolEdge();
    const built = buildProof(edge);
    const judged = await auth.authenticateForAudit({ ...built, route: '/edge/v1//trusted-time-anchor' });
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') {
      expect(judged.refusal).toBe('ROUTE_NOT_CANONICAL');
      // Nothing resolved, so there is no tenant to file the refusal under.
      expect(judged.organisationId).toBeNull();
    }
  });

  it('refuses a malformed proof without touching the registry', async () => {
    const judged = await auth.authenticateForAudit({ proof: { schema_version: 1 }, method: 'POST', route: ROUTE, body: '', traceId: randomUUID() });
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') {
      expect(judged.refusal).toBe('PROOF_MALFORMED');
      expect(judged.organisationId).toBeNull();
    }
  });
});

describe('WP-29B EDGE-B revocation and suspension are re-asked on every request', () => {
  it('refuses a WITHDRAWN Edge — the key is revoked with it', async () => {
    const edge = await enrolEdge();
    // Authenticates before the withdrawal, so the refusal below is the
    // withdrawal's effect and not a broken fixture.
    expect((await auth.authenticate(buildProof(edge))).outcome).toBe('AUTHENTICATED');

    const withdrawn = await enrolment.withdrawEdge(principal(COMMANDER), { organisationId: ORG, edgeId: edge.edgeId, traceId: randomUUID() });
    expect(withdrawn.outcome).toBe('WITHDRAWN');

    const judged = await auth.authenticateForAudit(buildProof(edge));
    expect(judged.outcome).toBe('REFUSED');
    // The KEY's lifecycle answers first: withdrawal revokes the credential, and
    // a revoked credential is refused whatever the principal's trust says.
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('EDGE_KEY_NOT_USABLE');
  });

  it('refuses a SUSPENDED Edge whose key is still perfectly valid (C15-02 s split)', async () => {
    const edge = await enrolEdge();
    await prisma.edgeNode.update({ where: { id: edge.edgeId }, data: { edgeTrust: EDGE_TRUST_SUSPENDED } });
    const judged = await auth.authenticateForAudit(buildProof(edge));
    expect(judged.outcome).toBe('REFUSED');
    // NOT `EDGE_KEY_NOT_USABLE`. The key is fine; the principal is not, and the
    // two are different incidents.
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('EDGE_NOT_TRUSTED');
  });
});

describe('WP-29B EDGE-B the one-shot request identity', () => {
  it('refuses the SAME proof presented twice', async () => {
    const edge = await enrolEdge();
    const built = buildProof(edge);
    expect((await auth.authenticate(built)).outcome).toBe('AUTHENTICATED');
    const replay = await auth.authenticateForAudit(built);
    expect(replay.outcome).toBe('REFUSED');
    // An authentication has no convergent outcome to hand back, so an exact
    // re-presentation is a replay rather than a retry.
    if (replay.outcome === 'REFUSED') expect(replay.refusal).toBe('REQUEST_REPLAYED');
  });

  it('refuses a DIFFERENT request smuggled under a spent request_id', async () => {
    const edge = await enrolEdge();
    const requestId = randomUUID().replace(/-/gu, '');
    expect((await auth.authenticate(buildProof(edge, { requestId }))).outcome).toBe('AUTHENTICATED');
    // Same slot, different bytes: the case the store exists to catch.
    const substituted = await auth.authenticateForAudit(buildProof(edge, { requestId, route: '/edge/v1/heartbeat', purpose: 'EDGE_HEARTBEAT' }));
    expect(substituted.outcome).toBe('REFUSED');
    if (substituted.outcome === 'REFUSED') expect(substituted.refusal).toBe('REQUEST_REPLAYED');
  });

  it('spends the identity in the ONE anti-replay store, under the Edge ceremony label', async () => {
    const edge = await enrolEdge();
    await auth.authenticate(buildProof(edge));
    // Filtered by ceremony: the enrolment that produced this Edge legitimately
    // spent two OTHER one-shot identities in the same store, which is the
    // point of a single store with ceremony LABELS rather than several stores.
    const rows = await prisma.deviceNonceConsumption.findMany({ where: { organisationId: ORG, ceremony: 'EDGE_REQUEST' } });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.replayKey).toContain('sentinel.edge.request.replay-identity.v1');
  });

  it('does NOT burn an identity for a request that failed to verify', async () => {
    const edge = await enrolEdge();
    const impostor = generateTestDeviceKeyPair();
    const requestId = randomUUID().replace(/-/gu, '');
    await auth.authenticate(buildProof(edge, { requestId, signWith: impostor }));
    expect(await prisma.deviceNonceConsumption.count({ where: { organisationId: ORG, ceremony: 'EDGE_REQUEST' } })).toBe(0);
    // And the honest Edge can still use that id, because nothing was spent.
    expect((await auth.authenticate(buildProof(edge, { requestId }))).outcome).toBe('AUTHENTICATED');
  });

  it('scopes the slot by tenant: two tenants may use the same request_id', async () => {
    const here = await enrolEdge();
    const there = await enrolEdge(OTHER_ORG, OTHER_ORG_SITE, OTHER_COMMANDER);
    const requestId = randomUUID().replace(/-/gu, '');
    expect((await auth.authenticate(buildProof(here, { requestId }))).outcome).toBe('AUTHENTICATED');
    expect((await auth.authenticate(buildProof(there, { requestId }))).outcome).toBe('AUTHENTICATED');
  });
});

describe('WP-29B EDGE-B the trusted-time claim is classified, never believed', () => {
  it('admits an Edge that claims no trusted time and says so honestly', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    expect(context.trustedTime).toBe('NONE');
  });

  it('admits a live claim as CLAIMED', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge, {
      trustedTimeAnchorId: randomUUID(),
      edgeTrustedTimestamp: new Date(Date.now() - 30_000).toISOString(),
    });
    expect(context.trustedTime).toBe('CLAIMED');
  });

  it('admits an aged-out claim as STALE rather than refusing the whole request', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge, {
      trustedTimeAnchorId: randomUUID(),
      edgeTrustedTimestamp: new Date(Date.now() - EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS - 60_000).toISOString(),
    });
    // An Edge whose anchor aged out is still an Edge. It simply holds no
    // trusted time, and the standing says so instead of a nullable instant a
    // caller would forget to check.
    expect(context.trustedTime).toBe('STALE');
  });

  it('refuses a claim central can see is in the future', async () => {
    const edge = await enrolEdge();
    const judged = await auth.authenticateForAudit(
      buildProof(edge, { trustedTimeAnchorId: randomUUID(), edgeTrustedTimestamp: new Date(Date.now() + 3_600_000).toISOString() }),
    );
    expect(judged.outcome).toBe('REFUSED');
    // An Edge that cannot make an honest claim may make NO claim. It may not
    // make a false one about a fact central checks for itself.
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('TRUSTED_TIME_CLAIM_NOT_PLAUSIBLE');
  });
});

describe('WP-29B/D25-13 the refusal boundary is not an enumeration oracle', () => {
  it('answers identically for a nonexistent key and for another tenant s Edge', async () => {
    const here = await enrolEdge();
    const there = await enrolEdge(OTHER_ORG, OTHER_ORG_SITE, OTHER_COMMANDER);

    // A key that never existed.
    const ghost = await auth.authenticate(buildProof(here, { registryKeyId: randomUUID() }));
    // A key that belongs to another tenant entirely, presented with this
    // tenant's Edge id: the resolver derives THAT key's tenant, then finds the
    // claimed Edge is not its Edge.
    const foreign = await auth.authenticate(buildProof(here, { registryKeyId: there.edgeKeyId }));

    expect(ghost).toEqual({ outcome: 'REFUSED' });
    expect(foreign).toEqual({ outcome: 'REFUSED' });
    // Byte-identical external answers. The internal reasons differ, and that
    // difference lives only in the audit.
    expect(JSON.stringify(ghost)).toBe(JSON.stringify(foreign));
  });

  it('answers identically for a revoked Edge, a suspended Edge and a forged signature', async () => {
    const withdrawn = await enrolEdge();
    await enrolment.withdrawEdge(principal(COMMANDER), { organisationId: ORG, edgeId: withdrawn.edgeId, traceId: randomUUID() });
    const suspended = await enrolEdge(ORG, SITE_TWO);
    await prisma.edgeNode.update({ where: { id: suspended.edgeId }, data: { edgeTrust: EDGE_TRUST_SUSPENDED } });
    const honest = await enrolEdge();

    const answers = [
      await auth.authenticate(buildProof(withdrawn)),
      await auth.authenticate(buildProof(suspended)),
      await auth.authenticate(buildProof(honest, { signWith: generateTestDeviceKeyPair() })),
    ];
    for (const answer of answers) expect(answer).toEqual({ outcome: 'REFUSED' });
  });

  it('files the PRECISE reason internally, and only internally', async () => {
    const edge = await enrolEdge();
    await prisma.edgeNode.update({ where: { id: edge.edgeId }, data: { edgeTrust: EDGE_TRUST_SUSPENDED } });
    const external = await auth.authenticate(buildProof(edge));
    expect(external).toEqual({ outcome: 'REFUSED' });

    const events = await prisma.edgeSecurityEvent.findMany({ where: { organisationId: ORG, eventType: 'EDGE_REQUEST_REFUSED' } });
    expect(events).toHaveLength(1);
    expect(events[0]?.refusalCode).toBe('EDGE_NOT_TRUSTED');
    expect(events[0]?.edgeId).toBe(edge.edgeId);
  });

  it('files NO row for a refusal taken before any tenant was established', async () => {
    // C17-02 from the other direction: an audit row must be filed under a
    // tenant the server established, and a malformed proof establishes none.
    // Inventing a placeholder would corrupt every tenant-scoped audit query.
    await auth.authenticate({ proof: { nonsense: true }, method: 'POST', route: ROUTE, body: '', traceId: randomUUID() });
    expect(await prisma.edgeSecurityEvent.count({ where: { organisationId: ORG } })).toBe(0);
    expect(await prisma.edgeSecurityEvent.count({ where: { organisationId: OTHER_ORG } })).toBe(0);
  });

  it('files an authentication under the tenant the REGISTRY named, carrying no statement', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const events = await prisma.edgeSecurityEvent.findMany({ where: { organisationId: ORG, eventType: 'EDGE_REQUEST_AUTHENTICATED' } });
    expect(events).toHaveLength(1);
    expect(events[0]?.siteId).toBe(SITE);
    const payload = events[0]?.payload as Record<string, unknown>;
    expect(payload.statement_fingerprint).toBe(context.statementFingerprint);
    // The DIGEST, never the statement, and never a signature.
    expect(JSON.stringify(payload)).not.toContain('signature');
  });
});

// ---------------------------------------------------------------------------
// THE TWO-LAYER RULE. Two directions, two independent tests.
// ---------------------------------------------------------------------------

describe('WP-29B EDGE-B a verified receipt is NOT an authenticated caller', () => {
  it('refuses a perfectly valid receipt presented by nobody', async () => {
    const edge = await enrolEdge();
    const receipt = buildReceipt(edge);

    // Prove the receipt itself is genuine, so this test is about the CALLER and
    // not about a broken fixture: presented by an authenticated Edge, the very
    // same bytes are admitted.
    const context = await authenticated(edge);
    expect((await witness.admitReceipt(context, receipt, randomUUID())).outcome).toBe('ADMITTED');

    const judged = await witness.admitReceiptForAudit(null, receipt, randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('CALLER_NOT_AUTHENTICATED');
  });

  it('refuses a receipt carried by a hand-built object that LOOKS like a context', async () => {
    const edge = await enrolEdge();
    const receipt = buildReceipt(edge);
    // Every field of a real context, correct values, taken from the database.
    // It is refused because the question is never "does this look
    // authenticated?" but "did the resolver produce it?".
    const forgedContext = {
      edgeId: edge.edgeId,
      organisationId: ORG,
      siteId: SITE,
      registryKeyId: edge.edgeKeyId,
      signatureProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      purpose: 'OFFLINE_OPERATION_INGRESS',
      method: 'POST',
      route: ROUTE,
      trustedTime: 'CLAIMED',
      statementFingerprint: 'b'.repeat(64),
    };
    const judged = await witness.admitReceiptForAudit(forgedContext, receipt, randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('CALLER_NOT_AUTHENTICATED');
  });

  it('cannot be handed a hand-built context at COMPILE time either', async () => {
    const edge = await enrolEdge();
    // @ts-expect-error an object literal is not an AuthenticatedEdgeContext: the brand symbol is module-private and cannot be named here.
    const forged: AuthenticatedEdgeContext = {
      edgeId: edge.edgeId,
      organisationId: ORG,
      siteId: SITE,
      registryKeyId: edge.edgeKeyId,
      signatureProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      purpose: 'OFFLINE_OPERATION_INGRESS',
      method: 'POST',
      route: ROUTE,
      trustedTime: 'CLAIMED',
      statementFingerprint: 'b'.repeat(64),
    };
    // The runtime agrees with the compiler.
    expect((await witness.admitReceiptForAudit(forged, buildReceipt(edge), randomUUID())).outcome).toBe('REFUSED');
  });

  it('writes no audit row for a receipt presented by nobody — there is no tenant to file under', async () => {
    const edge = await enrolEdge();
    await witness.admitReceipt(null, buildReceipt(edge), randomUUID());
    expect(await prisma.edgeSecurityEvent.count({ where: { organisationId: ORG, eventType: { startsWith: 'EDGE_RECEIPT' } } })).toBe(0);
  });
});

describe('WP-29B EDGE-B an authenticated caller does NOT get its receipts believed', () => {
  it('refuses a receipt signed by a key that is not the registered one', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const forged = buildReceipt(edge, { signWith: generateTestDeviceKeyPair() });

    const judged = await witness.admitReceiptForAudit(context, forged, randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('RECEIPT_SIGNATURE_NOT_VERIFIED');
  });

  it('leaves the caller s authentication untouched when its receipt is refused', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    expect((await witness.admitReceipt(context, buildReceipt(edge, { signWith: generateTestDeviceKeyPair() }), randomUUID())).outcome).toBe('REFUSED');
    // "Who are you" and "is this evidence real" are different questions, and
    // neither answer is borrowed for the other: the same context still admits a
    // genuine receipt.
    expect((await witness.admitReceipt(context, buildReceipt(edge), randomUUID())).outcome).toBe('ADMITTED');
  });

  it('refuses a receipt about ANOTHER tenant s Edge exactly as it refuses a nonexistent one', async () => {
    const here = await enrolEdge();
    const there = await enrolEdge(OTHER_ORG, OTHER_ORG_SITE, OTHER_COMMANDER);
    const context = await authenticated(here);

    const foreign = await witness.admitReceiptForAudit(context, buildReceipt(there, { edgeId: here.edgeId, signWith: there.keyPair }), randomUUID());
    const ghost = await witness.admitReceiptForAudit(context, buildReceipt(here, { edgeKeyId: randomUUID() }), randomUUID());

    // ONE code from ONE query. A caller able to tell these apart could
    // enumerate another tenant's Edge inventory through this surface.
    expect(foreign.outcome).toBe('REFUSED');
    expect(ghost.outcome).toBe('REFUSED');
    if (foreign.outcome === 'REFUSED' && ghost.outcome === 'REFUSED') expect(foreign.refusal).toBe(ghost.refusal);
    expect(await witness.admitReceipt(context, buildReceipt(there, { edgeId: here.edgeId }), randomUUID())).toEqual({ outcome: 'REFUSED' });
  });

  it('refuses a receipt about an Edge that is not the caller', async () => {
    const caller = await enrolEdge();
    const other = await enrolEdge(ORG, SITE_TWO);
    const context = await authenticated(caller);
    const judged = await witness.admitReceiptForAudit(context, buildReceipt(other), randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('RECEIPT_EDGE_NOT_CALLER');
  });

  it('refuses a receipt naming a key version the registry does not hold', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const judged = await witness.admitReceiptForAudit(context, buildReceipt(edge, { keyVersion: 7 }), randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('EDGE_IDENTITY_MISMATCH');
  });

  it('re-asks revocation at the receipt layer, after authentication succeeded', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    // The credential is withdrawn AFTER the caller authenticated. Central
    // revalidates rather than trusting a moment-old conclusion.
    await enrolment.withdrawEdge(principal(COMMANDER), { organisationId: ORG, edgeId: edge.edgeId, traceId: randomUUID() });
    const judged = await witness.admitReceiptForAudit(context, buildReceipt(edge), randomUUID());
    expect(judged.outcome).toBe('REFUSED');
    if (judged.outcome === 'REFUSED') expect(judged.refusal).toBe('EDGE_KEY_NOT_USABLE');
  });

  it('takes the tenant and the site of an admitted witness from the CONTEXT', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const judged = await witness.admitReceiptForAudit(context, buildReceipt(edge), randomUUID());
    expect(judged.outcome).toBe('ADMITTED');
    if (judged.outcome !== 'ADMITTED') return;
    // The receipt carries neither field and must never grow one.
    expect(judged.witness.organisationId).toBe(ORG);
    expect(judged.witness.siteId).toBe(SITE);
    const events = await prisma.edgeSecurityEvent.findMany({ where: { organisationId: ORG, eventType: 'EDGE_RECEIPT_ADMITTED' } });
    expect(events).toHaveLength(1);
    expect(events[0]?.edgeKeyId).toBe(edge.edgeKeyId);
  });
});

// ===========================================================================
// M3B §15 — THE EDGE IS A WITNESS, NOT A PROXY HUMAN.
//
// Every test here exists to prove ONE property from a different angle:
//
//     EDGE RECOVERY DOES NOT ERASE HUMAN AUTHORITY
//
// The Edge can authenticate perfectly, carry a perfectly valid device
// envelope, present a perfectly valid receipt and a perfectly verified
// central-signed time anchor -- and still cause no domain effect. C17-01 is
// preserved by construction, and these assert it rather than trusting it.
// ===========================================================================
describe('M3B \u00a715 Edge evidence relay causes no domain effect', () => {
  let observations: EdgeReceiptObservationService;
  let standing: EdgeEvidenceStandingService;

  beforeAll(() => {
    observations = moduleRef.get(EdgeReceiptObservationService);
    standing = moduleRef.get(EdgeEvidenceStandingService);
  });

  /** Records one witness exactly as the ingress does, and reports the outcome. */
  async function relay(
    context: AuthenticatedEdgeContext,
    receipt: unknown,
    overrides: { offlineOperationId?: string | null } = {},
  ): Promise<{ outcome: string; standing: string }> {
    const admission = await witness.admitReceiptForAudit(context, receipt, randomUUID());
    expect(admission.outcome).toBe('ADMITTED');
    if (admission.outcome !== 'ADMITTED') throw new Error('unreachable');

    const offlineOperationId = overrides.offlineOperationId === undefined ? randomUUID() : overrides.offlineOperationId;
    const outcome = await observations.record({
      witness: admission.witness,
      // Verified time is exercised separately; the point of THIS suite is that
      // even a fully verified relay changes nothing in the domain.
      verifiedTime: null,
      offlineOperationId,
      traceId: randomUUID(),
    });
    const current = await standing.standingOf(context.organisationId, offlineOperationId);
    return { outcome, standing: current };
  }

  async function domainReceiptCount(organisationId: string): Promise<number> {
    return prisma.fieldOfflineOperationReceipt.count({ where: { organisationId } });
  }

  it('persists the observation and causes NO domain effect, with no human anywhere', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const before = await domainReceiptCount(ORG);

    const result = await relay(context, buildReceipt(edge));

    expect(result.outcome).toBe('FIRST_SEEN');
    // The honest answer while the Field device has not reconnected.
    expect(result.standing).toBe('EVIDENCE_RECORDED');
    // THE LOAD-BEARING ASSERTION. No authoritative replay record was created.
    expect(await domainReceiptCount(ORG)).toBe(before);

    const stored = await prisma.edgeReceiptObservation.count({ where: { organisationId: ORG } });
    expect(stored).toBeGreaterThan(0);
  });


  /**
   * The §15 case that needs REAL verified evidence rather than a null.
   *
   * A fully verified, central-signed trusted time is the strongest thing this
   * channel can carry. It still causes no domain effect, and that is the point:
   * the strength of the EVIDENCE has no bearing on whether an operation is
   * AUTHORISED, because those are different questions asked of different
   * principals.
   */
  it('a fully VERIFIED central trusted time still causes no domain effect', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const before = await domainReceiptCount(ORG);

    // A real anchor, signed by a real key, verified by the real verifier --
    // constructed here rather than faked, because a stubbed
    // `VerifiedEdgeTrustedTimeEvidence` would prove nothing about the path.
    const signingPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = signingPair.publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    const publicKey = Buffer.concat([
      Buffer.from([0x04]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]).toString('base64url');

    const anchorStatement = {
      schema_version: 1 as const,
      anchor_id: randomUUID(),
      edge_id: context.edgeId,
      organisation_id: context.organisationId,
      site_id: context.siteId,
      edge_boot_id: 'boot-a',
      edge_monotonic_at_anchor: 1_000_000,
      server_issued_at: '2026-09-07T00:00:00.000Z',
      server_valid_until: '2026-09-07T06:00:00.000Z',
      signer_key_id: 'central-tta-test',
    };

    const canonical = canonicalEdgeTrustedTimeAnchorStatement(anchorStatement as never);
    const signer = createSign('sha256');
    signer.update(Buffer.from(canonical, 'utf8'));
    signer.end();
    const raw = signer.sign({ key: signingPair.privateKey, dsaEncoding: 'ieee-p1363' });
    const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
    const rawS = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
    const lowS = rawS > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - rawS : rawS;
    const anchorSignature = encodeCanonicalP256Signature(r, lowS);

    const derivedIso = new Date(Date.parse(anchorStatement.server_issued_at) + 30_000).toISOString();
    const verifier = new CentralEdgeTrustedTimeVerifier(
      new CentralTrustedTimeKeyringProvider({
        values: {
          EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([
            { signer_key_id: 'central-tta-test', public_key: publicKey, role: 'ACTIVE' },
          ]),
        },
      } as never),
      moduleRef.get(P256KeyImporter),
    );

    const verification = verifier.verify(
      context,
      {
        schema_version: 1,
        signed_anchor: { statement: anchorStatement, signature: anchorSignature },
        edge_boot_id: 'boot-a',
        edge_monotonic_at_observation: 1_030_000,
      },
      derivedIso,
    );
    expect(verification.ok, 'the anchor should have verified').toBe(true);
    if (!verification.ok) return;

    const admission = await witness.admitReceiptForAudit(context, buildReceipt(edge), randomUUID());
    expect(admission.outcome).toBe('ADMITTED');
    if (admission.outcome !== 'ADMITTED') return;

    const operationId = randomUUID();
    await observations.record({
      witness: admission.witness,
      verifiedTime: verification.evidence,
      offlineOperationId: operationId,
      traceId: randomUUID(),
    });

    // The verified time IS recorded, with its provenance.
    const stored = await prisma.edgeReceiptObservation.findFirst({
      where: { organisationId: ORG, offlineOperationId: operationId },
      select: { verifiedEdgeTrustedTime: true, trustedTimeAnchorId: true },
    });
    expect(stored?.verifiedEdgeTrustedTime?.toISOString()).toBe(derivedIso);
    expect(stored?.trustedTimeAnchorId).toBe(anchorStatement.anchor_id);

    // AND STILL NO DOMAIN EFFECT. The strongest possible evidence does not
    // authorise anything.
    expect(await domainReceiptCount(ORG)).toBe(before);
    expect(await standing.standingOf(ORG, operationId)).toBe('EVIDENCE_RECORDED');
  });

  it('a valid Edge receipt ALONE is not human authority', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const before = await domainReceiptCount(ORG);
    await relay(context, buildReceipt(edge));
    expect(await domainReceiptCount(ORG)).toBe(before);
  });

  it('the observation never advances a device cursor', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const cursorsBefore = await prisma.fieldOfflineDeviceCursor.count({ where: { organisationId: ORG } }).catch(() => 0);
    await relay(context, buildReceipt(edge));
    const cursorsAfter = await prisma.fieldOfflineDeviceCursor.count({ where: { organisationId: ORG } }).catch(() => 0);
    expect(cursorsAfter).toBe(cursorsBefore);
  });

  it('the SAME evidence arriving again CONVERGES rather than duplicating', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const receipt = buildReceipt(edge);
    const operationId = randomUUID();

    const first = await relay(context, receipt, { offlineOperationId: operationId });
    const second = await relay(context, receipt, { offlineOperationId: operationId });

    expect(first.outcome).toBe('FIRST_SEEN');
    expect(second.outcome).toBe('CONVERGED');
    // One witness, one row. A lost response is the NORMAL case, and Proof D
    // would count a single witnessed operation twice if this ever diverged.
    //
    // Scoped to THIS operation, not to the tenant: earlier tests in this block
    // legitimately leave their own observations behind, and a tenant-wide count
    // would make this assertion depend on execution order rather than on
    // convergence.
    const rows = await prisma.edgeReceiptObservation.count({
      where: { organisationId: ORG, offlineOperationId: operationId },
    });
    expect(rows).toBe(1);
  });

  it('the same evidence identity bound to a DIFFERENT operation is a CONFLICT', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const receipt = buildReceipt(edge);

    const first = await relay(context, receipt, { offlineOperationId: randomUUID() });
    expect(first.outcome).toBe('FIRST_SEEN');

    // `receipt_fingerprint` digests the Edge's signed statement, but the
    // operation id comes from envelope bytes the receipt does not cover -- so
    // one signed receipt CAN be re-bound to another operation. That must be
    // refused, never silently converged.
    const second = await relay(context, receipt, { offlineOperationId: randomUUID() });
    expect(second.outcome).toBe('CONFLICT');
  });

  it('reports EVIDENCE_RECORDED when the envelope carried no correlatable id', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    // Not UNKNOWN: we know exactly what we hold and exactly what we lack.
    const result = await relay(context, buildReceipt(edge), { offlineOperationId: null });
    expect(result.standing).toBe('EVIDENCE_RECORDED');
  });

  it('reports the AUTHORITATIVE standing once a real replay record exists', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    const operationId = randomUUID();
    await relay(context, buildReceipt(edge), { offlineOperationId: operationId });

    // Written directly here to stand in for the human-authenticated replay
    // path, which this suite deliberately does not invoke: the point is that
    // the standing is read from the DEVICE's record, whoever wrote it.
    await prisma.fieldOfflineOperationReceipt.create({
      data: {
        organisationId: ORG,
        siteId: SITE,
        userId: COMMANDER,
        deviceId: randomUUID(),
        deviceSequence: BigInt(1),
        offlineOperationId: operationId,
        operationKind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
        requestFingerprint: 'a'.repeat(64),
        downstreamIdempotencyKey: randomUUID(),
        clientCreatedAt: new Date(),
        firstReceivedAt: new Date(),
        firstTraceId: randomUUID(),
        status: 'APPLIED',
        outcome: 'APPLIED',
      },
    });

    const current = await standing.standingOf(ORG, operationId);
    expect(current).toBe('AUTHORITATIVE_REPLAY_APPLIED');
  });

  it('a REJECTED row with no finalised outcome is UNKNOWN, not terminal', async () => {
    const operationId = randomUUID();
    await prisma.fieldOfflineOperationReceipt.create({
      data: {
        organisationId: ORG,
        siteId: SITE,
        userId: COMMANDER,
        deviceId: randomUUID(),
        deviceSequence: BigInt(2),
        offlineOperationId: operationId,
        operationKind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
        requestFingerprint: 'b'.repeat(64),
        downstreamIdempotencyKey: randomUUID(),
        clientCreatedAt: new Date(),
        firstReceivedAt: new Date(),
        firstTraceId: randomUUID(),
        status: 'REJECTED',
        outcome: null,
      },
    });

    // The Edge must not prune an entry central may still apply.
    expect(await standing.standingOf(ORG, operationId)).toBe('UNKNOWN');
  });

  it('correlates EXACTLY, never by nearest match', async () => {
    const edge = await enrolEdge();
    const context = await authenticated(edge);
    await relay(context, buildReceipt(edge), { offlineOperationId: randomUUID() });

    // A different operation id in the same tenant must not inherit a standing.
    expect(await standing.standingOf(ORG, randomUUID())).toBe('EVIDENCE_RECORDED');
  });

  it('does not read another tenant\'s replay record', async () => {
    const operationId = randomUUID();
    await prisma.fieldOfflineOperationReceipt.create({
      data: {
        organisationId: ORG,
        siteId: SITE,
        userId: COMMANDER,
        deviceId: randomUUID(),
        deviceSequence: BigInt(3),
        offlineOperationId: operationId,
        operationKind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
        requestFingerprint: 'c'.repeat(64),
        downstreamIdempotencyKey: randomUUID(),
        clientCreatedAt: new Date(),
        firstReceivedAt: new Date(),
        firstTraceId: randomUUID(),
        status: 'APPLIED',
        outcome: 'APPLIED',
      },
    });

    // Same operation id, foreign tenant: the applied outcome must be invisible.
    expect(await standing.standingOf(OTHER_ORG, operationId)).toBe('EVIDENCE_RECORDED');
  });
});
