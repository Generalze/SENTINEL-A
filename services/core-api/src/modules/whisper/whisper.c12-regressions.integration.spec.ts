import { generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import {
  canonicalWhisperSignedStatement,
  WHISPER_SIGNATURE_ALGORITHM,
  whisperConfigurationFingerprint,
  whisperRecognitionFingerprint,
  type AuthenticatedWhisperDeviceContext,
  type DeviceActionWhisperResult,
} from '@sentinel/contracts';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { PrismaService } from '../../prisma/prisma.service';
import { IncidentsRepository } from '../incidents/incidents.repository';
import { IncidentsService } from '../incidents/incidents.service';
import { WHISPER_DEVICE_KEY_RESOLVER, type WhisperDeviceKeyResolver } from './whisper-key.resolver';
import { WhisperSignatureVerifier } from './whisper-signature.verifier';
import { ACTION_WHISPER_DEVICE_ACTION_INVOKE } from './whisper.constants';
import { WhisperRepository } from './whisper.repository';
import { WhisperService } from './whisper.service';
import { WhisperRecognitionUnresolvedError } from './whisper.types';

/**
 * C12 AUDIT REGRESSIONS.
 *
 * Four corrections were made after the WP-21B audit. Each is a property that
 * the existing 65 Whisper tests do not pin, and each failed silently rather
 * than loudly before the correction — which is precisely why they need
 * regressions of their own rather than a line appended to a passing test.
 *
 *   C12-01  The PRINCIPAL must be the trusted device context's actor.
 *           Otherwise the capability answer is BORROWED: an actor holding no
 *           `whisper.device-action.invoke` fires a silent duress signal
 *           because some unrelated principal in the tenant holds it.
 *
 *   C12-02  An Incident row is NOT proof the SILENT protocol was entered.
 *           The incident commits in one transaction; the Proof-A/SILENT
 *           machinery runs after it. Recovery that short-circuits on the
 *           incident finalises ACCEPTED over a response nobody established.
 *
 *   C12-03  At most one ACTIVE version per (organisation, family), enforced
 *           BELOW the service layer by a partial unique index.
 *
 *   C12-04  A direct organisation FK, because the composite Site FK is
 *           MATCH SIMPLE and an organisation-wide signal (site_id NULL) skips
 *           it entirely.
 *
 * This file carries its OWN fixture tag and bootstrap deliberately. C12-01 and
 * C12-03 need role and lifecycle states the two existing suites do not seed
 * (an actor who genuinely lacks invoke; two ACTIVE versions attempted at once),
 * and C12-02 faults a shared singleton mid-flight. Isolating that from the 65
 * tests already proving the runtime is cheaper than making those 65 tolerate
 * it. The Ed25519 registry, signing helper and cleanup order are the runtime
 * suite's, reused unchanged so a divergence there cannot hide here.
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

const tag = `wp21bc12_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteB1: `${tag}_siteB1`,
  commanderA1: `${tag}_commanderA1`,
  /** The DISTINCT approver W21-12 requires. */
  approverA1: `${tag}_approverA1`,
  /** field.operative @ siteA1 — the only §62 role holding invoke. */
  operativeA1: `${tag}_operativeA1`,
  /**
   * operator @ siteA1. In the tenant, on the roster, on a trusted device — and
   * WITHOUT `whisper.device-action.invoke`. C12-01's whole point is this
   * actor, so the suite asserts the absence rather than assuming it.
   */
  nonInvokerA1: `${tag}_nonInvokerA1`,
  operativeB1: `${tag}_operativeB1`,
  deviceA1: `${tag}_deviceA1`,
  keyA1: `${tag}_keyA1`,
};

const DEVICE_ACTION = 'triple-tap-power';
const LIFECYCLE_TO_APPROVAL = ['SIMULATION', 'FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL'] as const;
const REQUIRED_PROOF_A_TASKS = ['preserve-evidence', 'notify-commander', 'dispatch-field'] as const;

type UnsignedResult = Omit<DeviceActionWhisperResult, 'signature'>;

/** The runtime suite's deterministic stand-in, keyed by (organisation, key id). */
class TestDeviceKeyRegistry implements WhisperDeviceKeyResolver {
  private readonly keys = new Map<string, KeyObject>();

  register(organisationId: string, verificationKeyId: string, publicKey: KeyObject): void {
    this.keys.set(`${organisationId} ${verificationKeyId}`, publicKey);
  }

  async resolveVerificationKey(organisationId: string, verificationKeyId: string): Promise<KeyObject | null> {
    return this.keys.get(`${organisationId} ${verificationKeyId}`) ?? null;
  }
}

const keyA1 = generateKeyPairSync('ed25519');
const keyRegistry = new TestDeviceKeyRegistry();
keyRegistry.register(fx.orgA, fx.keyA1, keyA1.publicKey);

/** Signs EXACTLY the canonical statement, unpadded base64url, as W21-06 requires. */
function signResult(unsigned: UnsignedResult, privateKey: KeyObject): DeviceActionWhisperResult {
  const statement = canonicalWhisperSignedStatement(unsigned);
  const signature = cryptoSign(null, Buffer.from(statement, 'utf8'), privateKey).toString('base64url');
  return { ...unsigned, signature };
}

/** The seeded role baseline. Restored before every test, because C12-01's positive control grants a role. */
const SEEDED_ROLES: ReadonlyArray<{ id: string; org: string; role: string; site: string }> = [
  { id: fx.commanderA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
  { id: fx.approverA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
  { id: fx.operativeA1, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
  { id: fx.nonInvokerA1, org: fx.orgA, role: 'operator', site: fx.siteA1 },
  { id: fx.operativeB1, org: fx.orgB, role: 'field.operative', site: fx.siteB1 },
];

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({
    data: [
      { id: fx.orgA, name: 'WP-21B C12 Org A' },
      { id: fx.orgB, name: 'WP-21B C12 Org B' },
    ],
  });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });
  await prisma.user.createMany({
    data: SEEDED_ROLES.map((u) => ({ id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5 })),
  });
  await prisma.userRole.createMany({ data: SEEDED_ROLES.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });
}

/**
 * Restores the declared role baseline.
 *
 * C12-01's positive control GRANTS invoke to an actor who started without it,
 * so leaving that grant in place would silently disarm the two refusal tests
 * if the file were ever reordered. Re-deriving the baseline each time is a few
 * rows and removes the ordering dependency entirely.
 */
async function resetRoles(prisma: PrismaService): Promise<void> {
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: [fx.orgA, fx.orgB] } } } });
  await prisma.userRole.createMany({ data: SEEDED_ROLES.map((u) => ({ userId: u.id, role: u.role, siteId: u.site })) });
}

/** Everything one test may have written, deleted child-first (the runtime suite's order). */
async function truncateDomain(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  await prisma.responseDispatchHandoff.deleteMany({ where: { task: { incident: { organisationId: { in: orgs } } } } });
  await prisma.responseTaskSilentApproval.deleteMany({ where: { task: { incident: { organisationId: { in: orgs } } } } });
  await prisma.responseTask.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incidentUpdateOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperRecognitionReceipt.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperActivationApproval.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperSignalVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.whisperAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOperativeCurrentState.deleteMany({ where: { organisationId: { in: orgs } } });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  await truncateDomain(prisma);
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
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

describe('WP-21B C12 audit regressions (live stack)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let whisper: WhisperService;
  let incidents: IncidentsService;
  let incidentsRepository: IncidentsRepository;
  let whisperRepository: WhisperRepository;
  let verifier: WhisperSignatureVerifier;

  /** The principal as the DevAuthGuard would build it — read live, so a granted role really appears. */
  async function principalFor(userId: string): Promise<Principal> {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, include: { roles: true } });
    return buildPrincipal({
      user: { id: user.id, clearance: user.clearance },
      organisation_id: user.organisationId,
      roles: user.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
    });
  }

  /** Creates a family and walks it all the way to ACTIVE through the real Studio path. */
  async function activeSignal(overrides: Record<string, unknown> = {}): Promise<{ id: string; version: number }> {
    const author = await principalFor(fx.commanderA1);
    const approver = await principalFor(fx.approverA1);
    const created = await whisper.createSignal(
      author,
      whisper.parseCreateSignal({
        site_id: fx.siteA1,
        name: 'Duress tap',
        device_action_id: DEVICE_ACTION,
        authorised_user_ids: [fx.operativeA1],
        context_requirements: {},
        minimum_confidence: 0.5,
        response_protocol_id: 'SILENT_INCIDENT_RESPONSE',
        trace_id: `trace-${randomUUID()}`,
        ...overrides,
      }),
    );
    for (const to of LIFECYCLE_TO_APPROVAL) {
      await whisper.transition(author, created.whisper_signal_id, 1, whisper.parseTransition({ to, trace_id: `trace-${randomUUID()}` }));
    }
    await whisper.activate(approver, created.whisper_signal_id, 1, whisper.parseActivate({ trace_id: `trace-${randomUUID()}` }));
    return { id: created.whisper_signal_id, version: 1 };
  }

  function unsignedResult(signal: { id: string; version: number }, overrides: Partial<UnsignedResult> = {}): UnsignedResult {
    return {
      schema_version: 1,
      whisper_result_id: `result-${randomUUID()}`,
      whisper_signal_id: signal.id,
      whisper_signal_version: signal.version,
      organisation_id: fx.orgA,
      site_id: fx.siteA1,
      actor_user_id: fx.operativeA1,
      device_id: fx.deviceA1,
      device_action_id: DEVICE_ACTION,
      recognised_at: new Date().toISOString(),
      confidence: 0.95,
      device_trust: 'TRUSTED',
      context: {},
      freshness_ms: 0,
      anti_replay_nonce: `nonce-${randomUUID()}${randomUUID()}`,
      signature_algorithm: WHISPER_SIGNATURE_ALGORITHM,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  function deviceContext(overrides: Partial<AuthenticatedWhisperDeviceContext> = {}): AuthenticatedWhisperDeviceContext {
    return {
      organisationId: fx.orgA,
      actorUserId: fx.operativeA1,
      deviceId: fx.deviceA1,
      authorisedSiteIds: [fx.siteA1],
      deviceTrust: 'TRUSTED',
      verificationKeyId: fx.keyA1,
      ...overrides,
    };
  }

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

  const incidentsForFingerprint = (fingerprint: string, organisationId = fx.orgA) =>
    prisma.incident.findMany({ where: { organisationId, sourceKind: 'WHISPER_RECOGNITION', sourceRef: fingerprint } });

  /**
   * A well-formed version row written STRAIGHT AT THE TABLE.
   *
   * Every C12-03/C12-04 test writes through PrismaService rather than the
   * service, because the property under test is what the DATABASE refuses.
   * A service-level test could only ever prove the service is careful today.
   */
  function directVersionRow(overrides: Partial<Prisma.WhisperSignalVersionUncheckedCreateInput> = {}): Prisma.WhisperSignalVersionUncheckedCreateInput {
    const configuration = {
      modality: 'DEVICE_ACTION',
      device_action_id: DEVICE_ACTION,
      authorised_user_ids: [fx.operativeA1],
      context_requirements: {},
      minimum_confidence: 0.5,
      response_protocol_id: 'SILENT_INCIDENT_RESPONSE',
    } as const;
    return {
      whisperSignalId: randomUUID(),
      signalVersion: 1,
      organisationId: fx.orgA,
      siteId: null,
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
    };
  }

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(WHISPER_DEVICE_KEY_RESOLVER)
      .useValue(keyRegistry)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    prisma = app.get(PrismaService);
    whisper = app.get(WhisperService);
    incidents = app.get(IncidentsService);
    incidentsRepository = app.get(IncidentsRepository);
    whisperRepository = app.get(WhisperRepository);
    verifier = app.get(WhisperSignatureVerifier);
    await seed(prisma);
  }, 120_000);

  afterAll(async () => {
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 60_000);

  beforeEach(async () => {
    await truncateDomain(prisma);
    await resetRoles(prisma);
  }, 30_000);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ==========================================================================
  // C12-01 borrowed authority
  // ==========================================================================

  it('C12-01: a principal who is not the context actor cannot lend their invoke authority', async () => {
    // The roster names the NON-INVOKER, so the only thing standing between this
    // actor and a silent dispatch is `whisper.device-action.invoke` — which
    // they do not hold and the substituted principal does.
    const signal = await activeSignal({ authorised_user_ids: [fx.nonInvokerA1] });

    const borrower = await principalFor(fx.nonInvokerA1);
    const lender = await principalFor(fx.operativeA1);
    // Non-vacuity: if this ever stopped being true the test would pass for the
    // wrong reason, proving only that a refusal happened somewhere.
    expect(borrower.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(false);
    expect(lender.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(true);

    // Context and signed statement are BOTH the non-invoker's and both valid.
    // Only the principal is somebody else's.
    const signed = signResult(
      unsignedResult(signal, { actor_user_id: fx.nonInvokerA1 }),
      keyA1.privateKey,
    );
    const context = deviceContext({ actorUserId: fx.nonInvokerA1 });

    // The ORDERING is itself the disclosure argument: the binding is checked
    // immediately after parsing, so a mismatch cannot reach the verifier or
    // the signal lookup and therefore cannot be timed or probed for whether a
    // signal exists. Spying is how that ordering stays pinned — a correction
    // that merely moved the check later would still refuse, and every state
    // assertion below would still pass.
    const verifySpy = vi.spyOn(verifier, 'verify');
    const lookupSpy = vi.spyOn(whisperRepository, 'findVersionForRuntime');

    const outcome = await whisper.recognise(context, signed, lender);

    expect(outcome).toMatchObject({ kind: 'refused', conflict_code: 'DEVICE_CONTEXT_MISMATCH', replayed: false });
    expect(verifySpy).not.toHaveBeenCalled();
    expect(lookupSpy).not.toHaveBeenCalled();

    // NO receipt: the refusal precedes the replay boundary, so this signed
    // result's one-shot seven-column identity is untouched and still spendable.
    expect(await receiptsForIdentity(signed)).toHaveLength(0);
    expect(await prisma.whisperRecognitionReceipt.count({ where: { organisationId: fx.orgA } })).toBe(0);

    // NO incident, and therefore nobody was ever going to be sent.
    const fingerprint = whisperRecognitionFingerprint(signed);
    expect(await incidentsForFingerprint(fingerprint)).toHaveLength(0);
    expect(await prisma.incident.count({ where: { organisationId: fx.orgA } })).toBe(0);

    // The attempt is still AUDITED: an unbound principal on a silent duress
    // channel is exactly what oversight must be able to see.
    const audits = await prisma.whisperAuditLog.findMany({ where: { organisationId: fx.orgA, kind: 'WHISPER_RECOGNITION_REFUSED' } });
    expect(audits).toHaveLength(1);
    expect(audits[0]?.payload).toMatchObject({ conflict_code: 'DEVICE_CONTEXT_MISMATCH', recognition_fingerprint: fingerprint });
  }, 60_000);

  it('C12-01: a cross-organisation principal is refused identically whether or not the signal exists', async () => {
    const signal = await activeSignal({ authorised_user_ids: [fx.operativeA1] });
    const foreign = await principalFor(fx.operativeB1);
    expect(foreign.organisation_id).toBe(fx.orgB);
    expect(foreign.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(true);

    // (a) a REAL, ACTIVE signal in org A.
    const realSigned = signResult(unsignedResult(signal), keyA1.privateKey);
    const real = await whisper.recognise(deviceContext(), realSigned, foreign);

    // (b) a family id that exists NOWHERE. Same context, same foreign principal.
    const absentSigned = signResult(unsignedResult({ id: randomUUID(), version: 1 }), keyA1.privateKey);
    const absent = await whisper.recognise(deviceContext(), absentSigned, foreign);

    // INDISTINGUISHABLE. The refusal happens before any signal lookup, so the
    // caller cannot use a substituted principal as an oracle for which duress
    // signals a tenant has configured.
    expect(real).toMatchObject({ kind: 'refused', conflict_code: 'DEVICE_CONTEXT_MISMATCH', replayed: false });
    expect(absent).toMatchObject({ kind: 'refused', conflict_code: 'DEVICE_CONTEXT_MISMATCH', replayed: false });
    expect(real.kind === 'refused' && real.conflict_code).toBe(absent.kind === 'refused' && absent.conflict_code);
    // Identical in every respect except the fingerprint of what was signed.
    expect({ ...real, recognition_fingerprint: null }).toEqual({ ...absent, recognition_fingerprint: null });

    // Nothing was consumed or created in EITHER tenant.
    expect(await receiptsForIdentity(realSigned)).toHaveLength(0);
    expect(await receiptsForIdentity(absentSigned)).toHaveLength(0);
    expect(await prisma.whisperRecognitionReceipt.count({ where: { organisationId: { in: [fx.orgA, fx.orgB] } } })).toBe(0);
    expect(await prisma.incident.count({ where: { organisationId: { in: [fx.orgA, fx.orgB] } } })).toBe(0);
  }, 60_000);

  it('C12-01: the SAME signed result refused for a borrowed principal is accepted for its own actor holding invoke', async () => {
    const signal = await activeSignal({ authorised_user_ids: [fx.nonInvokerA1] });

    // ONE signed result, submitted twice. The only variable is the principal.
    const signed = signResult(unsignedResult(signal, { actor_user_id: fx.nonInvokerA1 }), keyA1.privateKey);
    const context = deviceContext({ actorUserId: fx.nonInvokerA1 });
    const fingerprint = whisperRecognitionFingerprint(signed);

    const borrowed = await whisper.recognise(context, signed, await principalFor(fx.operativeA1));
    expect(borrowed).toMatchObject({ kind: 'refused', conflict_code: 'DEVICE_CONTEXT_MISMATCH' });
    expect(await receiptsForIdentity(signed)).toHaveLength(0);

    // Now the actor holds invoke IN THEIR OWN RIGHT.
    await prisma.userRole.create({ data: { userId: fx.nonInvokerA1, role: 'field.operative', siteId: fx.siteA1 } });
    const ownPrincipal = await principalFor(fx.nonInvokerA1);
    expect(ownPrincipal.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE)).toBe(true);

    const accepted = await whisper.recognise(context, signed, ownPrincipal);

    // THE POSITIVE CONTROL. The identical bytes, the identical context, the
    // identical nonce — accepted. So the refusal above was caused by the
    // principal-to-context binding and by nothing incidental about this
    // statement, this signal, this device or this fixture. It also confirms
    // the earlier refusal really did leave the one-shot identity unspent.
    expect(accepted.kind).toBe('accepted');
    if (accepted.kind !== 'accepted') return;
    expect(accepted.replayed).toBe(false);
    expect(accepted.recognition_fingerprint).toBe(fingerprint);

    const receipts = await receiptsForIdentity(signed);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]?.status).toBe('APPLIED');
    expect(receipts[0]?.outcome).toBe('ACCEPTED');
    expect(await incidentsForFingerprint(fingerprint)).toHaveLength(1);
  }, 60_000);

  // ==========================================================================
  // C12-02 crash after the Incident commit, before the SILENT entry
  // ==========================================================================

  /**
   * The fault seam.
   *
   * `openWhisperSilentIncident` is two steps: `createFromWhisperRecognition`
   * commits the incident, its opening timeline entry and the outbox in ONE
   * transaction, and then `runProofA` establishes the response. The very first
   * thing `runProofA` does is `repository.ensureProofATasks`. Throwing there
   * lands the process EXACTLY in the window C12-02 is about: the incident is
   * durably committed and not one piece of the SILENT protocol exists.
   */
  function faultBetweenIncidentAndSilentEntry(): void {
    vi.spyOn(incidentsRepository, 'ensureProofATasks').mockRejectedValueOnce(
      new Error('simulated crash after incident commit, before response-task establishment'),
    );
  }

  it('C12-02: a crash between the incident commit and the SILENT entry recovers into a complete response', async () => {
    const signal = await activeSignal();
    const signed = signResult(unsignedResult(signal), keyA1.privateKey);
    const principal = await principalFor(fx.operativeA1);
    const fingerprint = whisperRecognitionFingerprint(signed);

    // The BEHAVIOURAL pin for C12-02, kept alongside the state assertions
    // because the two catch different regressions. State alone is not enough:
    // a reintroduced short-circuit would still leave a converged incident here
    // and could still look healthy if some other path had filled the tasks in.
    // What must never happen again is FINALISING WITHOUT RE-ENTERING, so the
    // call itself is what gets asserted. Call-through, so the real work runs.
    const enterSilent = vi.spyOn(incidents, 'openWhisperSilentIncident');

    faultBetweenIncidentAndSilentEntry();
    await expect(whisper.recognise(deviceContext(), signed, principal)).rejects.toBeInstanceOf(WhisperRecognitionUnresolvedError);
    expect(enterSilent).toHaveBeenCalledTimes(1);

    // ---- the intermediate state, stated honestly ------------------------
    const afterCrash = await incidentsForFingerprint(fingerprint);
    expect(afterCrash).toHaveLength(1);
    const crashedIncidentId = afterCrash[0]!.id;

    const midReceipt = await prisma.whisperRecognitionReceipt.findFirstOrThrow({ where: { organisationId: fx.orgA } });
    expect(midReceipt.status).toBe('UNKNOWN');
    expect(midReceipt.outcome).toBeNull();
    expect(midReceipt.finalizedAt).toBeNull();
    expect(['APPLIED', 'REFUSED']).not.toContain(midReceipt.status);

    // The response does not exist. Not partially — at all.
    expect(await prisma.responseTask.count({ where: { incidentId: crashedIncidentId } })).toBe(0);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: crashedIncidentId, kind: { startsWith: 'CONSTITUTION_' } } })).toBe(0);

    // ---- recovery: the IDENTICAL recognition, re-presented ---------------
    // The short-circuit condition is LIVE at this instant — the recovery probe
    // answers non-null — so if the superseded branch were back, the attempt
    // below would take it and `openWhisperSilentIncident` would never be
    // called a second time.
    expect(await incidents.findWhisperSilentIncident(fx.orgA, fingerprint)).not.toBeNull();

    const recovered = await whisper.recognise(deviceContext(), signed, principal);
    expect(recovered.kind).toBe('accepted');
    if (recovered.kind !== 'accepted') return;

    // ALWAYS called before finalizing accepted, recovered incident or not.
    expect(enterSilent).toHaveBeenCalledTimes(2);

    // Exactly ONE incident, and the SAME one — convergence, not a second open.
    const finalIncidents = await incidentsForFingerprint(fingerprint);
    expect(finalIncidents).toHaveLength(1);
    expect(finalIncidents[0]?.id).toBe(crashedIncidentId);
    expect(recovered.incident_id).toBe(crashedIncidentId);

    // The COMPLETE required response-task set now exists.
    const tasks = await prisma.responseTask.findMany({ where: { incidentId: crashedIncidentId } });
    expect(tasks).toHaveLength(REQUIRED_PROOF_A_TASKS.length);
    expect(tasks.map((task) => task.taskType).sort()).toEqual([...REQUIRED_PROOF_A_TASKS].sort());

    // The SILENT response is properly ESTABLISHED: a Constitution decision is
    // recorded against the dispatch task. This is the artefact whose absence
    // the crash produced, and it is the whole point of re-entering.
    const dispatch = tasks.find((task) => task.taskType === 'dispatch-field')!;
    const decisions = await prisma.incidentTimelineEntry.findMany({
      where: { incidentId: crashedIncidentId, kind: { startsWith: 'CONSTITUTION_' } },
    });
    expect(decisions).toHaveLength(1);
    expect((decisions[0]?.payload as { task_id?: string } | null)?.task_id).toBe(dispatch.id);
    expect((decisions[0]?.payload as { action?: string } | null)?.action).toBe('response.dispatch.silent');

    // ...and established WITHOUT inventing consent. W21-13: activating a signal
    // attested a tested configuration is safe to recognise; it is never an
    // approval of an operational response.
    expect(await prisma.responseTaskSilentApproval.count({ where: { taskId: dispatch.id } })).toBe(0);
    expect(decisions[0]?.kind).not.toBe('CONSTITUTION_ALLOW');

    // The dispatch has NOT been handed off. Recovery repairs the entry; it
    // does not send anybody.
    expect(dispatch.deliveryState).toBe('REQUESTED');
    expect(await prisma.responseDispatchHandoff.count({ where: { taskId: dispatch.id } })).toBe(0);

    // ONLY NOW is the receipt terminal-accepted.
    const finalReceipt = await prisma.whisperRecognitionReceipt.findFirstOrThrow({ where: { organisationId: fx.orgA } });
    expect(finalReceipt.status).toBe('APPLIED');
    expect(finalReceipt.outcome).toBe('ACCEPTED');
    expect(finalReceipt.incidentId).toBe(crashedIncidentId);
    expect(finalReceipt.attemptCount).toBe(2);
  }, 90_000);

  it('C12-02: an incident row is not proof the SILENT protocol was entered', async () => {
    const signal = await activeSignal();
    const signed = signResult(unsignedResult(signal), keyA1.privateKey);
    const principal = await principalFor(fx.operativeA1);
    const fingerprint = whisperRecognitionFingerprint(signed);

    faultBetweenIncidentAndSilentEntry();
    await expect(whisper.recognise(deviceContext(), signed, principal)).rejects.toBeInstanceOf(WhisperRecognitionUnresolvedError);

    // THE COUNTERFACTUAL, stated on the exact probe the superseded recovery
    // short-circuited on. `findWhisperSilentIncident` answers non-null here —
    // and the SUPERSEDED code read that as "the effect committed, we are done",
    // assigned `incidentId = recovered.incidentId`, skipped
    // `openWhisperSilentIncident` entirely and finalised the receipt ACCEPTED.
    const probe = await incidents.findWhisperSilentIncident(fx.orgA, fingerprint);
    expect(probe).not.toBeNull();
    expect(probe?.incidentId).toBe((await incidentsForFingerprint(fingerprint))[0]?.id);

    // ...and at the very same instant, NONE of the SILENT protocol exists.
    // So an ACCEPTED finalised on that probe's answer would have been a receipt
    // asserting a duress response that was never established: no tasks, no
    // Constitution decision, nothing for a commander to approve. Every exact
    // duplicate afterwards would have replayed that terminal receipt instead of
    // repairing the hole — a permanent, invisible failure to respond.
    //
    // The two facts are simply different, which is why the correction always
    // re-enters rather than assuming, and why the probe now decides only
    // WHETHER a stale-gated retry may still accept.
    const incidentId = probe!.incidentId;
    expect(await prisma.responseTask.count({ where: { incidentId } })).toBe(0);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId, kind: { startsWith: 'CONSTITUTION_' } } })).toBe(0);
    expect(await prisma.responseDispatchHandoff.count({ where: { task: { incidentId } } })).toBe(0);

    // The receipt correctly refuses to claim a verdict nobody reached.
    const receipt = await prisma.whisperRecognitionReceipt.findFirstOrThrow({ where: { organisationId: fx.orgA } });
    expect(receipt.status).toBe('UNKNOWN');
    expect(receipt.outcome).not.toBe('ACCEPTED');
    expect(await prisma.whisperAuditLog.count({ where: { organisationId: fx.orgA, kind: 'WHISPER_RECOGNITION_ACCEPTED' } })).toBe(0);
  }, 60_000);

  // ==========================================================================
  // C12-03 one ACTIVE version per (organisation, family), below the service
  // ==========================================================================

  it('C12-03: PostgreSQL refuses a second ACTIVE version of one family even when the service is bypassed', async () => {
    const signal = await activeSignal();
    const active = await prisma.whisperSignalVersion.findFirstOrThrow({
      where: { organisationId: fx.orgA, whisperSignalId: signal.id, status: 'ACTIVE' },
    });
    expect(active.signalVersion).toBe(1);

    // A straight INSERT of a second ACTIVE version of the same family.
    expect(
      await prismaErrorCode(
        prisma.whisperSignalVersion.create({
          data: directVersionRow({ whisperSignalId: signal.id, signalVersion: 2, siteId: fx.siteA1, status: 'ACTIVE' }),
        }),
      ),
    ).toBe('P2002');

    // ...and the UPDATE route to the same end. A DRAFT successor is entirely
    // legitimate; promoting it while the incumbent is still ACTIVE is not.
    const draft = await prisma.whisperSignalVersion.create({
      data: directVersionRow({ whisperSignalId: signal.id, signalVersion: 3, siteId: fx.siteA1, status: 'DRAFT' }),
    });
    expect(
      await prismaErrorCode(prisma.whisperSignalVersion.update({ where: { id: draft.id }, data: { status: 'ACTIVE' } })),
    ).toBe('P2002');

    // The tenant is left with exactly one answer to "which configuration is
    // live", which is the only state in which a duress signal is unambiguous.
    const stillActive = await prisma.whisperSignalVersion.findMany({
      where: { organisationId: fx.orgA, whisperSignalId: signal.id, status: 'ACTIVE' },
    });
    expect(stillActive).toHaveLength(1);
    expect(stillActive[0]?.id).toBe(active.id);
  }, 60_000);

  it('C12-03: the constraint is per (organisation, family), not global', async () => {
    const signal = await activeSignal();
    const sharedFamilyId = signal.id;

    // A DIFFERENT family in the SAME organisation keeps its own ACTIVE version.
    const otherFamily = await prisma.whisperSignalVersion.create({
      data: directVersionRow({ whisperSignalId: randomUUID(), signalVersion: 1, siteId: fx.siteA1, status: 'ACTIVE' }),
    });
    expect(otherFamily.status).toBe('ACTIVE');

    // ...and ANOTHER organisation may hold an ACTIVE version of the SAME family
    // identifier. Organisation-wide (site_id NULL), which is also the row shape
    // the C12-04 tenant FK exists to cover.
    const foreignTenant = await prisma.whisperSignalVersion.create({
      data: directVersionRow({ whisperSignalId: sharedFamilyId, signalVersion: 1, organisationId: fx.orgB, siteId: null, status: 'ACTIVE' }),
    });
    expect(foreignTenant.status).toBe('ACTIVE');
    expect(foreignTenant.organisationId).toBe(fx.orgB);

    // Three ACTIVE rows coexist. A GLOBAL unique index would have refused two
    // of them, so this is what makes the previous test's P2002 meaningful
    // rather than merely restrictive.
    const activeRows = await prisma.whisperSignalVersion.findMany({
      where: { organisationId: { in: [fx.orgA, fx.orgB] }, status: 'ACTIVE' },
    });
    expect(activeRows).toHaveLength(3);
    expect(activeRows.filter((row) => row.whisperSignalId === sharedFamilyId)).toHaveLength(2);
  }, 60_000);

  // ==========================================================================
  // C12-04 the direct organisation foreign key
  // ==========================================================================

  it('C12-04: an organisation-wide version for a nonexistent organisation is refused by the database', async () => {
    // site_id NULL. Under MATCH SIMPLE the composite (site_id, organisation_id)
    // FK is skipped ENTIRELY for this row, so before C12-04 nothing in the
    // database checked that this tenant existed at all — a silent-duress
    // configuration could be persisted against an organisation that is not
    // there.
    expect(
      await prismaErrorCode(
        prisma.whisperSignalVersion.create({
          data: directVersionRow({ organisationId: `${tag}_org_that_does_not_exist`, siteId: null }),
        }),
      ),
    ).toBe('P2003');

    expect(await prisma.whisperSignalVersion.count({ where: { organisationId: `${tag}_org_that_does_not_exist` } })).toBe(0);
  }, 30_000);

  it('C12-04: the same organisation-wide version for a real organisation is accepted', async () => {
    // The control: the refusal above is the FK doing its job, not this row
    // shape being unwritable.
    const row = await prisma.whisperSignalVersion.create({ data: directVersionRow({ organisationId: fx.orgA, siteId: null }) });
    expect(row.siteId).toBeNull();
    expect(row.organisationId).toBe(fx.orgA);
    expect(await prisma.whisperSignalVersion.count({ where: { id: row.id } })).toBe(1);
  }, 30_000);

  it('C12-04: a site belonging to another organisation is still refused by the composite site FK', async () => {
    // The direct tenant FK is SATISFIED here — org A exists — so only the
    // composite (site_id, organisation_id) -> sites FK can refuse this. C12-04
    // added tenant proof for NULL-site rows without weakening the pair check
    // that stops one tenant's configuration naming another tenant's site.
    expect(
      await prismaErrorCode(
        prisma.whisperSignalVersion.create({ data: directVersionRow({ organisationId: fx.orgA, siteId: fx.siteB1 }) }),
      ),
    ).toBe('P2003');

    expect(await prisma.whisperSignalVersion.count({ where: { organisationId: fx.orgA, siteId: fx.siteB1 } })).toBe(0);
  }, 30_000);
});
