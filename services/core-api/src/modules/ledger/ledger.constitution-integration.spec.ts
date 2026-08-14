import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { PrismaService } from '../../prisma/prisma.service';
import {
  BufferingLedgerSink,
  CLASSIFICATION_LEVELS,
  ConstitutionPolicyRepository,
  ConstitutionService,
  type Actor,
  type ConstitutionRequest,
} from '../constitution';
import { LedgerRepository } from './ledger.repository';
import { LedgerService } from './ledger.service';
import { makeAppConfig, uniqueOrgId } from './ledger.test-support';

function actor(organisationId: string): Actor {
  return {
    userId: 'u-officer',
    roles: ['security.officer'],
    organisationId,
    clearance: 4,
    deviceTrust: 'TRUSTED',
    purpose: 'Warrant 2026-118 execution',
  };
}

function request(organisationId: string): ConstitutionRequest {
  return {
    action: 'tracking.exceptional.enable',
    actor: actor(organisationId),
    target: { organisationId, classification: 'RESTRICTED', classificationLevel: CLASSIFICATION_LEVELS.RESTRICTED },
    approvals: [],
    approver_roles: {},
  };
}

/**
 * Acceptance criterion 3: "Constitution evaluations from WP-06 land as entries automatically —
 * count test." Wires the REAL `ConstitutionService` against the REAL `LedgerService` (exactly
 * the pairing `constitution.module.ts`'s `LEDGER_SINK` factory produces in the running app),
 * both against the live database, and proves every `evaluate()` call lands exactly one row.
 */
describe('Constitution evaluations auto-land in the Decision Ledger (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const ledgerRepository = new LedgerRepository(prisma);
  const ledgerService = new LedgerService(ledgerRepository);
  const constitutionRepository = new ConstitutionPolicyRepository(prisma);

  const createdOrgIds: string[] = [];
  function trackOrg(label: string): string {
    const id = uniqueOrgId(label);
    createdOrgIds.push(id);
    return id;
  }

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterEach(async () => {
    if (createdOrgIds.length > 0) {
      await prisma.decisionLedgerEntry.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      createdOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
  });

  it('every ConstitutionService.evaluate() call lands exactly one Decision Ledger row', async () => {
    const orgId = trackOrg('auto-land');
    const constitutionService = new ConstitutionService(constitutionRepository, ledgerService);
    await constitutionService.onModuleInit();

    const evaluationCount = 5;
    for (let i = 0; i < evaluationCount; i += 1) {
      await constitutionService.evaluate(request(orgId));
    }

    const stored = await ledgerService.query({ organisationId: orgId, limit: 50 });
    expect(stored.items).toHaveLength(evaluationCount);
    expect(stored.items.every((entry) => entry.decision_type === 'constitution.evaluate')).toBe(true);

    await expect(ledgerService.verifyChain(orgId)).resolves.toEqual({
      valid: true,
      organisation_id: orgId,
      entries_checked: evaluationCount,
    });
  });

  it('drains a BufferingLedgerSink into the durable store, exactly mirroring constitution.module.ts\'s LEDGER_SINK factory', async () => {
    const orgId = trackOrg('drain');

    // Phase 1: ConstitutionService wired against the WP-06 stub — the pre-WP-08 situation.
    const buffer = new BufferingLedgerSink();
    const bufferedConstitution = new ConstitutionService(constitutionRepository, buffer);
    await bufferedConstitution.onModuleInit();
    await bufferedConstitution.evaluate(request(orgId));
    await bufferedConstitution.evaluate(request(orgId));
    expect(buffer.size).toBe(2);

    // Phase 2: the WP-08 binding takes effect — drain, exactly as the LEDGER_SINK factory does.
    await ledgerService.drainBuffer(buffer);
    expect(buffer.size).toBe(0);

    // Phase 3: further evaluations go straight to the durable sink.
    const liveConstitution = new ConstitutionService(constitutionRepository, ledgerService);
    await liveConstitution.onModuleInit();
    await liveConstitution.evaluate(request(orgId));

    const stored = await ledgerService.query({ organisationId: orgId, limit: 50 });
    expect(stored.items).toHaveLength(3);
    await expect(ledgerService.verifyChain(orgId)).resolves.toEqual({
      valid: true,
      organisation_id: orgId,
      entries_checked: 3,
    });
  });
});
