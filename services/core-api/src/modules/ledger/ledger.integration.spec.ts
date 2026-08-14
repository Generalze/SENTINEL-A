import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerRepository } from './ledger.repository';
import { LedgerService } from './ledger.service';
import { makeAppConfig, uniqueOrgId } from './ledger.test-support';
import type { AppendLedgerEntryInput } from './ledger.types';

function validInput(organisationId: string, overrides: Partial<AppendLedgerEntryInput> = {}): AppendLedgerEntryInput {
  return {
    schema_version: 1,
    organisation_id: organisationId,
    decision_type: 'constitution.evaluate',
    inputs_snapshot: { action: 'tracking.exceptional.enable' },
    rule_or_model_versions: ['constitution-engine@1'],
    policy_version: 'sentinel-constitution-1.0.0',
    evidence_for: ['allow.default'],
    evidence_against: [],
    confidence: null,
    approvals: [],
    action_taken: 'ALLOW',
    outcome: null,
    trace_id: 'trace-1',
    ...overrides,
  };
}

/**
 * Live-stack tests against the real Postgres instance (services/core-api/.env's DATABASE_URL).
 * Every entry_id used below is namespaced under its (already-unique) organisation id:
 * `entry_id` is a GLOBAL primary key on the table (not scoped per organisation), and this suite
 * shares the database with the rest of the tree's test runs, so a bare literal like "e1" would
 * risk a primary-key collision across test files/runs. `uniqueOrgId` already embeds a
 * timestamp + counter, so prefixing with it is sufficient.
 */
describe('Decision Ledger (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const repository = new LedgerRepository(prisma);
  const service = new LedgerService(repository);

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

  it('links previous_hash to the prior entry for the same organisation, and leaves the first null', async () => {
    const orgId = trackOrg('chain-basic');
    await service.append(validInput(orgId, { entry_id: `${orgId}-e1` }));
    await service.append(validInput(orgId, { entry_id: `${orgId}-e2` }));

    const chain = await repository.listChainOrder(orgId);
    expect(chain).toHaveLength(2);
    expect(chain[0]!.previous_hash).toBeNull();
    expect(chain[1]!.previous_hash).toBe(chain[0]!.content_hash);

    await expect(service.verifyChain(orgId)).resolves.toEqual({ valid: true, organisation_id: orgId, entries_checked: 2 });
  });

  /** Acceptance criterion 5: Promise.all of N concurrent appends, then verifyChain passes and
   * there is exactly one head. */
  it('concurrent appends for the same organisation never fork the chain', async () => {
    const orgId = trackOrg('concurrent');
    const total = 20;

    await Promise.all(
      Array.from({ length: total }, (_, i) =>
        service.append(validInput(orgId, { entry_id: `${orgId}-c${i}`, trace_id: `trace-${i}` })),
      ),
    );

    const chain = await repository.listChainOrder(orgId);
    expect(chain).toHaveLength(total);

    const result = await service.verifyChain(orgId);
    expect(result).toEqual({ valid: true, organisation_id: orgId, entries_checked: total });

    // "Exactly one head": exactly one entry's content_hash is never referenced as another
    // entry's previous_hash. A forked chain would produce zero or more than one.
    const referenced = new Set(chain.map((e) => e.previous_hash).filter((h): h is string => h !== null));
    const heads = chain.filter((e) => !referenced.has(e.content_hash));
    expect(heads).toHaveLength(1);

    // No duplicate previous_hash values either — two entries both claiming the same
    // predecessor is exactly what a forked chain looks like, even if it happened not to break
    // the seq-ordered walk above.
    const previousHashes = chain.map((e) => e.previous_hash).filter((h): h is string => h !== null);
    expect(new Set(previousHashes).size).toBe(previousHashes.length);
  }, 30_000);

  /** Acceptance criterion 2: corrupt a row via raw SQL, verifyChain catches it. */
  it('verifyChain detects a row corrupted via raw SQL after it was appended', async () => {
    const orgId = trackOrg('tamper');
    const targetId = `${orgId}-e2`;
    await service.append(validInput(orgId, { entry_id: `${orgId}-e1` }));
    await service.append(validInput(orgId, { entry_id: targetId }));
    await service.append(validInput(orgId, { entry_id: `${orgId}-e3` }));

    // Simulate tampering: rewrite a hashed field directly at the SQL layer, bypassing the
    // service (and therefore the append-only surface) entirely.
    await prisma.$executeRaw`UPDATE decision_ledger_entries SET action_taken = 'DENY' WHERE entry_id = ${targetId}`;

    const result = await service.verifyChain(orgId);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.broken_entry_id).toBe(targetId);
      expect(result.reason).toContain('content_hash');
    }
  });

  it('verifyChain detects a forged previous_hash even when the row\'s own content is untouched', async () => {
    const orgId = trackOrg('tamper-link');
    const targetId = `${orgId}-e2`;
    await service.append(validInput(orgId, { entry_id: `${orgId}-e1` }));
    await service.append(validInput(orgId, { entry_id: targetId }));

    await prisma.$executeRaw`UPDATE decision_ledger_entries SET previous_hash = 'forged' WHERE entry_id = ${targetId}`;

    const result = await service.verifyChain(orgId);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.broken_entry_id).toBe(targetId);
      expect(result.reason).toContain('previous_hash');
    }
  });

  /** Deliverable #4: tenant-scoped, filterable, cursor-paginated read against the real DB. */
  it('filters by decision_type and paginates newest-first with a cursor, tenant-scoped', async () => {
    const orgId = trackOrg('list');
    const otherOrgId = trackOrg('list-other');
    const baseTime = Date.now() - 60_000;

    const entryIds: string[] = [];
    const seeds = [
      { type: 'constitution.evaluate', offsetMs: 0 },
      { type: 'constitution.evaluate', offsetMs: 1000 },
      { type: 'other.type', offsetMs: 2000 },
      { type: 'constitution.evaluate', offsetMs: 3000 },
    ];
    for (const [i, seed] of seeds.entries()) {
      const entryId = `${orgId}-list-${i}`;
      entryIds.push(entryId);
      await service.append(
        validInput(orgId, {
          entry_id: entryId,
          decision_type: seed.type,
          decided_at: new Date(baseTime + seed.offsetMs).toISOString(),
        }),
      );
    }
    await service.append(validInput(otherOrgId, { entry_id: `${otherOrgId}-entry` }));

    const all = await service.query({ organisationId: orgId, limit: 50 });
    expect(all.items.map((e) => e.entry_id)).toEqual([...entryIds].reverse());
    expect(all.items.every((e) => e.organisation_id === orgId)).toBe(true);

    const filtered = await service.query({ organisationId: orgId, decisionType: 'constitution.evaluate', limit: 50 });
    expect(filtered.items).toHaveLength(3);
    expect(filtered.items.every((e) => e.decision_type === 'constitution.evaluate')).toBe(true);

    const seen: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const result = await service.query({ organisationId: orgId, limit: 2, cursor });
      seen.push(...result.items.map((e) => e.entry_id));
      if (!result.next_cursor) break;
      cursor = result.next_cursor;
    }
    expect(seen).toEqual([...entryIds].reverse());
  });
});
