import { describe, expect, it } from 'vitest';
import { BufferingLedgerSink } from '../constitution/ledger.sink';
import { computeContentHash } from './ledger.hash';
import type { InsertLedgerEntryData } from './ledger.repository';
import { LedgerService, LedgerValidationError } from './ledger.service';
import type { AppendLedgerEntryInput, LedgerEntry, LedgerListFilter } from './ledger.types';

/** In-memory stand-in for LedgerRepository, replicating just enough of its append-chain
 * behaviour (latest-entry lookup by insertion order) to unit-test LedgerService in isolation
 * from Postgres. Live-DB behaviour (the advisory lock, real concurrency) is covered separately
 * in ledger.integration.spec.ts. */
class FakeLedgerRepository {
  rows: LedgerEntry[] = [];
  appendCalls: InsertLedgerEntryData[] = [];

  async append(data: InsertLedgerEntryData): Promise<LedgerEntry> {
    this.appendCalls.push(data);
    const latest = [...this.rows].reverse().find((r) => r.organisation_id === data.organisationId);
    const entry: LedgerEntry = {
      schema_version: data.schemaVersion as 1,
      entry_id: data.entryId,
      organisation_id: data.organisationId,
      decided_at: data.decidedAt.toISOString(),
      decision_type: data.decisionType,
      inputs_snapshot: data.inputsSnapshot as Record<string, unknown>,
      rule_or_model_versions: data.ruleOrModelVersions,
      policy_version: data.policyVersion,
      evidence_for: data.evidenceFor,
      evidence_against: data.evidenceAgainst,
      confidence: data.confidence,
      approvals: data.approvals as unknown as LedgerEntry['approvals'],
      action_taken: data.actionTaken,
      outcome: data.outcome,
      trace_id: data.traceId,
      content_hash: data.contentHash,
      previous_hash: latest?.content_hash ?? null,
      supersedes_entry_id: data.supersedesEntryId,
      created_at: new Date().toISOString(),
    };
    this.rows.push(entry);
    return entry;
  }

  async findByEntryId(entryId: string): Promise<LedgerEntry | null> {
    return this.rows.find((r) => r.entry_id === entryId) ?? null;
  }

  async countByOrganisation(organisationId: string): Promise<number> {
    return this.rows.filter((r) => r.organisation_id === organisationId).length;
  }

  async list(filter: LedgerListFilter): Promise<{ items: LedgerEntry[]; nextCursor: string | null }> {
    const items = this.rows.filter((r) => r.organisation_id === filter.organisationId).slice(0, filter.limit);
    return { items, nextCursor: null };
  }

  async listChainOrder(organisationId: string): Promise<LedgerEntry[]> {
    return this.rows.filter((r) => r.organisation_id === organisationId);
  }
}

function makeService(): { service: LedgerService; repo: FakeLedgerRepository } {
  const repo = new FakeLedgerRepository();
  const service = new LedgerService(repo as never);
  return { service, repo };
}

function validInput(overrides: Partial<AppendLedgerEntryInput> = {}): AppendLedgerEntryInput {
  return {
    schema_version: 1,
    organisation_id: 'org-1',
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

describe('LedgerService#append', () => {
  it('stamps entry_id and decided_at when the caller omits them', async () => {
    const { service, repo } = makeService();
    await service.append(validInput());

    expect(repo.rows).toHaveLength(1);
    const row = repo.rows[0]!;
    expect(row.entry_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(() => new Date(row.decided_at).toISOString()).not.toThrow();
    expect(new Date(row.decided_at).toISOString()).toBe(row.decided_at);
  });

  it('preserves a caller-supplied entry_id and decided_at', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'fixed-id', decided_at: '2026-08-14T10:00:01.000Z' }));

    expect(repo.rows[0]!.entry_id).toBe('fixed-id');
    expect(repo.rows[0]!.decided_at).toBe('2026-08-14T10:00:01.000Z');
  });

  it('rejects an entry that fails contracts validation, without calling the repository', async () => {
    const { service, repo } = makeService();
    // policy_version is required (min length 1) by DecisionLedgerEntrySchema.
    const invalid = { ...validInput(), policy_version: '' };

    await expect(service.append(invalid)).rejects.toThrow(LedgerValidationError);
    expect(repo.rows).toHaveLength(0);
  });

  it('computes content_hash matching computeContentHash over the canonicalised, stamped entry', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'entry-1', decided_at: '2026-08-14T10:00:01.000Z' }));

    const row = repo.rows[0]!;
    const expectedHash = computeContentHash({
      schema_version: row.schema_version,
      entry_id: row.entry_id,
      organisation_id: row.organisation_id,
      decided_at: row.decided_at,
      decision_type: row.decision_type,
      inputs_snapshot: row.inputs_snapshot,
      rule_or_model_versions: row.rule_or_model_versions,
      policy_version: row.policy_version,
      evidence_for: row.evidence_for,
      evidence_against: row.evidence_against,
      confidence: row.confidence,
      approvals: row.approvals,
      action_taken: row.action_taken,
      outcome: row.outcome,
      trace_id: row.trace_id,
      supersedes_entry_id: row.supersedes_entry_id,
    });
    expect(row.content_hash).toBe(expectedHash);
  });

  it('normalises a non-canonical decided_at string before hashing (matches the Date#toISOString() form a DB round trip reproduces)', async () => {
    const { service, repo } = makeService();
    // No fractional seconds — a valid ISO datetime, but not the canonical 3-digit-ms form.
    await service.append(validInput({ entry_id: 'entry-1', decided_at: '2026-08-14T10:00:01Z' }));

    const row = repo.rows[0]!;
    expect(row.decided_at).toBe('2026-08-14T10:00:01.000Z');
    const hashedWithRawString = computeContentHash({
      schema_version: row.schema_version,
      entry_id: row.entry_id,
      organisation_id: row.organisation_id,
      decided_at: '2026-08-14T10:00:01Z',
      decision_type: row.decision_type,
      inputs_snapshot: row.inputs_snapshot,
      rule_or_model_versions: row.rule_or_model_versions,
      policy_version: row.policy_version,
      evidence_for: row.evidence_for,
      evidence_against: row.evidence_against,
      confidence: row.confidence,
      approvals: row.approvals,
      action_taken: row.action_taken,
      outcome: row.outcome,
      trace_id: row.trace_id,
      supersedes_entry_id: row.supersedes_entry_id,
    });
    // Hashing the raw (non-normalised) string would have produced a DIFFERENT hash than what
    // was actually stored — proving the service normalises before hashing.
    expect(row.content_hash).not.toBe(hashedWithRawString);
  });

  it('chains previous_hash to the organisation\'s prior entry, and leaves it null for the first', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));
    await service.append(validInput({ entry_id: 'e2' }));
    await service.append(validInput({ entry_id: 'e3' }));

    expect(repo.rows[0]!.previous_hash).toBeNull();
    expect(repo.rows[1]!.previous_hash).toBe(repo.rows[0]!.content_hash);
    expect(repo.rows[2]!.previous_hash).toBe(repo.rows[1]!.content_hash);
  });

  it('keeps separate organisations on separate chains', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'a1', organisation_id: 'org-a' }));
    await service.append(validInput({ entry_id: 'b1', organisation_id: 'org-b' }));
    await service.append(validInput({ entry_id: 'a2', organisation_id: 'org-a' }));

    const a2 = repo.rows.find((r) => r.entry_id === 'a2')!;
    const a1 = repo.rows.find((r) => r.entry_id === 'a1')!;
    const b1 = repo.rows.find((r) => r.entry_id === 'b1')!;
    expect(b1.previous_hash).toBeNull();
    expect(a2.previous_hash).toBe(a1.content_hash);
  });

  it('persists supersedes_entry_id and folds it into the hash', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'original' }));
    await service.append(validInput({ entry_id: 'correction', supersedes_entry_id: 'original', outcome: 'confirmed_threat' }));

    const correction = repo.rows.find((r) => r.entry_id === 'correction')!;
    expect(correction.supersedes_entry_id).toBe('original');

    const withoutSupersedes = computeContentHash({
      schema_version: correction.schema_version,
      entry_id: correction.entry_id,
      organisation_id: correction.organisation_id,
      decided_at: correction.decided_at,
      decision_type: correction.decision_type,
      inputs_snapshot: correction.inputs_snapshot,
      rule_or_model_versions: correction.rule_or_model_versions,
      policy_version: correction.policy_version,
      evidence_for: correction.evidence_for,
      evidence_against: correction.evidence_against,
      confidence: correction.confidence,
      approvals: correction.approvals,
      action_taken: correction.action_taken,
      outcome: correction.outcome,
      trace_id: correction.trace_id,
      supersedes_entry_id: null,
    });
    expect(correction.content_hash).not.toBe(withoutSupersedes);
  });
});

describe('LedgerService#query', () => {
  it('delegates to the repository and renames nextCursor to next_cursor', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));

    const result = await service.query({ organisationId: 'org-1', limit: 10 });
    expect(result.items).toHaveLength(1);
    expect(result.next_cursor).toBeNull();
    expect(repo.rows).toHaveLength(1);
  });
});

describe('LedgerService#verifyChain', () => {
  it('reports valid for an untampered chain, checking every entry', async () => {
    const { service } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));
    await service.append(validInput({ entry_id: 'e2' }));
    await service.append(validInput({ entry_id: 'e3' }));

    await expect(service.verifyChain('org-1')).resolves.toEqual({
      valid: true,
      organisation_id: 'org-1',
      entries_checked: 3,
    });
  });

  it('reports valid with zero entries checked for an organisation with no entries', async () => {
    const { service } = makeService();
    await expect(service.verifyChain('org-empty')).resolves.toEqual({
      valid: true,
      organisation_id: 'org-empty',
      entries_checked: 0,
    });
  });

  it('detects a row whose content was altered after being appended', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));
    await service.append(validInput({ entry_id: 'e2' }));

    const target = repo.rows.find((r) => r.entry_id === 'e2')!;
    // Simulate tampering: mutate a hashed field directly, bypassing the service entirely.
    (target as { action_taken: string }).action_taken = 'DENY';

    const result = await service.verifyChain('org-1');
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.broken_entry_id).toBe('e2');
      expect(result.reason).toContain('content_hash');
      expect(result.entries_checked).toBe(2);
    }
  });

  it('detects a broken chain link (previous_hash rewritten) even when content_hash itself is untouched', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));
    await service.append(validInput({ entry_id: 'e2' }));
    await service.append(validInput({ entry_id: 'e3' }));

    const target = repo.rows.find((r) => r.entry_id === 'e3')!;
    (target as { previous_hash: string | null }).previous_hash = 'forged-hash';

    const result = await service.verifyChain('org-1');
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.broken_entry_id).toBe('e3');
      expect(result.reason).toContain('previous_hash');
    }
  });

  it('stops at the first broken entry rather than reporting every subsequent one', async () => {
    const { service, repo } = makeService();
    await service.append(validInput({ entry_id: 'e1' }));
    await service.append(validInput({ entry_id: 'e2' }));
    await service.append(validInput({ entry_id: 'e3' }));

    const e1 = repo.rows.find((r) => r.entry_id === 'e1')!;
    (e1 as { action_taken: string }).action_taken = 'DENY';

    const result = await service.verifyChain('org-1');
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.broken_entry_id).toBe('e1');
      expect(result.entries_checked).toBe(1);
    }
  });
});

describe('LedgerService#drainBuffer', () => {
  it('is a no-op when nothing is buffered', async () => {
    const { service, repo } = makeService();
    await service.drainBuffer(new BufferingLedgerSink());
    expect(repo.rows).toHaveLength(0);
  });

  it('appends every buffered entry, in buffered order, and empties the buffer', async () => {
    const { service, repo } = makeService();
    const sink = new BufferingLedgerSink();
    await sink.append({ ...validInput({ entry_id: 'buffered-1' }), decided_at: '2026-08-14T10:00:01.000Z' } as never);
    await sink.append({ ...validInput({ entry_id: 'buffered-2' }), decided_at: '2026-08-14T10:00:02.000Z' } as never);
    expect(sink.size).toBe(2);

    await service.drainBuffer(sink);

    expect(repo.rows.map((r) => r.entry_id)).toEqual(['buffered-1', 'buffered-2']);
    expect(repo.rows[1]!.previous_hash).toBe(repo.rows[0]!.content_hash);
    expect(sink.size).toBe(0);
  });
});
