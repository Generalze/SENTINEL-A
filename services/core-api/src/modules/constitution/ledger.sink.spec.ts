/**
 * SENTINEL — Decision Ledger sink and record shape (WP-06 mandatory addition 4).
 *
 * The record is asserted against the `@sentinel/contracts` `DecisionLedgerEntrySchema` itself,
 * so WP-08 can bind a real sink knowing the DTO already validates.
 */

import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
// Runtime import via the package's public entry point: vitest resolves the `exports` map, so
// the spec validates against the real published schema rather than a copy of its shape.
import { DecisionLedgerEntrySchema } from '@sentinel/contracts';

import { CONSTITUTION_ENGINE_VERSION, evaluate, type ConstitutionRequest } from './constitution.engine';
import { policyContentSha256 } from './constitution.hash';
import { SENTINEL_BASELINE_POLICY } from './constitution.policy';
import { BUFFERING_LEDGER_SINK_CAPACITY, BufferingLedgerSink, LEDGER_SINK } from './ledger.sink';
import {
  CONSTITUTION_DECISION_TYPE,
  buildDecisionRecord,
  type DecisionRecord,
} from './decision-record';

const ORG = 'org-sentinel-1';
const POLICY_SHA = policyContentSha256(SENTINEL_BASELINE_POLICY);

function twoPersonRequest(approverIds: readonly string[] = []): ConstitutionRequest {
  return {
    action: 'tracking.exceptional.enable',
    actor: {
      userId: 'u-officer',
      roles: ['security.officer'],
      organisationId: ORG,
      clearance: 4,
      deviceTrust: 'TRUSTED',
      purpose: 'Warrant 2026-118 execution',
    },
    target: { organisationId: ORG, classification: 'RESTRICTED', classificationLevel: 3 },
    approvals: approverIds.map((userId) => ({
      userId,
      role: 'security.officer',
      at: '2026-08-14T10:00:00.000Z',
    })),
    approver_roles: Object.fromEntries(approverIds.map((id) => [id, ['security.officer']])),
  };
}

function record(request: ConstitutionRequest): DecisionRecord {
  return buildDecisionRecord({
    request,
    decision: evaluate(request, SENTINEL_BASELINE_POLICY),
    policyContentSha256: POLICY_SHA,
    entryId: 'entry-1',
    decidedAt: '2026-08-14T10:00:01.000Z',
    traceId: 'trace-1',
  });
}

describe('buildDecisionRecord', () => {
  it('produces a record that satisfies the contracts DecisionLedgerEntry schema', () => {
    for (const request of [twoPersonRequest(), twoPersonRequest(['u-1', 'u-2'])]) {
      const parsed = DecisionLedgerEntrySchema.safeParse(record(request));
      expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
    }
  });

  it('records the policy version, the content hash and the engine build', () => {
    const entry = record(twoPersonRequest(['u-1', 'u-2']));

    expect(entry.policy_version).toBe(SENTINEL_BASELINE_POLICY.version);
    expect(entry.rule_or_model_versions).toContain(CONSTITUTION_ENGINE_VERSION);
    expect(entry.rule_or_model_versions).toContain(`constitution-policy-sha256@${POLICY_SHA}`);
    expect(entry.inputs_snapshot['policy_content_sha256']).toBe(POLICY_SHA);
    expect(entry.decision_type).toBe(CONSTITUTION_DECISION_TYPE);
  });

  it('records the decision as the action taken, with the outcome still open', () => {
    expect(record(twoPersonRequest()).action_taken).toBe('REQUIRE_TWO_PERSON');
    expect(record(twoPersonRequest(['u-1', 'u-2'])).action_taken).toBe('ALLOW');
    expect(record(twoPersonRequest()).outcome).toBeNull();
    // Deterministic rules (§61): a confidence score would be a false signal.
    expect(record(twoPersonRequest()).confidence).toBeNull();
  });

  it('snapshots the inputs, including the resolved approver roles', () => {
    const entry = record(twoPersonRequest(['u-1', 'u-2']));
    const snapshot = entry.inputs_snapshot;

    expect(snapshot['action']).toBe('tracking.exceptional.enable');
    expect(snapshot['approver_roles']).toEqual({
      'u-1': ['security.officer'],
      'u-2': ['security.officer'],
    });
    expect(entry.approvals.map((a) => a.user_id)).toEqual(['u-1', 'u-2']);
  });

  it('splits the trace into evidence for and against, losing nothing', () => {
    const request = twoPersonRequest();
    const decision = evaluate(request, SENTINEL_BASELINE_POLICY);
    const entry = record(request);

    const traceLines = [...entry.evidence_for, ...entry.evidence_against].filter((line) =>
      line.startsWith('['),
    );
    expect(traceLines).toHaveLength(decision.trace.length);
    for (const check of decision.trace) {
      expect(traceLines.some((line) => line.includes(check.check))).toBe(true);
    }
    // Every reason is carried too.
    for (const reason of decision.reasons) {
      expect([...entry.evidence_for, ...entry.evidence_against]).toContain(reason);
    }
  });

  it('keeps a blank organisation representable rather than dropping the entry', () => {
    const request = twoPersonRequest();
    const blank: ConstitutionRequest = {
      ...request,
      actor: { ...request.actor, organisationId: '  ' },
    };
    const entry = buildDecisionRecord({
      request: blank,
      decision: evaluate(blank, SENTINEL_BASELINE_POLICY),
      policyContentSha256: POLICY_SHA,
      entryId: 'entry-1',
      decidedAt: '2026-08-14T10:00:01.000Z',
      traceId: '',
    });

    expect(DecisionLedgerEntrySchema.safeParse(entry).success).toBe(true);
    expect(entry.organisation_id).toBe('unattributed');
    expect(entry.trace_id).toBe('unattributed');
    // The real (blank) value is still visible in the snapshot.
    expect((entry.inputs_snapshot['actor'] as Record<string, unknown>)['organisation_id']).toBe('  ');
  });
});

describe('BufferingLedgerSink', () => {
  it('buffers appended entries and hands them over on drain', async () => {
    const sink = new BufferingLedgerSink();
    await sink.append(record(twoPersonRequest()));
    await sink.append(record(twoPersonRequest(['u-1', 'u-2'])));

    expect(sink.size).toBe(2);
    const drained = sink.drain();
    expect(drained.map((e) => e.action_taken)).toEqual(['REQUIRE_TWO_PERSON', 'ALLOW']);
    expect(sink.size).toBe(0);
    expect(sink.drain()).toEqual([]);
  });

  it('resolves through the Nest container under the LEDGER_SINK token', async () => {
    // Mirrors ConstitutionModule's binding exactly, so `useExisting` really does hand the same
    // instance to both tokens. (It cannot police the constructor's `@Optional()`: vitest
    // transpiles with esbuild, which emits no `design:paramtypes` for Nest to resolve.)
    const moduleRef = await Test.createTestingModule({
      providers: [BufferingLedgerSink, { provide: LEDGER_SINK, useExisting: BufferingLedgerSink }],
    }).compile();

    const concrete = moduleRef.get(BufferingLedgerSink);
    expect(moduleRef.get(LEDGER_SINK)).toBe(concrete);

    await concrete.append(record(twoPersonRequest()));
    expect(concrete.drain()).toHaveLength(1);
    expect(BUFFERING_LEDGER_SINK_CAPACITY).toBeGreaterThan(0);
  });

  it('drops the oldest entries when the buffer overflows, and counts the loss', async () => {
    const sink = new BufferingLedgerSink(2);
    const entry = record(twoPersonRequest());
    await sink.append({ ...entry, entry_id: 'a' });
    await sink.append({ ...entry, entry_id: 'b' });
    await sink.append({ ...entry, entry_id: 'c' });

    expect(sink.size).toBe(2);
    expect(sink.droppedCount).toBe(1);
    expect(sink.drain().map((e) => e.entry_id)).toEqual(['b', 'c']);
    // drain() does not erase the record of what was lost.
    expect(sink.droppedCount).toBe(1);
  });
});
