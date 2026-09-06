import { isConsistentDeviceNonceConsumption } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { buildConsumptionFact, readClaimedOfflineOperationId } from './device-offline-ingress.service';

/**
 * WP-29A — THE TWO INGRESS HELPERS THAT DECIDE WHAT THE EVALUATOR IS TOLD.
 *
 * Neither is glamorous and both are load-bearing, which is exactly the shape of
 * code that goes wrong quietly.
 *
 * `readClaimedOfflineOperationId` HAD A DEFECT AND THIS FILE EXISTS BECAUSE OF
 * IT. The first revision read `body.envelope` at the top level, while the
 * gateway's outer request schema is `.strict()` and nests every operation's
 * semantic content under `payload`. Every submission would have been refused —
 * not by this function, but three steps later, at the target-id binding, which
 * would have made the cause look like a client signing fault. It was caught by
 * the engineer building the client against the same contract from the other
 * side, not by any test, because there was no test.
 *
 * `buildConsumptionFact` is the C15-R1 surface: an EXACT_DUPLICATE naming no
 * stored outcome must never become a fact the evaluator can act on, because the
 * defect C15-R1 corrected was precisely such a fact falling through a
 * convergence branch and causing a SECOND application of a queued operation.
 */

describe('WP-29A readClaimedOfflineOperationId', () => {
  const id = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';

  it('reads the id from the nested payload the strict gateway schema requires', () => {
    expect(readClaimedOfflineOperationId({ proof: {}, payload: { envelope: { offline_operation_id: id }, payload: {} } })).toBe(id);
  });

  it('does NOT read a top-level envelope — the shape the strict schema refuses', () => {
    // The regression guard. A body shaped this way never reaches the ingress at
    // all, so answering an id for it would be answering about a request that
    // cannot exist.
    expect(readClaimedOfflineOperationId({ proof: {}, envelope: { offline_operation_id: id } })).toBeNull();
  });

  it('answers null for every shape it cannot read, rather than throwing', () => {
    // Refusal belongs to ONE boundary — the canonical envelope parse — so this
    // yields null and lets that boundary produce the single external answer.
    // Throwing here would turn a malformed body into a 500 where every other
    // malformed body gets the same 403, which is an oracle built out of error shapes.
    for (const body of [null, undefined, 'string', 42, [], {}, { payload: null }, { payload: {} }, { payload: { envelope: null } }, { payload: { envelope: {} } }, { payload: { envelope: { offline_operation_id: 7 } } }]) {
      expect(readClaimedOfflineOperationId(body)).toBeNull();
    }
  });
});

describe('WP-29A buildConsumptionFact', () => {
  const replayKey = '{"organisation_id":"org-a"}';
  const fingerprint = 'a'.repeat(64);
  const otherFingerprint = 'b'.repeat(64);

  it('reports FIRST_SEEN when the store holds nothing', () => {
    const fact = buildConsumptionFact(replayKey, fingerprint, null);
    expect(fact.outcome).toBe('FIRST_SEEN');
    expect(fact.stored_outcome_ref).toBeNull();
    expect(isConsistentDeviceNonceConsumption(fact)).toBe(true);
  });

  it('reports EXACT_DUPLICATE for the same bytes with a stored outcome', () => {
    const fact = buildConsumptionFact(replayKey, fingerprint, { statementFingerprint: fingerprint, storedOutcomeRef: 'op-1' });
    expect(fact.outcome).toBe('EXACT_DUPLICATE');
    expect(fact.stored_outcome_ref).toBe('op-1');
    expect(isConsistentDeviceNonceConsumption(fact)).toBe(true);
  });

  it('reports REUSED_WITH_CHANGED_SEMANTICS when the same slot carries different bytes', () => {
    const fact = buildConsumptionFact(replayKey, fingerprint, { statementFingerprint: otherFingerprint, storedOutcomeRef: 'op-1' });
    expect(fact.outcome).toBe('REUSED_WITH_CHANGED_SEMANTICS');
    // The fingerprint reported is the STORED one — what was actually seen under
    // this identity — so the evaluator's own misbinding check compares against
    // the truth rather than against the request that asked.
    expect(fact.statement_fingerprint).toBe(otherFingerprint);
    expect(isConsistentDeviceNonceConsumption(fact)).toBe(true);
  });

  it('refuses to call a duplicate with NO stored outcome an EXACT_DUPLICATE', () => {
    // C15-R1, and the whole reason this helper is written out rather than
    // coalesced. A duplicate that names no outcome is a fact nothing can act
    // on: reporting it as EXACT_DUPLICATE would send the evaluator down the
    // convergence branch with nothing to converge on, and the operation would
    // be applied a second time. It is reported as a conflict, which fails
    // closed.
    for (const ref of [null, '', '   ']) {
      const fact = buildConsumptionFact(replayKey, fingerprint, { statementFingerprint: fingerprint, storedOutcomeRef: ref });
      expect(fact.outcome, JSON.stringify(ref)).toBe('REUSED_WITH_CHANGED_SEMANTICS');
      expect(fact.stored_outcome_ref).toBeNull();
      expect(isConsistentDeviceNonceConsumption(fact)).toBe(true);
    }
  });

  it('always produces a fact the frozen contract accepts', () => {
    // The evaluator runs `isConsistentDeviceNonceConsumption` first and refuses
    // NONCE_CONSUMPTION_INCONSISTENT when it fails. A helper that could emit an
    // unparseable fact would turn every submission into that refusal.
    const cases = [
      null,
      { statementFingerprint: fingerprint, storedOutcomeRef: 'op-1' },
      { statementFingerprint: otherFingerprint, storedOutcomeRef: null },
    ];
    for (const stored of cases) {
      expect(isConsistentDeviceNonceConsumption(buildConsumptionFact(replayKey, fingerprint, stored))).toBe(true);
    }
  });
});
