import { describe, it, expect } from 'vitest';
import { createHypothesis, applySignal, deriveSeverity } from './threatState';
import type { Signal, ThreatHypothesis } from './threatState';

/**
 * Numeric scenarios below are computed by hand against the documented
 * formulas in threatState.ts:
 *
 *   weightedConfidence = confidence * trustWeight(sourceTrust)
 *     trusted -> x1.0, degraded -> x0.5, suspicious -> x0.25
 *
 *   aggregateSupport      = 1 - Π(1 - w_i) over SUPPORTING weighted confidences
 *   contradictionStrength = 1 - Π(1 - w_j) over CONTRADICTING weighted confidences
 *   threatProbability     = clamp01(aggregateSupport - contradictionStrength)
 *
 *   state thresholds (pre-cap): >=0.85 -> 4, >=0.65 -> 3, >=0.40 -> 2, >=0.20 -> 1, else 0
 */

function sig(overrides: Partial<Signal> & Pick<Signal, 'signalId' | 'sourceId' | 'sourceType' | 'sourceTrust' | 'kind' | 'confidence'>): Signal {
  return { ...overrides };
}

describe('createHypothesis', () => {
  it('starts at NORMAL (0) with zeroed metrics and empty logs', () => {
    const h = createHypothesis('H1', 'HIGH');
    expect(h.state).toBe(0);
    expect(h.detectionConfidence).toBe(0);
    expect(h.threatProbability).toBe(0);
    expect(h.signals).toEqual([]);
    expect(h.ignoredSignals).toEqual([]);
    expect(h.transitions).toEqual([]);
    expect(h.operationalSeverity).toBe(deriveSeverity(0, 'HIGH'));
  });
});

describe('escalation with diverse supporting sources', () => {
  it('reaches PROBABLE_THREAT (3) with two diverse trusted supporting sources, capped at SUSPICIOUS (2) after the first', () => {
    let h = createHypothesis('H1', 'HIGH');

    // Signal A alone: weighted 0.6 -> aggregateSupport 0.6 -> baseState 2 (SUSPICIOUS).
    // Diversity = 1 (<2) -> ceiling 2 -> state 2.
    h = applySignal(h, sig({ signalId: 'sigA', sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    expect(h.state).toBe(2);

    // Signal B (different source): aggregateSupport = 1-(0.4*0.4) = 0.84 -> baseState 3.
    // Diversity = 2 (>=2) -> ceiling 4 (uncapped) -> state 3.
    h = applySignal(h, sig({ signalId: 'sigB', sourceId: 'camB', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    expect(h.state).toBe(3);
    expect(h.threatProbability).toBeCloseTo(0.84, 5);
  });
});

describe('source diversity cap', () => {
  it('caps a single prolific source at SUSPICIOUS (2) no matter how many signals it sends', () => {
    let h = createHypothesis('H1', 'HIGH');
    for (let i = 0; i < 5; i++) {
      h = applySignal(
        h,
        sig({ signalId: `sig${i}`, sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.9 }),
      );
    }
    // aggregateSupport approaches 1 (baseState would be 4), but diversity stays 1
    // (single sourceId) so the state cap holds it at 2 throughout.
    expect(h.state).toBe(2);
    expect(h.threatProbability).toBeGreaterThan(0.85);
    // Only the very first signal caused a transition (0 -> 2); the rest are no-ops.
    expect(h.transitions).toHaveLength(1);
    expect(h.transitions[0]).toMatchObject({ from: 0, to: 2, signalId: 'sig0' });
  });
});

describe('humanAuthorised field-source exception to the diversity cap', () => {
  it('raises the cap to PROBABLE_THREAT (3) for a single-source humanAuthorised field signal below 0.9 confidence', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    // weighted = 0.7 -> aggregateSupport 0.7 -> baseState 3. Diversity = 1 (<2),
    // but humanAuthorised field signal qualifies -> ceiling 3 (confidence 0.7 < 0.9).
    const h = applySignal(
      h0,
      sig({
        signalId: 'sigF1',
        sourceId: 'field1',
        sourceType: 'field',
        sourceTrust: 'trusted',
        kind: 'SUPPORTING',
        confidence: 0.7,
        humanAuthorised: true,
      }),
    );
    expect(h.state).toBe(3);
  });

  it('raises the cap all the way to VERIFIED_THREAT (4) when that human signal itself has confidence >= 0.9', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    // weighted = 0.95 -> aggregateSupport 0.95 -> baseState 4. Diversity = 1 (<2),
    // humanAuthorised field signal with confidence 0.95 >= 0.9 -> ceiling 4.
    const h = applySignal(
      h0,
      sig({
        signalId: 'sigF2',
        sourceId: 'field1',
        sourceType: 'field',
        sourceTrust: 'trusted',
        kind: 'SUPPORTING',
        confidence: 0.95,
        humanAuthorised: true,
      }),
    );
    expect(h.state).toBe(4);
  });
});

describe('contradiction handling', () => {
  it('a strong contradiction (weighted >= 0.6) forces de-escalation and is retained permanently', () => {
    let h = createHypothesis('H1', 'HIGH');
    h = applySignal(h, sig({ signalId: 'sigA', sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    h = applySignal(h, sig({ signalId: 'sigB', sourceId: 'camB', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    expect(h.state).toBe(3); // established above

    // Contradiction: weighted 0.7 (trusted x 0.7) >= 0.6 threshold.
    const before = h.state;
    h = applySignal(h, sig({ signalId: 'sigC', sourceId: 'camC', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'CONTRADICTING', confidence: 0.7 }));

    expect(h.state).toBeLessThanOrEqual(before - 1);
    // Retained permanently even though it drove the state down.
    expect(h.signals.some((s) => s.signalId === 'sigC' && s.kind === 'CONTRADICTING')).toBe(true);
    const lastTransition = h.transitions[h.transitions.length - 1];
    expect(lastTransition.signalId).toBe('sigC');
    expect(lastTransition.reason).toMatch(/contradiction/i);
  });

  it('a weak contradiction (weighted < 0.6) does not force de-escalation, but is still retained', () => {
    let h = createHypothesis('H1', 'HIGH');
    // Three diverse strong supporters -> aggregateSupport = 1 - 0.2^3 = 0.992 -> state 4.
    h = applySignal(h, sig({ signalId: 's1', sourceId: 'src1', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.8 }));
    h = applySignal(h, sig({ signalId: 's2', sourceId: 'src2', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.8 }));
    h = applySignal(h, sig({ signalId: 's3', sourceId: 'src3', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.8 }));
    expect(h.state).toBe(4);
    const transitionsBefore = h.transitions.length;

    // Weak contradiction: weighted 0.05 (trusted x 0.05) < 0.6 threshold.
    // threatProbability = 0.992 - 0.05 = 0.942, still >= 0.85 -> state stays 4.
    h = applySignal(h, sig({ signalId: 's4', sourceId: 'src4', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'CONTRADICTING', confidence: 0.05 }));

    expect(h.state).toBe(4);
    expect(h.transitions).toHaveLength(transitionsBefore); // no new transition
    expect(h.signals.some((s) => s.signalId === 's4')).toBe(true); // still retained
  });
});

describe('quarantined signals', () => {
  it('are ignored entirely for state computation but recorded in ignoredSignals', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    const h = applySignal(
      h0,
      sig({ signalId: 'sigQ', sourceId: 'bad1', sourceType: 'cyber', sourceTrust: 'quarantined', kind: 'SUPPORTING', confidence: 0.99 }),
    );
    expect(h.state).toBe(0);
    expect(h.threatProbability).toBe(0);
    expect(h.detectionConfidence).toBe(0);
    expect(h.signals).toHaveLength(0);
    expect(h.transitions).toHaveLength(0);
    expect(h.ignoredSignals).toHaveLength(1);
    expect(h.ignoredSignals[0].signalId).toBe('sigQ');
  });
});

describe('CRITICAL_LIFE_SAFETY (state 5) gate', () => {
  it('rejects a lifeSafety signal when the resulting state would be below PROBABLE_THREAT (3)', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    // Single trusted supporting source, weighted 0.5 -> aggregateSupport 0.5 -> baseState 2.
    // Diversity 1 (<2), no human exception -> ceiling 2 -> state 2. 2 < 3, so even though
    // lifeSafety+trusted conditions are met, the gate must not fire.
    const h = applySignal(
      h0,
      sig({ signalId: 'sigLS1', sourceId: 'field1', sourceType: 'field', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.5, lifeSafety: true }),
    );
    expect(h.state).toBe(2);
    expect(h.state).not.toBe(5);
  });

  it('escalates to CRITICAL_LIFE_SAFETY (5) once state >= 3 and a trusted lifeSafety signal arrives', () => {
    let h = createHypothesis('H1', 'HIGH');
    h = applySignal(h, sig({ signalId: 'sigA', sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    h = applySignal(h, sig({ signalId: 'sigB', sourceId: 'camB', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    expect(h.state).toBe(3);

    h = applySignal(
      h,
      sig({ signalId: 'sigLS2', sourceId: 'field1', sourceType: 'field', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.5, lifeSafety: true }),
    );
    expect(h.state).toBe(5);
    expect(h.operationalSeverity).toBe('SEV1');
    const last = h.transitions[h.transitions.length - 1];
    expect(last).toMatchObject({ from: 3, to: 5, signalId: 'sigLS2' });
    expect(last.reason).toMatch(/life-safety/i);
  });
});

describe('transitions log', () => {
  it('records every state change, in order, with correct from/to/signalId', () => {
    let h = createHypothesis('H1', 'HIGH');
    h = applySignal(h, sig({ signalId: 'sigA', sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    h = applySignal(h, sig({ signalId: 'sigB', sourceId: 'camB', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    h = applySignal(
      h,
      sig({ signalId: 'sigC', sourceId: 'field1', sourceType: 'field', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.5, lifeSafety: true }),
    );

    expect(h.transitions.map((t) => [t.from, t.to, t.signalId])).toEqual([
      [0, 2, 'sigA'],
      [2, 3, 'sigB'],
      [3, 5, 'sigC'],
    ]);
    for (const t of h.transitions) {
      expect(t.reason.length).toBeGreaterThan(0);
    }
  });
});

describe('immutability', () => {
  it('never mutates the input hypothesis', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    const snapshotBefore = JSON.parse(JSON.stringify(h0)) as unknown;

    const h1 = applySignal(h0, sig({ signalId: 'sigA', sourceId: 'camA', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));

    expect(h1).not.toBe(h0);
    expect(JSON.parse(JSON.stringify(h0))).toEqual(snapshotBefore);
    expect(h0.state).toBe(0);
    expect(h0.signals).toHaveLength(0);
    expect(h0.transitions).toHaveLength(0);

    // Applying a second signal must not retroactively mutate h1 either.
    const h1SnapshotBefore = JSON.parse(JSON.stringify(h1)) as unknown;
    applySignal(h1, sig({ signalId: 'sigB', sourceId: 'camB', sourceType: 'camera', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 }));
    expect(JSON.parse(JSON.stringify(h1))).toEqual(h1SnapshotBefore);
  });
});

describe('trust weighting', () => {
  it('a suspicious-trust signal (x0.25) is weighted below the 0.5 diversity threshold even at max confidence', () => {
    const h0 = createHypothesis('H1', 'HIGH');
    // weighted = 1.0 * 0.25 = 0.25 -> aggregateSupport 0.25 -> baseState 1 (OBSERVE).
    const h = applySignal(
      h0,
      sig({ signalId: 'sigS', sourceId: 'susp1', sourceType: 'intel', sourceTrust: 'suspicious', kind: 'SUPPORTING', confidence: 1.0 }),
    );
    expect(h.threatProbability).toBeCloseTo(0.25, 5);
    expect(h.state).toBe(1);
  });

  it('two degraded-trust sources (x0.5) at confidence 1.0 exactly hit the diversity threshold and reach PROBABLE_THREAT', () => {
    let h = createHypothesis('H1', 'HIGH');
    // weighted = 0.5 each. After first: aggregateSupport 0.5 -> baseState 2, diversity 1 -> ceiling 2 -> state 2.
    h = applySignal(h, sig({ signalId: 'sigD1', sourceId: 'd1', sourceType: 'sensor', sourceTrust: 'degraded', kind: 'SUPPORTING', confidence: 1.0 }));
    expect(h.state).toBe(2);
    // After second: aggregateSupport = 1-(0.5*0.5) = 0.75 -> baseState 3, diversity 2 -> ceiling 4 -> state 3.
    h = applySignal(h, sig({ signalId: 'sigD2', sourceId: 'd2', sourceType: 'sensor', sourceTrust: 'degraded', kind: 'SUPPORTING', confidence: 1.0 }));
    expect(h.state).toBe(3);
    expect(h.threatProbability).toBeCloseTo(0.75, 5);
  });
});

describe('deriveSeverity mapping', () => {
  it('maps state/impact combinations per the documented score table', () => {
    expect(deriveSeverity(0, 'LOW')).toBe('SEV5');
    expect(deriveSeverity(0, 'EXTREME')).toBe('SEV4');
    expect(deriveSeverity(2, 'LOW')).toBe('SEV4');
    expect(deriveSeverity(3, 'MODERATE')).toBe('SEV3');
    expect(deriveSeverity(4, 'EXTREME')).toBe('SEV1');
    // State 5 always overrides to SEV1 regardless of potentialImpact.
    expect(deriveSeverity(5, 'LOW')).toBe('SEV1');
    expect(deriveSeverity(5, 'EXTREME')).toBe('SEV1');
  });

  it('confidence and severity are never conflated: two hypotheses with identical high confidence but different impact/state diverge in severity', () => {
    let low: ThreatHypothesis = createHypothesis('LOW-IMPACT', 'LOW');
    let high: ThreatHypothesis = createHypothesis('HIGH-IMPACT', 'EXTREME');
    const s = sig({ signalId: 'x', sourceId: 'src', sourceType: 'sensor', sourceTrust: 'trusted', kind: 'SUPPORTING', confidence: 0.6 });
    low = applySignal(low, s);
    high = applySignal(high, { ...s, signalId: 'y' });

    expect(low.threatProbability).toBe(high.threatProbability); // same detection/threat math
    expect(low.state).toBe(high.state); // same state
    expect(low.operationalSeverity).not.toBe(high.operationalSeverity); // but severity differs by impact
  });
});
