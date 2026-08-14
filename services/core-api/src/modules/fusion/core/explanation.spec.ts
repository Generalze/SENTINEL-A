import { describe, expect, it } from 'vitest';
import { FUSION_RULE_VERSIONS } from '../fusion.constants';
import { buildConfidenceExplanation } from './explanation';
import { applySignal, createHypothesis } from './threatState';
import type { Signal, ThreatHypothesis } from './threatState';

const WINDOW = 'org-1/site-1/zone-1 @ 2026-08-14T10:00:00.000Z..2026-08-14T10:15:00.000Z';

function sig(overrides: Partial<Signal> & Pick<Signal, 'signalId' | 'sourceId'>): Signal {
  return {
    sourceType: 'camera',
    sourceTrust: 'trusted',
    kind: 'SUPPORTING',
    confidence: 0.6,
    ...overrides,
  };
}

function explain(hypothesis: ThreatHypothesis): string {
  return buildConfidenceExplanation(hypothesis, WINDOW, FUSION_RULE_VERSIONS);
}

describe('buildConfidenceExplanation', () => {
  it('names the state, the window and the rule versions', () => {
    const explanation = explain(createHypothesis('H1', 'MODERATE'));
    expect(explanation).toContain('Threat state 0 (NORMAL)');
    expect(explanation).toContain(WINDOW);
    for (const version of FUSION_RULE_VERSIONS) {
      expect(explanation).toContain(version);
    }
  });

  it('states explicitly that no contradicting evidence was observed', () => {
    // §11.4: an operator must be able to tell "we searched and found nothing"
    // apart from "nobody searched", so the zero case is never silent.
    const hypothesis = applySignal(createHypothesis('H1', 'HIGH'), sig({ signalId: 's1', sourceId: 'cam-1' }));
    const explanation = explain(hypothesis);
    expect(explanation).toContain('Contradicting evidence: none observed');
    expect(explanation).toMatch(/contradictions are searched for on every event/i);
  });

  it('describes contradicting evidence alongside supporting evidence once one arrives', () => {
    let hypothesis = createHypothesis('H1', 'HIGH');
    hypothesis = applySignal(hypothesis, sig({ signalId: 's1', sourceId: 'cam-1' }));
    hypothesis = applySignal(hypothesis, sig({ signalId: 's2', sourceId: 'cam-2' }));
    hypothesis = applySignal(
      hypothesis,
      sig({ signalId: 's3', sourceId: 'door-1', sourceType: 'access', kind: 'CONTRADICTING', confidence: 0.7 }),
    );

    const explanation = explain(hypothesis);
    expect(explanation).toContain('Supporting evidence: 2 signal(s) from 2 source(s) (cam-1, cam-2)');
    expect(explanation).toContain('Contradicting evidence: 1 signal(s) from 1 source(s) (door-1)');
    expect(explanation).toMatch(/retained permanently/i);
  });

  it('names all four separated values and never collapses them into one score', () => {
    const hypothesis = applySignal(createHypothesis('H1', 'HIGH'), sig({ signalId: 's1', sourceId: 'cam-1' }));
    const explanation = explain(hypothesis);
    expect(explanation).toContain('detection confidence');
    expect(explanation).toContain('threat probability');
    expect(explanation).toContain('potential impact HIGH');
    expect(explanation).toContain(`operational severity ${hypothesis.operationalSeverity}`);
  });

  it('explains the source-diversity cap when it is the binding constraint', () => {
    let hypothesis = createHypothesis('H1', 'HIGH');
    for (let i = 0; i < 4; i += 1) {
      hypothesis = applySignal(hypothesis, sig({ signalId: `s${i}`, sourceId: 'cam-solo', confidence: 0.9 }));
    }
    expect(hypothesis.state).toBe(2);
    expect(explain(hypothesis)).toMatch(/source-diversity cap holds this hypothesis at SUSPICIOUS/i);
  });

  it('explains the relaxed cap when a human-authorised field report is present', () => {
    const hypothesis = applySignal(
      createHypothesis('H1', 'HIGH'),
      sig({ signalId: 'sF', sourceId: 'field-1', sourceType: 'field', confidence: 0.7, humanAuthorised: true }),
    );
    expect(hypothesis.state).toBe(3);
    expect(explain(hypothesis)).toMatch(/relaxed here because a human-authorised field report is present/i);
  });

  it('explains the life-safety gate when state 5 is reached', () => {
    let hypothesis = createHypothesis('H1', 'HIGH');
    hypothesis = applySignal(hypothesis, sig({ signalId: 's1', sourceId: 'cam-1' }));
    hypothesis = applySignal(hypothesis, sig({ signalId: 's2', sourceId: 'cam-2' }));
    hypothesis = applySignal(
      hypothesis,
      sig({ signalId: 's3', sourceId: 'field-1', sourceType: 'field', confidence: 0.5, lifeSafety: true }),
    );
    expect(hypothesis.state).toBe(5);
    expect(explain(hypothesis)).toMatch(/life-safety gate/i);
  });

  it('reports quarantined signals as recorded but excluded', () => {
    const hypothesis = applySignal(
      createHypothesis('H1', 'HIGH'),
      sig({ signalId: 'sQ', sourceId: 'bad-1', sourceTrust: 'quarantined', confidence: 0.99 }),
    );
    expect(explain(hypothesis)).toMatch(/1 signal\(s\) from quarantined sources were recorded but excluded/i);
  });

  it('is deterministic — the same hypothesis always explains itself identically', () => {
    const hypothesis = applySignal(createHypothesis('H1', 'HIGH'), sig({ signalId: 's1', sourceId: 'cam-1' }));
    expect(explain(hypothesis)).toBe(explain(hypothesis));
  });
});
