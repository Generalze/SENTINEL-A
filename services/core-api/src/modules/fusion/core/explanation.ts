/**
 * §65.3 `confidence_explanation` (WP-05 deliverables #3 and #6).
 *
 * The explanation is REGENERATED from the hypothesis's own signal history on
 * every update — it is never an operator-authored note and never appended to
 * incrementally. That means it can never drift from the numbers it explains,
 * and re-running Fusion over the same events reproduces it character for
 * character.
 *
 * It is written to be read by an operator under time pressure, in a fixed
 * order:
 *   1. Where the state ended up and what drove it.
 *   2. The supporting evidence, with source diversity spelled out.
 *   3. The contradicting evidence — ALWAYS a sentence of its own, including
 *      when there is none. §11.4 makes contradiction search first-class, so
 *      "no contradicting evidence has been observed" must be stated
 *      explicitly rather than inferred from an absent sentence: an operator
 *      must be able to tell "we looked and found nothing" apart from "nobody
 *      looked".
 *   4. The four separated values (§11.3), named, so the UI cannot collapse
 *      them into one score without contradicting the text beside it.
 *   5. The rule versions that produced the assessment.
 *
 * Pure: no clock, no I/O, no randomness.
 */

import { THREAT_STATE_NAMES, computeDiverseSupportingCount } from './threatState';
import type { ProcessedSignal, ThreatHypothesis } from './threatState';

/** Formats a [0,1] value as a 2-decimal string; keeps explanations stable to compare. */
function pct(value: number): string {
  return value.toFixed(2);
}

function distinctSources(signals: readonly ProcessedSignal[]): string[] {
  return [...new Set(signals.map((s) => s.sourceId))].sort();
}

function describeStateDriver(hypothesis: ThreatHypothesis, supporting: readonly ProcessedSignal[]): string {
  const diverse = computeDiverseSupportingCount(hypothesis.signals);

  if (hypothesis.state === 5) {
    return 'State 5 was reached through the life-safety gate, which requires a life-safety signal from a trusted or human-authorised source while the hypothesis already stood at PROBABLE_THREAT or above.';
  }
  if (diverse < 2) {
    const humanException = supporting.some((s) => s.humanAuthorised === true && s.sourceType === 'field');
    if (humanException) {
      return `Only ${diverse} independent supporting source(s) reached the trust-weighted 0.50 threshold, so the source-diversity cap applies; it is relaxed here because a human-authorised field report is present.`;
    }
    return `Only ${diverse} independent supporting source(s) reached the trust-weighted 0.50 threshold, so the source-diversity cap holds this hypothesis at SUSPICIOUS (2) or below no matter how strong the aggregate evidence becomes.`;
  }
  return `${diverse} independent supporting sources reached the trust-weighted 0.50 threshold, so the source-diversity cap does not constrain this hypothesis.`;
}

/**
 * Builds the stored explanation string.
 *
 * `correlationDescription` is the human-readable correlation key
 * (`describeCorrelationKey`), included so the explanation says which
 * space-time window the evidence was grouped over — grouping is half of why
 * a hypothesis says what it says.
 */
export function buildConfidenceExplanation(
  hypothesis: ThreatHypothesis,
  correlationDescription: string,
  ruleVersions: readonly string[],
): string {
  const supporting = hypothesis.signals.filter((s) => s.kind === 'SUPPORTING');
  const contradicting = hypothesis.signals.filter((s) => s.kind === 'CONTRADICTING');

  const sentences: string[] = [];

  sentences.push(
    `Threat state ${hypothesis.state} (${THREAT_STATE_NAMES[hypothesis.state]}) over ${correlationDescription}.`,
  );

  sentences.push(describeStateDriver(hypothesis, supporting));

  if (supporting.length === 0) {
    sentences.push('No supporting evidence has been observed in this window.');
  } else {
    const sources = distinctSources(supporting);
    sentences.push(
      `Supporting evidence: ${supporting.length} signal(s) from ${sources.length} source(s) (${sources.join(', ')}), combined by noisy-OR over trust-weighted confidences to an aggregate support of ${pct(aggregate(supporting))}.`,
    );
  }

  // Always emitted, including the zero case — see the module doc.
  if (contradicting.length === 0) {
    sentences.push(
      'Contradicting evidence: none observed. No signal so far weakens this hypothesis; contradictions are searched for on every event, not only when the hypothesis is challenged.',
    );
  } else {
    const sources = distinctSources(contradicting);
    sentences.push(
      `Contradicting evidence: ${contradicting.length} signal(s) from ${sources.length} source(s) (${sources.join(', ')}), combined to a contradiction strength of ${pct(aggregate(contradicting))}, which is subtracted from aggregate support. Contradictions are retained permanently and are never pruned from this record.`,
    );
  }

  if (hypothesis.ignoredSignals.length > 0) {
    sentences.push(
      `${hypothesis.ignoredSignals.length} signal(s) from quarantined sources were recorded but excluded from every computation.`,
    );
  }

  sentences.push(
    `Separated values (§11.3, never collapsed into one score): detection confidence ${pct(hypothesis.detectionConfidence)}; threat probability ${pct(hypothesis.threatProbability)}; potential impact ${hypothesis.potentialImpact}; operational severity ${hypothesis.operationalSeverity}.`,
  );

  sentences.push(`Produced by rule versions: ${ruleVersions.join(', ')}.`);

  return sentences.join(' ');
}

/** Noisy-OR aggregate of a signal subset, mirroring the core's combination. */
function aggregate(signals: readonly ProcessedSignal[]): number {
  const product = signals.reduce((acc, s) => acc * (1 - Math.min(1, Math.max(0, s.weightedConfidence))), 1);
  return Math.min(1, Math.max(0, 1 - product));
}
