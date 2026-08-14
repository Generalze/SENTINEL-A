/**
 * SENTINEL Fusion — threat-state machine (SENTINEL architecture §11).
 *
 * Pure, immutable TypeScript implementation. `applySignal` never mutates its
 * inputs: it always returns a brand-new `ThreatHypothesis` object, built by
 * spreading/copying the previous one.
 *
 * ---------------------------------------------------------------------------
 * State machine overview
 * ---------------------------------------------------------------------------
 * A ThreatHypothesis accumulates Signals over time. On every non-quarantined
 * signal we:
 *
 *   1. Weight the incoming signal's confidence by source trust.
 *   2. Permanently append the (weighted) signal to the hypothesis's signal
 *      history — this is what lets contradictions be retained forever and
 *      lets source diversity be computed from the full accumulated history
 *      rather than just the most recent signal.
 *   3. Recompute `threatProbability` and `detectionConfidence` from the full
 *      accumulated signal history (see formulas below).
 *   4. Derive a "base state" purely from `threatProbability`.
 *   5. Apply the source-diversity cap (rule 4), which can only ever *lower*
 *      the base state (except for the documented humanAuthorised/field
 *      exception, which raises the cap itself, not the state).
 *   6. Apply the strong-contradiction forced de-escalation (rule 6).
 *   7. Apply the CRITICAL_LIFE_SAFETY gate (rule 7), which is the only way
 *      to reach state 5.
 *   8. If the resulting state differs from the previous state, append a
 *      `Transition` record.
 *
 * Every step is a pure function of `(hypothesis, signal)`.
 */

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/**
 * 0 NORMAL, 1 OBSERVE, 2 SUSPICIOUS, 3 PROBABLE_THREAT, 4 VERIFIED_THREAT,
 * 5 CRITICAL_LIFE_SAFETY.
 */
export type ThreatState = 0 | 1 | 2 | 3 | 4 | 5;

export const THREAT_STATE_NAMES: Readonly<Record<ThreatState, string>> = {
  0: 'NORMAL',
  1: 'OBSERVE',
  2: 'SUSPICIOUS',
  3: 'PROBABLE_THREAT',
  4: 'VERIFIED_THREAT',
  5: 'CRITICAL_LIFE_SAFETY',
};

export type SourceType = 'camera' | 'access' | 'field' | 'sensor' | 'cyber' | 'intel';

export type SourceTrust = 'trusted' | 'degraded' | 'suspicious' | 'quarantined';

export type SignalKind = 'SUPPORTING' | 'CONTRADICTING';

/** Confidence that a detection is genuine (evidentiary quality), never impact/severity. */
export type PotentialImpact = 'LOW' | 'MODERATE' | 'HIGH' | 'EXTREME';

/** SEV1 = most severe / highest priority response, SEV5 = least severe. */
export type OperationalSeverity = 'SEV5' | 'SEV4' | 'SEV3' | 'SEV2' | 'SEV1';

export interface Signal {
  readonly signalId: string;
  readonly sourceId: string;
  readonly sourceType: SourceType;
  readonly sourceTrust: SourceTrust;
  readonly kind: SignalKind;
  /** Raw, un-weighted confidence reported by the source, in [0, 1]. */
  readonly confidence: number;
  readonly humanAuthorised?: boolean;
  readonly lifeSafety?: boolean;
}

/** A Signal that has been accepted (non-quarantined) and trust-weighted. */
export interface ProcessedSignal extends Signal {
  /** confidence * trustWeight(sourceTrust), clamped to [0, 1]. */
  readonly weightedConfidence: number;
}

export interface Transition {
  readonly from: ThreatState;
  readonly to: ThreatState;
  readonly signalId: string;
  readonly reason: string;
}

export interface ThreatHypothesis {
  readonly id: string;
  readonly state: ThreatState;

  /**
   * Confidence that genuine detections are occurring at all (evidentiary
   * strength of the accumulated sensor signals), regardless of whether they
   * support or contradict the threat hypothesis. Distinct from
   * threatProbability — see module docs.
   */
  readonly detectionConfidence: number;

  /** Probability the hypothesis actually represents a real threat. See formula below. */
  readonly threatProbability: number;

  readonly potentialImpact: PotentialImpact;
  readonly operationalSeverity: OperationalSeverity;

  /** Every accepted (non-quarantined) signal, in arrival order. Never mutated or pruned. */
  readonly signals: readonly ProcessedSignal[];

  /** Signals from quarantined sources: recorded, but never affect state computation. */
  readonly ignoredSignals: readonly Signal[];

  /** Append-only log of every state change. */
  readonly transitions: readonly Transition[];
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

export function createHypothesis(id: string, potentialImpact: PotentialImpact): ThreatHypothesis {
  const state: ThreatState = 0;
  return {
    id,
    state,
    detectionConfidence: 0,
    threatProbability: 0,
    potentialImpact,
    operationalSeverity: deriveSeverity(state, potentialImpact),
    signals: [],
    ignoredSignals: [],
    transitions: [],
  };
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

function clampState(n: number): ThreatState {
  const c = Math.min(5, Math.max(0, Math.round(n)));
  return c as ThreatState;
}

/** Rule 2: trust weighting on confidence. */
function trustWeight(trust: SourceTrust): number {
  switch (trust) {
    case 'trusted':
      return 1.0;
    case 'degraded':
      return 0.5;
    case 'suspicious':
      return 0.25;
    case 'quarantined':
      return 0;
    default: {
      const exhaustive: never = trust;
      return exhaustive;
    }
  }
}

/**
 * Combines a set of independent weighted confidences into a single [0, 1]
 * strength using the "noisy-OR" combination: combined = 1 - Π(1 - w_i).
 *
 * This is used both for aggregating supporting evidence and for aggregating
 * contradicting evidence. Properties that make it a good fit here:
 *   - A single very strong signal (w close to 1) alone can push the
 *     combination close to 1, matching "one solid piece of evidence should
 *     be enough to build a strong probability."
 *   - Multiple weak signals compound (diminishing returns), which rewards
 *     corroboration without letting an unbounded number of weak signals
 *     trivially saturate the result to exactly 1.
 *   - It is naturally bounded to [0, 1) for finite inputs, order-independent,
 *     and deterministic given a signal set.
 */
function combineNoisyOr(weights: readonly number[]): number {
  const productOfComplements = weights.reduce((acc, w) => acc * (1 - clamp01(w)), 1);
  return clamp01(1 - productOfComplements);
}

/**
 * Rule 5: threatProbability formula.
 *
 *   aggregateSupport       = noisy-OR combination of weighted confidences of
 *                             every accumulated SUPPORTING signal.
 *   contradictionStrength  = noisy-OR combination of weighted confidences of
 *                             every accumulated CONTRADICTING signal.
 *   threatProbability      = clamp01(aggregateSupport - contradictionStrength)
 *
 * i.e. contradicting evidence is combined amongst itself exactly like
 * supporting evidence, and then subtracted as a single penalty. This keeps
 * the formula simple, deterministic, and symmetric, while guaranteeing
 * contradictions can only ever push the probability down, never up.
 */
function computeThreatProbability(signals: readonly ProcessedSignal[]): number {
  const supportWeights = signals.filter((s) => s.kind === 'SUPPORTING').map((s) => s.weightedConfidence);
  const contradictWeights = signals.filter((s) => s.kind === 'CONTRADICTING').map((s) => s.weightedConfidence);
  const aggregateSupport = combineNoisyOr(supportWeights);
  const contradictionStrength = combineNoisyOr(contradictWeights);
  return clamp01(aggregateSupport - contradictionStrength);
}

/**
 * detectionConfidence: noisy-OR combination of *every* accepted signal's
 * weighted confidence, irrespective of SUPPORTING/CONTRADICTING kind. This
 * answers "how confident are we that something real is being sensed at
 * all," which is intentionally independent of whether the evidence points
 * toward or away from an actual threat.
 */
function computeDetectionConfidence(signals: readonly ProcessedSignal[]): number {
  return combineNoisyOr(signals.map((s) => s.weightedConfidence));
}

/** Rule 3: source diversity = distinct sourceId among SUPPORTING signals with weightedConfidence >= 0.5. */
function computeDiverseSupportingCount(signals: readonly ProcessedSignal[]): number {
  const ids = new Set(
    signals.filter((s) => s.kind === 'SUPPORTING' && s.weightedConfidence >= 0.5).map((s) => s.sourceId),
  );
  return ids.size;
}

/** Base state purely from the aggregate threat probability (states 0-4 only; state 5 is gated separately). */
function stateFromProbability(p: number): ThreatState {
  if (p >= 0.85) return 4;
  if (p >= 0.65) return 3;
  if (p >= 0.4) return 2;
  if (p >= 0.2) return 1;
  return 0;
}

/**
 * Rule 4: state cap driven by source diversity, with the humanAuthorised
 * field-source exception.
 *
 * - >= 2 diverse supporting sources: no cap from this rule (returns 4, the
 *   max reachable via the probability formula; state 5 is handled outside
 *   this function entirely).
 * - < 2 diverse supporting sources: capped at 2, UNLESS at least one
 *   accumulated SUPPORTING signal has humanAuthorised=true and
 *   sourceType='field', in which case the cap becomes 3 — or 4 if that
 *   human signal's own (raw, un-weighted) confidence is >= 0.9.
 *
 * (Assumption: the humanAuthorised/field exception only applies to
 * SUPPORTING signals — a contradicting human-authorised report should not
 * raise the ceiling on how *threatening* the state can be.)
 */
function computeDiversityCeiling(diverseSupportingCount: number, supportingSignals: readonly ProcessedSignal[]): ThreatState {
  if (diverseSupportingCount >= 2) return 4;
  const qualifyingHuman = supportingSignals.filter((s) => s.humanAuthorised === true && s.sourceType === 'field');
  if (qualifyingHuman.length === 0) return 2;
  const hasStrongHuman = qualifyingHuman.some((s) => s.confidence >= 0.9);
  return hasStrongHuman ? 4 : 3;
}

const IMPACT_SCORE: Readonly<Record<PotentialImpact, number>> = {
  LOW: 0,
  MODERATE: 1,
  HIGH: 2,
  EXTREME: 3,
};

/**
 * Severity mapping (documented design choice):
 *
 *   - State 5 (CRITICAL_LIFE_SAFETY) is ALWAYS SEV1, regardless of
 *     potentialImpact — an active, confirmed life-safety condition is by
 *     definition the highest operational priority.
 *   - Otherwise, score = state (0-4) + impactScore (LOW=0, MODERATE=1,
 *     HIGH=2, EXTREME=3), giving a range of 0-7, mapped as:
 *
 *       score 0-1  -> SEV5
 *       score 2-3  -> SEV4
 *       score 4-5  -> SEV3
 *       score 6    -> SEV2
 *       score 7    -> SEV1
 *
 *     This is monotonic non-decreasing in both state and impact: escalating
 *     either the confirmed threat state or the potential impact can only
 *     raise (or hold) operational severity, never lower it.
 */
export function deriveSeverity(state: ThreatState, potentialImpact: PotentialImpact): OperationalSeverity {
  if (state === 5) return 'SEV1';
  const score = state + IMPACT_SCORE[potentialImpact];
  if (score <= 1) return 'SEV5';
  if (score <= 3) return 'SEV4';
  if (score <= 5) return 'SEV3';
  if (score <= 6) return 'SEV2';
  return 'SEV1';
}

interface ReasonParams {
  readonly lifeSafetyTriggered: boolean;
  readonly contradictionForced: boolean;
  readonly contradictionWeighted: number | undefined;
  readonly diversityCapped: boolean;
  readonly diverseSupportingCount: number;
  readonly ceiling: ThreatState;
  readonly threatProbability: number;
}

function buildReason(p: ReasonParams): string {
  const parts: string[] = [];
  if (p.lifeSafetyTriggered) {
    parts.push(
      'life-safety gate triggered: lifeSafety signal from a trusted or human-authorised source with pre-gate state >= 3',
    );
  }
  if (p.contradictionForced) {
    parts.push(
      `strong contradiction (weighted confidence ${(p.contradictionWeighted ?? 0).toFixed(2)} >= 0.60) forced de-escalation by at least one level`,
    );
  }
  if (p.diversityCapped) {
    parts.push(
      `source-diversity cap applied: only ${p.diverseSupportingCount} diverse supporting source(s) (<2), ceiling=${p.ceiling}`,
    );
  }
  if (parts.length === 0) {
    parts.push(`recomputed from aggregate threat probability ${p.threatProbability.toFixed(3)}`);
  }
  return parts.join('; ');
}

// ---------------------------------------------------------------------------
// applySignal — the core, pure state transition function
// ---------------------------------------------------------------------------

export function applySignal(hypothesis: ThreatHypothesis, signal: Signal): ThreatHypothesis {
  // Rule 1: quarantined sources are ignored entirely for state computation,
  // but recorded permanently in ignoredSignals. Nothing else changes.
  if (signal.sourceTrust === 'quarantined') {
    return {
      ...hypothesis,
      ignoredSignals: [...hypothesis.ignoredSignals, signal],
    };
  }

  const weightedConfidence = clamp01(clamp01(signal.confidence) * trustWeight(signal.sourceTrust));
  const processedSignal: ProcessedSignal = { ...signal, weightedConfidence };

  // Rule 6 (part 1): every contradiction — regardless of strength — is
  // retained on the record permanently, alongside all supporting evidence.
  const signals: readonly ProcessedSignal[] = [...hypothesis.signals, processedSignal];

  const supportingSignals = signals.filter((s) => s.kind === 'SUPPORTING');

  const threatProbability = computeThreatProbability(signals);
  const detectionConfidence = computeDetectionConfidence(signals);
  const diverseSupportingCount = computeDiverseSupportingCount(signals);

  const baseState = stateFromProbability(threatProbability);
  const ceiling = computeDiversityCeiling(diverseSupportingCount, supportingSignals);
  const diversityCapped = ceiling < baseState;
  let state: ThreatState = clampState(Math.min(baseState, ceiling));

  // Rule 6 (part 2): a strong contradiction (weighted confidence >= 0.6)
  // forces the state down at least one level from the *previous* hypothesis
  // state, no matter what the probability-driven computation above yielded.
  const contradictionForced = signal.kind === 'CONTRADICTING' && weightedConfidence >= 0.6;
  if (contradictionForced) {
    const forcedCeiling = clampState(Math.max(0, hypothesis.state - 1));
    state = clampState(Math.min(state, forcedCeiling));
  }

  // Rule 7: CRITICAL_LIFE_SAFETY (state 5) gate. This is the ONLY path to
  // state 5 — it is never reached via the probability thresholds alone.
  // "current state" is evaluated as the state computed above (post cap,
  // post contradiction-forcing) for this same signal application, which —
  // because probability/diversity are recomputed from the full signal
  // history on every call — is equivalent to asking "is the hypothesis at
  // PROBABLE_THREAT or higher once this signal is accounted for."
  const lifeSafetyEligible =
    signal.lifeSafety === true && (signal.sourceTrust === 'trusted' || signal.humanAuthorised === true);
  const lifeSafetyTriggered = lifeSafetyEligible && state >= 3;
  if (lifeSafetyTriggered) {
    state = 5;
  }

  const operationalSeverity = deriveSeverity(state, hypothesis.potentialImpact);

  const stateChanged = state !== hypothesis.state;
  const transitions: readonly Transition[] = stateChanged
    ? [
        ...hypothesis.transitions,
        {
          from: hypothesis.state,
          to: state,
          signalId: signal.signalId,
          reason: buildReason({
            lifeSafetyTriggered,
            contradictionForced,
            contradictionWeighted: contradictionForced ? weightedConfidence : undefined,
            diversityCapped,
            diverseSupportingCount,
            ceiling,
            threatProbability,
          }),
        },
      ]
    : hypothesis.transitions;

  return {
    ...hypothesis,
    state,
    detectionConfidence,
    threatProbability,
    operationalSeverity,
    signals,
    transitions,
  };
}
