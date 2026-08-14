/**
 * Fusion v1 signal mapping — NormalisedEvent -> Signal (WP-05 deliverable #2).
 *
 * ARCHITECTURE §65.1: Fusion v1 is transparent RULES, not a learned model.
 * Everything that decides whether an event supports or contradicts a threat
 * hypothesis lives in the `EVENT_TYPE_RULES` table below. The table is data:
 * `mapEventToSignal` contains no event-type-specific branching whatsoever, so
 * there is exactly one place to read (and to change) to know how Fusion
 * interprets any event type.
 *
 * WHAT DERIVES FROM THE TABLE AND WHAT DOES NOT
 * ---------------------------------------------
 * From the table ONLY:
 *   - `kind` (SUPPORTING / CONTRADICTING)
 *   - whether the mapping is conditional at all, and on which metadata flag
 *   - whether `humanAuthorised` may be set, and from which metadata flag
 *   - the potential-impact family the signal contributes (M1 placeholder rule)
 * From the event itself (never from the table):
 *   - `signalId`   = event.event_id       (one signal per event, one-for-one)
 *   - `sourceId`   = event.source_id
 *   - `sourceType` = event.source_type    (already a contract-constrained enum)
 *   - `sourceTrust`= event.source_trust   (trust weighting is the core's job)
 *   - `confidence` = event.confidence     (raw; the core applies trust weight)
 *   - `lifeSafety` = metadata.life_safety === true (see LIFE-SAFETY below)
 *
 * UNKNOWN EVENT TYPES
 * -------------------
 * An event type with no rule produces NO signal — it can neither raise nor
 * lower a threat state. It is still recorded (`fusion_applied_events` with
 * `ignore_reason = 'no_rule'`) so that "Fusion saw this and deliberately did
 * nothing with it" is auditable, and so an unmapped event type shows up as a
 * gap in the rule table rather than as silence. Failing closed this way is
 * deliberate: guessing a mapping for an unrecognised type would put
 * un-reviewed logic into a threat assessment.
 *
 * LIFE-SAFETY
 * -----------
 * `metadata.life_safety === true` sets the signal's life-safety flag for ANY
 * mapped event type, not just some of them. It is a property of the observed
 * situation ("someone is being hurt right now"), not of the sensor family, so
 * it is read uniformly rather than being per-rule. It only ever *arms* the
 * core's rule-7 gate; the core still requires state >= 3 and a trusted or
 * human-authorised source before state 5 can be reached.
 *
 * VERSIONING
 * ----------
 * Any change to this table (adding a type, changing a kind, changing a
 * condition, changing an impact family) requires bumping
 * FUSION_RULES_VERSION in fusion.constants.ts. That version is stamped onto
 * every hypothesis and every transition (§65.3 `rule_or_model_versions`), so
 * a stored assessment always says which table produced it.
 */

import type { NormalisedEvent } from '@sentinel/contracts';
import { FUSION_RULES_VERSION } from '../fusion.constants';
import type { PotentialImpact, Signal, SignalKind } from './threatState';

// ---------------------------------------------------------------------------
// Impact families (M1 placeholder rule — see derivePotentialImpact)
// ---------------------------------------------------------------------------

/**
 * The evidence family a SUPPORTING signal belongs to. Used only by the M1
 * placeholder potential-impact rule; it never influences threat state.
 */
export type ImpactFamily = 'PRESENCE' | 'MOTION' | 'BEHAVIOUR' | 'ACCESS' | 'THREAT_LIKE' | 'VIOLENCE' | 'FIELD';

/**
 * M1 PLACEHOLDER RULE (versioned with FUSION_RULES_VERSION).
 *
 * §11.3 requires potential impact to be a value in its own right, kept
 * separate from confidence and severity — but the architecture does not yet
 * specify how a rules-only Fusion should derive it, and deriving it properly
 * needs asset criticality and site context that Milestone 1 does not model.
 *
 * So M1 uses a deliberately crude, constant, fully transparent rule:
 *   HIGH      if any SUPPORTING signal so far belongs to an access,
 *             threat-like-object, violence or field-report family;
 *   MODERATE  otherwise.
 *
 * Properties this rule is chosen to have:
 *   - It reads only accumulated SUPPORTING families, so contradicting
 *     evidence can never raise potential impact.
 *   - Because the core never prunes signals, the family set only ever grows,
 *     which makes the rule monotonic: potential impact can rise from MODERATE
 *     to HIGH but never silently fall. That matters because the core's
 *     severity mapping is monotonic in impact — a falling impact would drop
 *     operational severity for a reason unrelated to the threat state.
 *   - LOW and EXTREME are never produced in M1. Emitting them would imply a
 *     judgement about asset value / consequence that this milestone has no
 *     input data for; claiming that precision would be worse than admitting
 *     the two-value placeholder.
 */
export const HIGH_IMPACT_FAMILIES: readonly ImpactFamily[] = ['ACCESS', 'THREAT_LIKE', 'VIOLENCE', 'FIELD'];

export function derivePotentialImpact(supportingFamilies: readonly string[]): PotentialImpact {
  return supportingFamilies.some((family) => HIGH_IMPACT_FAMILIES.includes(family as ImpactFamily))
    ? 'HIGH'
    : 'MODERATE';
}

// ---------------------------------------------------------------------------
// The rule table
// ---------------------------------------------------------------------------

export interface EventTypeRule {
  /** Exact `event_type` this rule matches. Matching is exact, never prefix or regex. */
  readonly eventType: string;
  /** SUPPORTING raises the hypothesis; CONTRADICTING is subtracted by the core (§11.4). */
  readonly kind: SignalKind;
  /** Family contributed to the M1 potential-impact rule when this signal is SUPPORTING. */
  readonly impactFamily: ImpactFamily;
  /**
   * When present, the rule only fires if `metadata[requiresMetadataFlag]` is
   * strictly `true`. When the flag is absent or any other value the event
   * produces NO signal and is recorded with `ignore_reason = 'condition_not_met'`.
   * v1 supports exactly one condition shape — a boolean-true metadata flag —
   * on purpose: an expression language here would be logic hiding in data.
   */
  readonly requiresMetadataFlag?: string;
  /**
   * When present, the signal's `humanAuthorised` flag is taken from
   * `metadata[humanAuthorisedFromMetadataFlag] === true`. Rules that do not
   * declare this can NEVER produce a human-authorised signal, whatever their
   * metadata contains — the core's diversity-cap exception and life-safety
   * gate both key off this flag, so it must not be settable by an arbitrary
   * source claiming human authorisation.
   */
  readonly humanAuthorisedFromMetadataFlag?: string;
  /** Why this mapping is correct. Kept in the data so review reads as one unit. */
  readonly rationale: string;
}

/**
 * THE TABLE. Ordered for reading (supporting families first, then the single
 * contradicting rule); lookup is by exact `eventType` via RULES_BY_EVENT_TYPE,
 * so order carries no behaviour.
 *
 * Duplicate `eventType` entries are a programming error and are rejected at
 * module load (see RULES_BY_EVENT_TYPE below).
 */
export const EVENT_TYPE_RULES: readonly EventTypeRule[] = [
  {
    eventType: 'person_detected',
    kind: 'SUPPORTING',
    impactFamily: 'PRESENCE',
    rationale:
      'A person present in a monitored space is the weakest form of corroboration: it is consistent with a developing situation but equally consistent with routine activity. It supports the hypothesis; the source-diversity cap and the confidence weighting are what stop it from escalating on its own.',
  },
  {
    eventType: 'loitering_detected',
    kind: 'SUPPORTING',
    impactFamily: 'BEHAVIOUR',
    rationale:
      'Dwelling well beyond normal transit time is a behavioural anomaly, a stronger indicator than bare presence, and a classic pre-incident pattern. Still only supporting evidence — never a determination.',
  },
  {
    eventType: 'motion_detected',
    kind: 'SUPPORTING',
    impactFamily: 'MOTION',
    rationale:
      'Raw motion is the weakest sensor observation in the vocabulary but it is genuine evidence that something is happening in the zone, and it contributes source diversity when it corroborates an independent camera or access source.',
  },
  {
    eventType: 'access_denied_attempt',
    kind: 'SUPPORTING',
    impactFamily: 'ACCESS',
    rationale:
      'A refused credential at a controlled door is an attempt to enter a space the holder is not entitled to enter. It is direct evidence of intent against an access boundary, which is why it carries the ACCESS impact family.',
  },
  {
    eventType: 'zone.restricted.entry',
    kind: 'SUPPORTING',
    impactFamily: 'ACCESS',
    rationale:
      'Named explicitly by the directive as SUPPORTING. JUDGEMENT CALL, flagged for lead review: it is filed under the ACCESS impact family because a restricted zone is an access-controlled space and entering one is an access-boundary violation of the same nature as a denied credential. If the lead intends restricted-zone entry to sit outside the four high-impact families, change this one field to a new ZONE family — nothing else in the module needs to change.',
  },
  {
    eventType: 'object.threat_like',
    kind: 'SUPPORTING',
    impactFamily: 'THREAT_LIKE',
    rationale:
      'A threat-like-object detection (§10.5). The architecture is emphatic that this is evidence and not a declaration of guilt, which is exactly what SUPPORTING means here: it feeds the probability and it raises potential impact, but corroboration and the diversity cap still gate escalation.',
  },
  {
    eventType: 'violence.possible',
    kind: 'SUPPORTING',
    impactFamily: 'VIOLENCE',
    rationale:
      'Possible physical violence (§10.4). Strongly supporting, and the family most likely to be paired with metadata.life_safety, which is what arms the core life-safety gate.',
  },
  {
    eventType: 'field.hostile_observation',
    kind: 'SUPPORTING',
    impactFamily: 'FIELD',
    humanAuthorisedFromMetadataFlag: 'human_authorised',
    rationale:
      'A hostile observation reported by a human in the field. This is the ONLY rule permitted to set humanAuthorised, and only when metadata.human_authorised === true; the core treats a human-authorised field signal as an exception to the source-diversity cap, so no other event type may reach that exception.',
  },
  {
    eventType: 'field.report.hostile',
    kind: 'SUPPORTING',
    impactFamily: 'FIELD',
    humanAuthorisedFromMetadataFlag: 'human_authorised',
    rationale:
      'ALIAS of field.hostile_observation. The WP-05 directive body names this event type as `field.report.hostile` while the implementation notes name it `field.hostile_observation`; both are mapped identically so neither spelling can silently fall through as an unmapped type. Collapse to one once the event vocabulary is frozen.',
  },
  {
    eventType: 'access_granted_valid',
    kind: 'CONTRADICTING',
    impactFamily: 'ACCESS',
    requiresMetadataFlag: 'schedule_match',
    rationale:
      'The §11.4 contradictory-evidence case. A credential that was validly granted AND matches the operational schedule is positive evidence that the activity in this window is authorised routine, so it must actively pull the hypothesis down rather than merely be absent from it. The schedule_match guard is essential: a valid grant OUTSIDE the expected schedule is not exculpatory, so without the flag this rule deliberately produces no signal at all (recorded as condition_not_met) rather than a weakened contradiction.',
  },
  {
    eventType: 'access.granted.valid',
    kind: 'CONTRADICTING',
    impactFamily: 'ACCESS',
    requiresMetadataFlag: 'schedule_match',
    rationale:
      'ALIAS of access_granted_valid — same directive spelling mismatch as the field rules above. Identical mapping and identical guard.',
  },
];

/** Exact-match lookup built from the table; duplicate event types are rejected at load. */
export const RULES_BY_EVENT_TYPE: ReadonlyMap<string, EventTypeRule> = (() => {
  const map = new Map<string, EventTypeRule>();
  for (const rule of EVENT_TYPE_RULES) {
    if (map.has(rule.eventType)) {
      throw new Error(`EVENT_TYPE_RULES contains duplicate event type "${rule.eventType}"`);
    }
    map.set(rule.eventType, rule);
  }
  return map;
})();

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/** Why an event produced no signal. Persisted on `fusion_applied_events.ignore_reason`. */
export type IgnoreReason = 'no_rule' | 'condition_not_met';

export interface MappedSignal {
  readonly outcome: 'signal';
  readonly signal: Signal;
  readonly rule: EventTypeRule;
  /** Contributed to the hypothesis's impact-family set only when kind is SUPPORTING. */
  readonly impactFamily: ImpactFamily | null;
  readonly ruleVersion: string;
}

export interface IgnoredEvent {
  readonly outcome: 'ignored';
  readonly reason: IgnoreReason;
  /** Present for 'condition_not_met' (a rule matched but its guard failed). */
  readonly rule: EventTypeRule | null;
  readonly ruleVersion: string;
}

export type SignalMapping = MappedSignal | IgnoredEvent;

function metadataFlag(metadata: Record<string, unknown> | undefined, key: string): boolean {
  return metadata?.[key] === true;
}

/**
 * Maps a normalised event to a Fusion signal using EVENT_TYPE_RULES.
 *
 * Deliberately total: it never throws and never guesses. Every event ends up
 * either as one signal or as one recorded ignore with a reason.
 */
export function mapEventToSignal(event: NormalisedEvent): SignalMapping {
  const rule = RULES_BY_EVENT_TYPE.get(event.event_type);
  if (!rule) {
    return { outcome: 'ignored', reason: 'no_rule', rule: null, ruleVersion: FUSION_RULES_VERSION };
  }

  const metadata = event.metadata as Record<string, unknown> | undefined;

  if (rule.requiresMetadataFlag && !metadataFlag(metadata, rule.requiresMetadataFlag)) {
    return { outcome: 'ignored', reason: 'condition_not_met', rule, ruleVersion: FUSION_RULES_VERSION };
  }

  const signal: Signal = {
    signalId: event.event_id,
    sourceId: event.source_id,
    sourceType: event.source_type,
    sourceTrust: event.source_trust,
    kind: rule.kind,
    confidence: event.confidence,
    // Only a rule that declares the flag may produce a human-authorised
    // signal; every other event type is pinned to false regardless of what
    // its metadata claims.
    humanAuthorised: rule.humanAuthorisedFromMetadataFlag
      ? metadataFlag(metadata, rule.humanAuthorisedFromMetadataFlag)
      : false,
    lifeSafety: metadataFlag(metadata, 'life_safety'),
  };

  return {
    outcome: 'signal',
    signal,
    rule,
    impactFamily: rule.kind === 'SUPPORTING' ? rule.impactFamily : null,
    ruleVersion: FUSION_RULES_VERSION,
  };
}
