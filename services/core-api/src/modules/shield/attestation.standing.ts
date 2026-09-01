import {
  attestationStandingPermitsTrusted,
  evaluateAttestationStanding,
  type DeviceAttestationOutcome,
  type DeviceAttestationStanding,
  type DeviceTrust,
} from '@sentinel/contracts';

/**
 * WP-24/C16-05 — ONE CANONICAL EFFECTIVE-ATTESTATION RESOLUTION.
 *
 * TWO DEFECTS THIS FILE EXISTS TO REMOVE
 * --------------------------------------
 * (a) AGEING NEVER HAPPENED. Recording `UNAVAILABLE` did nothing at all, so a
 *     device that reached TRUSTED and then went dark stayed TRUSTED for ever.
 *     `evaluateAttestationStanding` degrades last-known-good to EXPIRED past
 *     six hours, but nothing ever ASKED it about a TRUSTED device again.
 *
 * (b) NEGATIVE EVIDENCE COULD BE ERASED BY AN OUTAGE. The old resolution asked
 *     two independent questions — "what is the latest observation?" and "what
 *     is the latest VERIFIED observation?" — and handed both to the contract.
 *     For the history
 *
 *         VERIFIED (t0) -> NEGATIVE (t1) -> UNAVAILABLE (t2)
 *
 *     that produced `outcome: UNAVAILABLE` with `lastVerifiedAt: t0`, i.e.
 *     LAST_KNOWN_GOOD. The provider outage RESURRECTED a positive result the
 *     device had already lost, and the intervening negative evidence vanished.
 *
 * THE RULE, STATED ONCE
 * ---------------------
 * Walk the history NEWEST FIRST.
 *
 *   * The newest observation that is NOT `UNAVAILABLE` is the DECISIVE one.
 *     `UNAVAILABLE` is an absence of evidence (C14-05) and can neither create
 *     nor destroy a standing; everything newer than the decisive observation is
 *     by construction `UNAVAILABLE`.
 *   * If the decisive observation is NEGATIVE / INVALID / REVOKED, the standing
 *     is NEGATIVE and stays negative until a NEW `VERIFIED` observation exists
 *     AFTER it. The older positive can never be resurrected — if a VERIFIED
 *     result existed after the negative one, that VERIFIED result would BE the
 *     decisive observation and we would not be in this branch.
 *   * If the decisive observation is VERIFIED, it — and only it — is
 *     `lastVerifiedAt`. A newer `UNAVAILABLE` then rides it through exactly
 *     `DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS`, which is the CONTRACT's
 *     arithmetic and is not restated here.
 *   * No decisive observation at all (only outages, or no history) is
 *     INELIGIBLE: a device that has never been vouched for cannot become
 *     TRUSTED during an outage.
 *   * Evidence recorded in the FUTURE relative to the authoritative server
 *     clock is not a history at all. It fails closed as INCONSISTENT (C15-07).
 *
 * THE POLICY IS STILL THE CONTRACT'S. This module selects WHICH evidence is
 * decisive; `evaluateAttestationStanding` decides what that evidence MEANS,
 * including every boundary. Restating the six-hour rule here would be a second
 * copy of a security decision in a place nobody reviews as one (D24-01).
 */

/** One append-only observation, reduced to the two fields the selection needs. */
export interface AttestationObservationFact {
  readonly outcome: string;
  /** The SERVER-recorded evaluation instant. */
  readonly evaluatedAt: Date;
}

/**
 * The evidence the contract should be asked about, or `INCONSISTENT` when the
 * history does not describe a possible past.
 */
export type SelectedAttestationEvidence =
  | {
      readonly outcome: DeviceAttestationOutcome;
      readonly lastVerifiedAt: Date | null;
      readonly hasPriorVerified: boolean;
    }
  | 'INCONSISTENT';

/** `UNAVAILABLE` is the one outcome that is an ABSENCE of evidence rather than evidence. */
const OUTCOME_UNAVAILABLE = 'UNAVAILABLE';

/**
 * Chooses the evidence, given the newest observation of ANY outcome and the
 * newest observation that is not `UNAVAILABLE`.
 *
 * Two targeted reads rather than a full history walk in memory: the answer is
 * identical (everything between the decisive observation and the latest one is
 * `UNAVAILABLE` by definition of "decisive") and a device with a long outage
 * does not drag thousands of rows through the service to reach it.
 */
export function selectAttestationEvidence(input: {
  latest: AttestationObservationFact | null;
  decisive: AttestationObservationFact | null;
  now: Date;
}): SelectedAttestationEvidence {
  const nowMs = input.now.getTime();
  if (!Number.isFinite(nowMs)) return 'INCONSISTENT';

  // A device with no history at all has never been looked at. That is an
  // absence, not a negative — and with no prior VERIFIED result the contract
  // maps it to INELIGIBLE, which cannot support TRUSTED.
  if (input.latest === null) {
    return { outcome: OUTCOME_UNAVAILABLE, lastVerifiedAt: null, hasPriorVerified: false };
  }

  for (const fact of [input.latest, input.decisive]) {
    if (fact === null) continue;
    const at = fact.evaluatedAt.getTime();
    // C15-07: a record from the future is not fresh evidence, it is a record
    // somebody or something wrote wrong. It vouches for nothing.
    if (!Number.isFinite(at) || at > nowMs) return 'INCONSISTENT';
  }

  // Only outages on record. Same answer as no history: never vouched for.
  if (input.decisive === null) {
    return { outcome: OUTCOME_UNAVAILABLE, lastVerifiedAt: null, hasPriorVerified: false };
  }

  // The decisive observation cannot be older than the latest one; if it is
  // newer, the two reads describe an impossible ordering.
  if (input.decisive.evaluatedAt.getTime() > input.latest.evaluatedAt.getTime()) return 'INCONSISTENT';

  if (input.decisive.outcome !== 'VERIFIED') {
    // NEGATIVE / INVALID / REVOKED, and nothing has verified since. The
    // standing is negative, and `lastVerifiedAt` is deliberately withheld: no
    // older positive may be offered as a basis, because offering it is exactly
    // how the outage used to erase the negative.
    return {
      outcome: input.decisive.outcome as DeviceAttestationOutcome,
      lastVerifiedAt: null,
      hasPriorVerified: false,
    };
  }

  // The decisive observation is VERIFIED, so anything newer is an outage.
  const latestIsOutage = input.latest.outcome === OUTCOME_UNAVAILABLE;
  return {
    outcome: (latestIsOutage ? OUTCOME_UNAVAILABLE : 'VERIFIED') as DeviceAttestationOutcome,
    lastVerifiedAt: input.decisive.evaluatedAt,
    hasPriorVerified: true,
  };
}

/**
 * The standing itself. `evaluateAttestationStanding` is called, never
 * paraphrased: the six-hour grace, its INCLUSIVE upper boundary and the
 * negative/outage asymmetry are all the contract's rulings.
 */
export function resolveAttestationStanding(input: {
  latest: AttestationObservationFact | null;
  decisive: AttestationObservationFact | null;
  now: Date;
}): DeviceAttestationStanding {
  const evidence = selectAttestationEvidence(input);
  if (evidence === 'INCONSISTENT') return 'INCONSISTENT';
  return evaluateAttestationStanding({
    outcome: evidence.outcome,
    lastVerifiedAt: evidence.lastVerifiedAt === null ? null : evidence.lastVerifiedAt.toISOString(),
    now: input.now.toISOString(),
    hasPriorVerified: evidence.hasPriorVerified,
  }).standing;
}

/**
 * WP-24/C16-R5 — THE ONE PLACE PERSISTED TRUST IS RECONCILED WITH EXPIRING
 * EVIDENCE.
 *
 * THE HOLE IT CLOSES
 * ------------------
 * C16-05 made ageing happen, but only as an EVENT: the `TRUSTED -> DEGRADED`
 * move is written when an attestation observation is RECORDED. For the history
 *
 *     VERIFIED (t0) -> UNAVAILABLE (t1, inside the grace)   ... and then silence
 *
 * nothing ever runs again. At t0 + 6h + 1ms no observation arrives, no job
 * fires, and the persisted `device.trust` column still reads `TRUSTED` — for
 * ever. `deviceMayAct` read that column directly, so it kept answering `true`
 * for `WHISPER_DEVICE_ACTION` on evidence that had expired.
 *
 * THE RULE
 * --------
 * AUTHORISATION MUST NOT REST ON PERSISTED TRUST ALONE WHEN THAT TRUST DEPENDS
 * ON EVIDENCE THAT EXPIRES. `TRUSTED` is the only trust state
 * `attestationStandingPermitsTrusted` gates, so it is the only one this
 * function can lower: everything else is either already below TRUSTED or is a
 * conclusion (`COMPROMISED`) that attestation does not create and must not
 * erase.
 *
 * DEGRADED, not QUARANTINED — the same choice C16-05 made for the recorded
 * transition, for the same reason. An expired attestation is IGNORANCE, not
 * suspicion; nothing has accused this device of anything, and the capability
 * ordering keeps those apart.
 *
 * IT FAILS CLOSED IMMEDIATELY AND IT DOES NOT WRITE. A read that notices expiry
 * changes the ANSWER at once; it deliberately does NOT mutate the device row.
 * A read path that writes turns every authorisation check into a writer,
 * couples availability of reads to availability of writes, and would race the
 * genuine observation path that owns the `TRUSTED -> DEGRADED` transition and
 * its D24-08 transition record. The durable move remains
 * `recordAttestationObservation`'s; this is the live answer in the meantime.
 *
 * THE POLICY IS STILL THE CONTRACT'S. `attestationStandingPermitsTrusted` is
 * called, never paraphrased — which of the standings can carry TRUSTED is not a
 * decision this module gets a second opinion about.
 */
export function effectiveDeviceTrust(persistedTrust: DeviceTrust, standing: DeviceAttestationStanding): DeviceTrust {
  if (persistedTrust !== 'TRUSTED') return persistedTrust;
  return attestationStandingPermitsTrusted(standing) ? 'TRUSTED' : 'DEGRADED';
}
