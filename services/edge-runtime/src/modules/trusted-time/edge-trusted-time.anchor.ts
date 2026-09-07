import { z } from 'zod';
import {
  DEVICE_TIME_NOT_AUTHORITATIVE,
  classifyDevicePolicyLease,
  isExpiredAt,
  parseAuthoritativeInstants,
  type DevicePolicyLease,
  type EdgeTrustedTimeAnchorStatement,
} from '@sentinel/contracts';

/**
 * WP-29B / EDGE-C, FW2-10 — WHERE EDGE'S TRUSTED TIME COMES FROM, AND WHERE IT
 * REFUSES TO COME FROM.
 *
 * Edge's whole security purpose is to be a time witness. `edge_trusted_time` on
 * a `DeviceEdgeReceipt` is the value `evaluateOfflineOperationAdmissibility`
 * uses to place an offline operation inside its policy-lease window; without a
 * trustworthy one, five of the six offline operation kinds are refused at
 * NO_TRUSTWORTHY_TIME_WITNESS. So this file is where the entire argument either
 * holds or quietly stops holding.
 *
 * THE ONE FORMULA
 * ---------------
 *      trusted_now = statement.server_issued_at
                    + (monotonic_now − statement.edge_monotonic_at_anchor)
 *
 * Central's authoritative instant, carried forward by an interval measured on a
 * clock that only counts. Nothing else is admissible, and the exclusions are
 * each a real, tempting shortcut:
 *
 *   NEVER `Date.now()` / the host wall clock
 *       The wall clock on a site appliance is settable. Somebody with physical
 *       access — or a compromised management agent, or a hypervisor rollback —
 *       moves it back four hours, and Edge starts issuing receipts placing
 *       today's operations inside yesterday's expired lease. That is precisely
 *       the forgery D23-12 refuses to accept from a DEVICE, and it would be
 *       silently accepted from Edge because a receipt from a TRUSTED Edge is
 *       exactly what central asked for.
 *
 *   NEVER an NTP-disciplined clock
 *       Better, and still not evidence. Unauthenticated NTP is spoofable from
 *       the same LAN Edge is defending, and worse, a disciplining daemon STEPS
 *       the clock — so a value read from it can move backwards between two
 *       receipts with nothing recording that it did. An anchor plus a monotonic
 *       interval cannot do that; a stepped clock can.
 *
 *   NEVER a device-supplied timestamp
 *       `envelope.created_at` is client telemetry, and the contract's own
 *       comment is that the absence of any read of it IS the rule. An Edge that
 *       took time from the device it is witnessing would make the witness a
 *       mirror.
 *
 * PURE, AND TESTABLE WITHOUT A CLOCK
 * ----------------------------------
 * Nothing here reads a clock, a file, an environment variable or the network.
 * The monotonic reading and the OS boot identity arrive as PARAMETERS. That is
 * not a testing convenience — it is what makes "Edge never reads the wall
 * clock" a property a reader can verify by looking, rather than a claim about
 * code that could always grow one more import.
 *
 * WHAT CHANGED UNDER THE FW2-11 RULING
 * ------------------------------------
 * Round 1 held a locally-shaped anchor record. It now holds the FROZEN
 * `EdgeTrustedTimeAnchorStatement` — the exact object central signed — and
 * nothing else. The arithmetic and every boundary below are unchanged; what
 * changed is that BOTH operands of the subtraction are now inside a signature.
 * That matters more than it looks: an attacker who could not touch
 * `server_issued_at` but could edit a local monotonic field would move every
 * derived instant forward by however much they chose, with the signature
 * intact. There is deliberately no local anchor shape left for such a field to
 * live in.
 *
 * THIS CLASS ASSUMES THE STATEMENT HAS ALREADY BEEN VERIFIED. Admitting one is
 * `EdgeTrustedTimeAnchorVerifier`'s job, and it is the only thing that
 * constructs this with a non-null statement.
 */

/**
 * One reading of the two facts Edge is allowed to observe about local time.
 *
 * `monotonic_ms` must come from a source that only counts forward within a boot
 * (`process.hrtime.bigint()`), and specifically not from `Date.now()`.
 *
 * `boot_id` is the OS's identity for the current boot. It exists here because a
 * monotonic counter is only meaningful WITHIN one boot: across a restart the
 * counter resets to zero, and an anchor carried across that boundary would be
 * carried forward by an interval that is nonsense.
 */
export interface EdgeMonotonicReading {
  readonly monotonic_ms: number;
  readonly boot_id: string;
}

/**
 * Why Edge does or does not have trusted time. Every non-VALID member is a
 * distinct fact an operator needs to be able to tell apart, and every one of
 * them produces `null` rather than a guess.
 */
export const EdgeTrustedTimeStandingSchema = z.enum([
  'VALID',
  /** No anchor at all — Edge has never been given one, or a persisted one was refused. */
  'NO_ANCHOR',
  /** The anchor exists but `server_valid_until` has been reached. */
  'ANCHOR_EXPIRED',
  /** The machine rebooted. See `classify` for why this invalidates rather than degrades. */
  'BOOT_IDENTITY_CHANGED',
  /** The "monotonic" source went backwards, so it is not monotonic and cannot be trusted. */
  'MONOTONIC_NOT_MONOTONIC',
  /** C15-07: an instant this decision depends on is unreadable. */
  DEVICE_TIME_NOT_AUTHORITATIVE,
]);
export type EdgeTrustedTimeStanding = z.infer<typeof EdgeTrustedTimeStandingSchema>;

/**
 * Whether a specific operation may be witnessed, and if so at what instant.
 *
 * FW2-10 requires BOTH conditions, and the union makes the conjunction
 * structural: there is no shape in which `trusted_now` is available without the
 * lease having been judged at it.
 */
export type EdgeOperationWitnessDecision =
  | { readonly witnessable: true; readonly trusted_now: string }
  | { readonly witnessable: false; readonly reason: EdgeTrustedTimeStanding | 'LEASE_NOT_IN_FORCE' };

/**
 * THE TRUSTED-TIME ANCHOR. Pure logic over a VERIFIED statement and an injected
 * reading.
 *
 * Constructed with the statement central signed, or `null` when there is none.
 * Holding `null` is an ordinary, expected state — a freshly booted Edge that
 * has not yet reached central is in it, and so is an Edge whose persisted
 * anchor was refused at load, which after a host reboot is the NORMAL case.
 */
export class EdgeTrustedTimeAnchor {
  constructor(private readonly anchor: EdgeTrustedTimeAnchorStatement | null) {}

  /** The verified statement, or `null`. Read-only, for diagnostics and re-persistence. */
  get statement(): EdgeTrustedTimeAnchorStatement | null {
    return this.anchor;
  }

  /**
   * The anchor's usable lifetime in milliseconds, derived from the two signed
   * instants, or `null`. Diagnostics only — the expiry decision below works
   * from the instants themselves, so this can never become a second, drifting
   * opinion about when an anchor ends.
   */
  get lifetimeMs(): number | null {
    if (this.anchor === null) return null;
    const instants = parseAuthoritativeInstants({ issued: this.anchor.server_issued_at, valid: this.anchor.server_valid_until });
    return instants === null ? null : instants.valid - instants.issued;
  }

  /**
   * Why Edge does or does not currently hold trusted time.
   *
   * The order of the checks is the argument:
   *
   *  1. NO ANCHOR is not a failure, it is the starting state.
   *
   *  2. BOOT IDENTITY BEFORE EVERYTHING ELSE. If the OS boot id has changed,
   *     the anchor's `edge_monotonic_at_anchor` refers to a counter that no longer
   *     exists — the new boot's counter started at zero. Subtracting the two
   *     produces an interval that is not merely wrong but ARBITRARILY wrong,
   *     and in the common case (new counter smaller than the old one) it is
   *     NEGATIVE, which would push trusted time BACKWARDS and place today's
   *     operations inside an expired lease. This is the FW2-10 rule stated
   *     plainly: a persisted anchor is INVALID after a reboot until central
   *     re-establishes trusted time. Edge keeps its durable queue — the queued
   *     operations are still real work — but it must not manufacture trusted
   *     time from a new wall clock to go with them.
   *
   *  3. A MONOTONIC SOURCE THAT WENT BACKWARDS IS NOT MONOTONIC. Within one
   *     boot this cannot happen if the source is what it claims to be, so
   *     observing it means the source is wrong — a caller passing `Date.now()`
   *     after a clock step, a suspended and resumed VM with a broken timer, a
   *     test double. Failing closed here is what stops that mistake from
   *     becoming a receipt.
   *
   *  4. C15-07: an unreadable signed instant answers TIME_NOT_AUTHORITATIVE
   *     rather than being compared as `NaN`, because every comparison against
   *     `NaN` is `false` and a bare comparison would silently answer "not
   *     expired". The frozen `parseAuthoritativeInstants` is used rather than a
   *     local `Date.parse` for exactly that reason.
   *
   *  5. Expiry is judged on the DERIVED instant against the signed
   *     `server_valid_until`, through the shared `isExpiredAt`, so the boundary
   *     is EXCLUSIVE exactly as it is everywhere else: `trusted_now >=
   *     server_valid_until` is expired. At the boundary the two possible
   *     mistakes are not symmetrical — refusing one millisecond early costs a
   *     refusal an operator can see, admitting one millisecond late vouches for
   *     time nobody re-established.
   *
   *     Note what is NOT consulted: the host clock plays no part in expiry
   *     either. An NTP rollback or a wall-clock jump cannot extend an anchor,
   *     because the only thing that advances is the monotonic reading.
   */
  classify(reading: EdgeMonotonicReading): EdgeTrustedTimeStanding {
    const anchor = this.anchor;
    if (anchor === null) return 'NO_ANCHOR';
    if (anchor.edge_boot_id !== reading.boot_id) return 'BOOT_IDENTITY_CHANGED';

    const elapsedMs = reading.monotonic_ms - anchor.edge_monotonic_at_anchor;
    if (elapsedMs < 0) return 'MONOTONIC_NOT_MONOTONIC';

    const instants = parseAuthoritativeInstants({ issued: anchor.server_issued_at, valid: anchor.server_valid_until });
    if (instants === null) return DEVICE_TIME_NOT_AUTHORITATIVE;
    if (isExpiredAt(instants.issued + elapsedMs, instants.valid)) return 'ANCHOR_EXPIRED';
    return 'VALID';
  }

  /**
   * `trusted_now`, or `null`.
   *
   * `null` IS THE ANSWER, NOT A MISSING ANSWER. It flows into
   * `DeviceEdgeReceipt.edge_trusted_time`, which is nullable precisely so that
   * "I saw this operation, in this order, and I do not know what time it was"
   * is a sentence Edge can say truthfully. Central then refuses the time-bounded
   * kinds at NO_TRUSTWORTHY_TIME_WITNESS.
   *
   * That refusal is the CORRECT OUTCOME and must never be traded for a guess.
   * Every available substitute — the host clock, the last known good time, the
   * anchor's own `server_issued_at` used as though no time had passed, the device's
   * `created_at` — turns a refusal an operator can see into a receipt that
   * looks exactly like a real one, signed by a genuinely trusted Edge, placing
   * an operation in a window nobody witnessed. A visible gap in evidence is
   * recoverable. A forged one is not.
   */
  trustedNow(reading: EdgeMonotonicReading): string | null {
    const anchor = this.anchor;
    if (anchor === null) return null;
    if (this.classify(reading) !== 'VALID') return null;

    const instants = parseAuthoritativeInstants({ issued: anchor.server_issued_at, valid: anchor.server_valid_until });
    // Unreachable while `classify` answers VALID; kept because a future edit to
    // `classify` must not be able to turn this into a `NaN` timestamp.
    if (instants === null) return null;

    const elapsedMs = reading.monotonic_ms - anchor.edge_monotonic_at_anchor;
    return new Date(instants.issued + elapsedMs).toISOString();
  }

  /**
   * FW2-10, the conjunction: AN OPERATION NEEDS BOTH.
   *
   * The anchor must still be valid — Edge must actually know what time it is —
   * AND the operation's own policy lease must be in force AT that instant. Two
   * separate facts, and neither implies the other:
   *
   *   valid anchor, expired lease  — Edge knows the time perfectly well and the
   *                                  authority to act ran out. Witnessing it
   *                                  would produce a receipt that proves the
   *                                  operation happened outside its window,
   *                                  which central refuses as LEASE_NOT_IN_FORCE.
   *                                  Declining locally saves a round trip and,
   *                                  more importantly, keeps Edge from
   *                                  attesting to work it can see was
   *                                  unauthorised.
   *
   *   expired anchor, live lease   — the lease may well be fine, but Edge has no
   *                                  trustworthy instant to judge it AT. The
   *                                  only honest answer is that it does not
   *                                  know, and `classifyDevicePolicyLease`
   *                                  is deliberately never called with a
   *                                  fabricated instant to find out.
   *
   * The lease is judged with the FROZEN `classifyDevicePolicyLease` rather than
   * a local comparison, so Edge and central answer the boundary question — and
   * the unreadable-instant question — with the same code.
   */
  evaluateOperationWitness(lease: DevicePolicyLease, reading: EdgeMonotonicReading): EdgeOperationWitnessDecision {
    const standing = this.classify(reading);
    if (standing !== 'VALID') return { witnessable: false, reason: standing };

    const trustedNow = this.trustedNow(reading);
    if (trustedNow === null) return { witnessable: false, reason: DEVICE_TIME_NOT_AUTHORITATIVE };

    const leaseStanding = classifyDevicePolicyLease(lease, trustedNow);
    if (leaseStanding === DEVICE_TIME_NOT_AUTHORITATIVE) {
      return { witnessable: false, reason: DEVICE_TIME_NOT_AUTHORITATIVE };
    }
    if (leaseStanding !== 'VALID') return { witnessable: false, reason: 'LEASE_NOT_IN_FORCE' };

    return { witnessable: true, trusted_now: trustedNow };
  }
}
