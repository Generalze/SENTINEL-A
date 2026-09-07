/**
 * WP-29B / LANE B — THE DURABLE QUEUE'S HARD-WIRED NUMBERS.
 *
 * These live here rather than in `edge-runtime.constants.ts` only to keep the
 * queue's surface in one directory; the DOCTRINE is that file's, restated
 * because it decides every value below:
 *
 *   DOES THIS VALUE CHANGE WHAT EDGE IS WILLING TO WITNESS OR ADMIT? If yes it
 *   is hard-wired and changing it is a reviewed diff.
 *
 * Every number here answers yes, and the queue depth is the sharpest case.
 * `EDGE_QUEUE_MAX_UNSETTLED=1` is an Edge that refuses the site's second
 * operation of the shift; `EDGE_QUEUE_MAX_UNSETTLED=100000000` is an Edge that
 * fills its own disk and then cannot write the queue it is protecting — the
 * failure that takes down the store is always the write you are in the middle
 * of. Neither is a deployment preference, and both are settable in thirty
 * seconds by anyone with shell access to a wiring closet if this is an env var.
 *
 * There is deliberately NO `EDGE_QUEUE_MAX_ATTEMPTS` and no `EDGE_QUEUE_MAX_AGE_MS`,
 * for the reason `RetrySchedule` gives on the Android side: a cap on attempts
 * or on age is a rule that eventually DISCARDS an operation an operative
 * actually performed, because a network stayed down longer than somebody
 * guessed. Only central ends a queued operation, and it ends it by answering.
 */

/** The database file, inside the configured `EDGE_QUEUE_PATH` directory. */
export const EDGE_QUEUE_DATABASE_FILENAME = 'edge-queue.db';

/**
 * The stored format. A different version is REFUSED, never guessed at and never
 * migrated in place by a box on a customer LAN — see `MalformedEdgeQueueError`.
 */
export const EDGE_QUEUE_SCHEMA_VERSION = 1;

/**
 * `MAX_OFFLINE_DEVICE_SEQUENCE` from the frozen contracts, repeated as a SQL
 * literal because a CHECK constraint cannot import.
 *
 * It bounds `enqueued_edge_monotonic_position` for the reason the contract
 * gives: `DeviceEdgeReceipt.edge_monotonic_position` shares this ceiling, so a
 * queue that could record a position the receipt schema then refuses to carry
 * would produce entries Edge cannot witness for — discovered at witness time
 * rather than at enqueue time.
 */
export const EDGE_QUEUE_MAX_MONOTONIC_POSITION = 9_007_199_254_740_991;

/**
 * HOW MANY OPERATIONS CENTRAL HAS NOT ANSWERED THIS EDGE WILL HOLD.
 *
 * This is the admission bound, and it counts UNSETTLED entries only. It is
 * sized for the situation Edge exists for: a whole site, cut off for a long
 * shift. A few hundred operatives acknowledging messages and moving through
 * assignments for twelve hours does not reach four thousand; a site that does
 * has a bigger problem than a full queue, and it will find out about it
 * truthfully rather than by losing the four thousand and first.
 */
export const EDGE_QUEUE_MAX_UNSETTLED = 4_096;

/**
 * HOW MANY SETTLED ENTRIES ARE KEPT AFTER CENTRAL HAS ANSWERED.
 *
 * A settled entry is local PROVENANCE — it says central accepted or refused
 * this exact envelope, and an operator diagnosing "did my duress signal get
 * there" wants to see it. It is not evidence anyone depends on: central holds
 * the receipt, and this is Edge's copy of a finished conversation.
 *
 * So this is the only bound in the file that is enforced by DELETION, and the
 * distinction is the whole capacity policy: reclamation may remove a row
 * CENTRAL HAS ANSWERED, and there is a database trigger that makes removing any
 * other row impossible. Deleting an unresolved operation to make room is the
 * defect this codebase most needs to be unable to commit; deleting a receipt
 * for work central already recorded is housekeeping.
 */
export const EDGE_QUEUE_SETTLED_RETENTION = 1_024;

/**
 * When the unsettled depth crosses this fraction of the bound, the store starts
 * reporting a DEGRADED capacity state.
 *
 * Not a second bound, and it refuses nothing: it exists so that "the queue is
 * filling up" is visible while there is still time to do something about it,
 * instead of arriving as the first refusal. An operator who learns about
 * saturation from a refused operation learns about it from a Field operative.
 */
export const EDGE_QUEUE_DEGRADED_FRACTION = 0.9;

/** The wait after the first attempt that did not settle. */
export const EDGE_QUEUE_RETRY_BASE_DELAY_MS = 5_000;

/**
 * The ceiling on the wait. Fifteen minutes.
 *
 * THE CEILING IS ON THE DELAY, NOT ON THE NUMBER OF ATTEMPTS. The delay
 * saturates; the operation does not expire.
 */
export const EDGE_QUEUE_RETRY_MAX_DELAY_MS = 900_000;

/**
 * How long to wait before attempt number `attemptCount + 1`.
 *
 * Pure arithmetic, no clock and no timer, so everything about a backoff that
 * can be wrong — an overflow at attempt 60, a ceiling that is not a ceiling — is
 * settled by a unit test. `attemptCount` is the number of attempts already made
 * and not settled; zero means "never tried" and answers zero.
 *
 * WHY THERE IS NO JITTER HERE, WHEN THE ANDROID SCHEDULE HAS IT.
 * `RetrySchedule` jitters because a FLEET of handsets rejoins one access point
 * at the same instant and would retry in lockstep. An Edge is one process
 * draining one queue to one central: there is no herd to spread, and the
 * randomness would only make the store's behaviour irreproducible in a test for
 * no operational gain. If Edge ever forwards in parallel, the spread belongs at
 * that call site, not in this arithmetic.
 *
 * The shift is bounded before it is applied — `1 << 60` is not a large number in
 * JavaScript, it is a WRONG one — so saturation is reached by comparison rather
 * than by trusting the exponent.
 */
export function edgeQueueRetryDelayMs(attemptCount: number): number {
  if (!Number.isInteger(attemptCount) || attemptCount <= 0) return 0;
  const steps = Math.min(attemptCount - 1, 40);
  const delay = EDGE_QUEUE_RETRY_BASE_DELAY_MS * Math.pow(2, steps);
  return Math.min(delay, EDGE_QUEUE_RETRY_MAX_DELAY_MS);
}
