/**
 * TI-03 — the interactive-transaction ACQUISITION budget, stated once.
 *
 * WHAT THIS IS, AND WHAT IT IS NOT
 *
 * Prisma's `$transaction(fn, options)` carries two independent time limits and
 * they are routinely confused:
 *
 *   `maxWait`  how long a caller may wait to ACQUIRE a transaction — a pool
 *              connection plus a slot in Prisma's own transaction queue —
 *              before it gives up without ever having begun. Default 2000 ms.
 *   `timeout`  how long an ALREADY-ACQUIRED transaction may execute before the
 *              engine rolls it back. Default 5000 ms.
 *
 * This module governs `maxWait` ONLY. Nothing here may be used to widen
 * `timeout`: a transaction that runs too long is a different defect with a
 * different remedy, and raising both would hide it.
 *
 * WHY THE DEFAULT WAS WRONG FOR SENTINEL
 *
 * A Prisma interactive transaction holds its pool connection for the whole
 * callback, including the JavaScript that runs BETWEEN statements. So a handful
 * of concurrent transactions can occupy the pool while Postgres itself is idle.
 * That is precisely what was measured at the failure instant: three sessions
 * occupying the pool, all `idle in transaction` on `Client`/`ClientRead`, ZERO
 * blocking chains and ZERO locks held — and a fourth caller failing at
 * elapsed 2019 ms against Prisma's inherited 2000 ms ceiling with
 * `Transaction API error: Unable to start a transaction in the given time`.
 * Row locks were exonerated; the budget was the defect.
 *
 * The margin was never there to begin with. Measured interactive-transaction
 * duration across the system is p50 11 ms, p90 1009 ms, p99 1984 ms — against a
 * 2000 ms acquisition ceiling. One transaction at p99 is enough to exhaust the
 * budget of the next caller that wants the same connection, with nothing
 * pathological happening anywhere.
 *
 * WHERE THE VALUE COMES FROM — IT IS NOT INVENTED
 *
 * `LedgerRepository.append` already ran on 10_000 ms, and the comment above it
 * already diagnosed this exact failure mode a year of call sites too early:
 *
 *     "A burst of concurrent appends for the same organisation legitimately
 *      serialises on the advisory lock (that is the point), so later
 *      transactions in the burst can be left waiting for both a free pool
 *      connection and their turn on the lock; Prisma's interactive-transaction
 *      defaults (`maxWait` 2s, `timeout` 5s) are sized for independent
 *      transactions, not a deliberately-serialised queue, so both are raised
 *      here to accommodate a legitimate burst rather than surfacing it as a
 *      spurious 'unable to start a transaction' error."
 *
 * That reasoning was never specific to the ledger. Every `$transaction` in this
 * service shares one pool, so every one of them can be the caller left waiting
 * behind a legitimate burst. The ledger's value is therefore promoted from a
 * local workaround to the service-wide policy, and this module is the single
 * place it is written down.
 *
 * WHY BOUNDED, NOT INFINITE
 *
 * 10_000 ms is a budget, not a licence. It is roughly five times the measured
 * p99 transaction duration, so a caller queued behind several legitimate
 * transactions waits and then proceeds; but under genuine saturation — slots
 * held longer than the budget — the caller still fails, and fails at a known
 * ceiling. Unbounded waiting would convert an honest, fast, attributable error
 * into a hung request, which is a worse defect than the one being corrected.
 * `transaction-budget.spec.ts` and `ti03-acquisition-budget.integration.spec.ts`
 * pin both halves of that claim.
 */

/**
 * The acquisition budget every interactive transaction in core-api is given.
 *
 * Pass it as `maxWait`. Do not read it as a `timeout`, and do not fork it per
 * module: a per-call-site budget is how the 2000 ms default survived unnoticed
 * at 41 of 43 call sites in the first place.
 */
export const DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS = 10_000;

/**
 * The options object to spread into a `$transaction` call that has no other
 * options of its own.
 *
 * Deliberately carries `maxWait` and nothing else. A call site that also needs
 * a non-default `timeout` states that itself, next to the reason it needs one —
 * so an execution-time exception stays visible as an exception rather than
 * being absorbed into a shared default.
 */
export const DEFAULT_INTERACTIVE_TRANSACTION_OPTIONS = {
  maxWait: DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS,
} as const;
