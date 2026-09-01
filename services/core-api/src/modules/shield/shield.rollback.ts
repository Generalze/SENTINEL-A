import type { ShieldRefusalCode } from './shield.types';

/**
 * WP-24/C16-02, C16-04 — THE ONE DOCTRINE THIS FILE EXISTS TO ENFORCE.
 *
 *     NO CONSUMPTION RECORD, AND NO IRREVERSIBLE SECURITY WRITE, MAY SURVIVE A
 *     TRANSACTION IN WHICH THE EFFECT IT CLAIMS DID NOT COMMIT.
 *
 * WHY A SENTINEL ERROR AND NOT A RETURN
 * -------------------------------------
 * A normal `return` from a Prisma interactive transaction COMMITS. That is the
 * whole defect C16-02 and C16-04 name, and it is invisible at the call site:
 *
 *   * enrollment consumed the bootstrap and challenge replay identities BEFORE
 *     the admissibility gate ran, stored a PRE-GENERATED device id as the
 *     outcome reference, and then returned a refusal. The callback returned
 *     normally, so Prisma committed — leaving a FIRST_SEEN row pointing at a
 *     device that was never created. A later exact retry then classified as
 *     EXACT_DUPLICATE and "converged" on an identity that does not exist.
 *
 *   * rotation marked the old key ROTATED and inserted the new key before the
 *     device-pointer compare-and-set. Returning `STALE_ROTATION` when the CAS
 *     reported zero rows committed both of those writes: two live keys, a
 *     device pointing at neither, and no rotation.
 *
 *   * the disposition path moved trust, wrote the transition record and then
 *     discovered the key lifecycle transition was illegal — and committed the
 *     trust move anyway.
 *
 * THE RULE, STATED SO IT CAN BE CHECKED IN REVIEW
 * ----------------------------------------------
 *  1. PREVALIDATE every fallible condition BEFORE the first write of a
 *     transaction. Locks, contract parses, authority, lifecycle legality,
 *     runtime key validity, semantic bindings — all of them.
 *  2. A refusal reached AFTER the first write must `throw` this sentinel. It
 *     must never `return`.
 *  3. The outer caller catches it, and only then produces the external
 *     refusal — after Postgres has rolled the whole transaction back.
 *  4. Anything the refusal still needs to RECORD (the D24-12 audit event) is
 *     written afterwards, in its own transaction, so the trail survives while
 *     the security state does not.
 *
 * The sentinel carries the refusal it maps to, so the external answer is
 * decided at the point the refusal is discovered and is never re-derived from
 * an exception message.
 */
export class ShieldTransactionRollback extends Error {
  /** The external refusal this rollback maps to, verbatim. */
  readonly refusal: ShieldRefusalCode;

  /**
   * Whether the caller should still write a refusal audit event afterwards.
   *
   * `false` for refusals discovered before anything worth recording happened
   * (a lock read that found nothing), `true` for a refusal that a D24-12 trail
   * must retain. It is a field rather than a caller-side `switch` because the
   * decision belongs where the refusal is raised.
   */
  readonly audited: boolean;

  constructor(refusal: ShieldRefusalCode, options: { audited?: boolean } = {}) {
    super(`shield transaction rolled back: ${refusal}`);
    this.name = 'ShieldTransactionRollback';
    this.refusal = refusal;
    this.audited = options.audited ?? true;
  }
}

/** Narrowing helper, so a `catch` never has to trust `instanceof` alone at a distance. */
export function isShieldTransactionRollback(error: unknown): error is ShieldTransactionRollback {
  return error instanceof ShieldTransactionRollback;
}
