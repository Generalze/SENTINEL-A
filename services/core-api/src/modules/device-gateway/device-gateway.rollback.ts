import type { DeviceGatewayRefusal } from './device-gateway.types';

/**
 * WP-25/D25-02 — THE SENTINEL THAT MAKES "ONE TRANSACTION, OR NOTHING" TRUE.
 *
 *     NO GATEWAY REPLAY CONSUMPTION, AND NO DOMAIN EFFECT, MAY SURVIVE A
 *     TRANSACTION IN WHICH THE OTHER DID NOT COMMIT.
 *
 * This is `shield.rollback.ts`'s doctrine, applied to the one place in
 * Sentinel where a device's one-shot identity and a Field-domain mutation must
 * land together. The mechanism is copied deliberately rather than reinvented,
 * because the failure it prevents is invisible at the call site:
 *
 *     A NORMAL `return` FROM A PRISMA INTERACTIVE TRANSACTION COMMITS.
 *
 * So a refusal discovered after the replay identity has been claimed — a
 * domain service that refuses, an authoritative result that does not match
 * what the gateway was about to attest to, an audit write that fails — must
 * `throw` this, never `return` a refusal. The outer caller catches it, and
 * only then produces the external answer, after Postgres has rolled the whole
 * transaction back.
 *
 * WHY IT IS THROWN BEFORE THE FIRST WRITE TOO
 * -------------------------------------------
 * Shield distinguishes a pre-write refusal, which may return, from a
 * post-write one, which must throw. This module throws in BOTH cases, on
 * purpose. The D25-04A fence re-reads seven independent facts under lock and
 * every one of them can refuse; a mixture of `return` and `throw` inside that
 * block would make the safety of each arm a matter of counting which writes
 * had happened yet. Throwing uniformly makes the rule checkable by inspection:
 * inside the final effect transaction there is no `return` of a refusal at all.
 *
 * The sentinel carries the refusal it maps to, so the external answer is
 * decided where the refusal is discovered and is never re-derived from an
 * exception message.
 */
export class DeviceGatewayTransactionRollback extends Error {
  /** The INTERNAL refusal this rollback maps to. Never the external one. */
  readonly refusal: DeviceGatewayRefusal;

  /** The frozen evaluator's own verdict, when a frozen evaluator produced it. */
  readonly contractRefusal: string | null;

  constructor(refusal: DeviceGatewayRefusal, contractRefusal: string | null = null) {
    super(`device gateway transaction rolled back: ${refusal}`);
    this.name = 'DeviceGatewayTransactionRollback';
    this.refusal = refusal;
    this.contractRefusal = contractRefusal;
  }
}

/** Narrowing helper, so a `catch` never has to trust `instanceof` alone at a distance. */
export function isDeviceGatewayTransactionRollback(error: unknown): error is DeviceGatewayTransactionRollback {
  return error instanceof DeviceGatewayTransactionRollback;
}
