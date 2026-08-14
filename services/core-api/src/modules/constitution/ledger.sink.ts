/**
 * SENTINEL — Decision Ledger sink (WP-06 mandatory addition 4).
 *
 * WP-08 owns the durable, append-only Decision Ledger. Until it lands, the Constitution still
 * has to emit one record per evaluation — the requirement is that *no evaluation path skips
 * the sink*, not that the ledger is durable yet. `BufferingLedgerSink` is that stub: it keeps
 * records in memory and hands them over via `drain()`.
 *
 * The interface is intentionally minimal (`append`) so the WP-08 implementation is a drop-in
 * rebinding of `LEDGER_SINK` with no change to the Constitution module.
 */

import { Injectable, Optional } from '@nestjs/common';
import type { DecisionRecord } from './decision-record';

export interface LedgerSink {
  /**
   * Appends one entry. Rejecting is meaningful: `ConstitutionService.evaluate` propagates the
   * failure rather than returning an unrecorded decision, so an unwritable ledger fails the
   * evaluation closed instead of silently losing the audit trail.
   */
  append(entry: DecisionRecord): Promise<void>;
}

/** DI token for the ledger sink. WP-08 rebinds this to the durable implementation. */
export const LEDGER_SINK = 'CONSTITUTION_LEDGER_SINK';

/**
 * Bound so the buffer cannot become an unbounded memory leak in a long-running process that
 * nobody drains. Overflow drops the OLDEST entries and counts them, so the loss is visible
 * rather than silent — an in-memory stub must never pretend to be a durable ledger.
 */
export const BUFFERING_LEDGER_SINK_CAPACITY = 10_000;

@Injectable()
export class BufferingLedgerSink implements LedgerSink {
  private readonly entries: DecisionRecord[] = [];
  private dropped = 0;

  /**
   * `@Optional()` is load-bearing. The service compiles with `emitDecoratorMetadata`, so this
   * constructor emits `design:paramtypes = [Number]`; without `@Optional()` Nest would try to
   * resolve a `Number` provider and fail to instantiate the sink at boot. (Vitest transpiles
   * with esbuild, which emits no decorator metadata, so no unit test can reproduce that — the
   * annotation is here for the compiled runtime.) With it, the container injects nothing and
   * the default applies, while tests can still construct the sink with a small capacity.
   */
  constructor(@Optional() private readonly capacity: number = BUFFERING_LEDGER_SINK_CAPACITY) {}

  append(entry: DecisionRecord): Promise<void> {
    this.entries.push(entry);
    while (this.entries.length > this.capacity) {
      this.entries.shift();
      this.dropped += 1;
    }
    return Promise.resolve();
  }

  /** Returns everything buffered so far and empties the buffer. */
  drain(): readonly DecisionRecord[] {
    const drained = [...this.entries];
    this.entries.length = 0;
    return drained;
  }

  /** Buffered entries not yet drained. */
  get size(): number {
    return this.entries.length;
  }

  /** Entries discarded because the buffer overflowed. Never resets; drain() does not clear it. */
  get droppedCount(): number {
    return this.dropped;
  }
}
