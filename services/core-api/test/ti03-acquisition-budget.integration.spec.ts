import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS } from '../src/prisma/transaction-budget';

/**
 * TI-03 — THE ACQUISITION MECHANISM, CONSTRUCTED RATHER THAN WAITED FOR.
 *
 * WHAT WAS ACTUALLY WRONG
 * -----------------------
 * A Prisma interactive transaction holds its pool connection for the entire
 * callback — including the JavaScript that runs BETWEEN statements. So the pool
 * can be fully occupied while Postgres itself is doing nothing. Captured at the
 * failure instant:
 *
 *     elapsed_ms = 2019   maxWait = 2000
 *     sessions at failure instant        3
 *     sessions WITH a blocking chain     0
 *     locks held by any of them          0
 *     all three: idle in transaction, wait_event Client/ClientRead
 *
 * Zero blockers, zero locks. The caller did not lose a race for a row; it ran
 * out of permission to WAIT. 41 of 43 `$transaction` call sites had inherited
 * Prisma's 2000 ms `maxWait` by saying nothing, against measured transaction
 * durations of p50 11 ms, p90 1009 ms, p99 1984 ms — no margin at all.
 *
 * WHY THIS SUITE IS BUILT THE WAY IT IS
 * -------------------------------------
 * Earlier passes sampled `pg_stat_activity` during real suites and produced
 * three confident wrong causes, because continuous sampling can only show that
 * contention existed SOMEWHERE during a run — never that the client which timed
 * out had exhausted its OWN budget. So nothing here waits for a victim. Every
 * quantity is fixed in advance:
 *
 *     a pool of a KNOWN size            (connection_limit)
 *     occupiers that hold it for a KNOWN duration
 *     one competitor with a KNOWN maxWait
 *
 * and the ONLY thing that differs between the three cases below is the budget.
 * Same pool size, same bodies, same process, same database.
 *
 * The occupying transactions do nothing but `SELECT 1` and wait. No tables, no
 * rows, no locks, no application code — so a pass cannot be credited to, and a
 * failure cannot be blamed on, anything except pool occupancy against a budget.
 * Nothing here writes to the database, so this suite is safe beside others.
 *
 * WHAT MUST BE TRUE — BOTH HALVES
 * -------------------------------
 *   1. BOUNDED WAITING. Under legitimate contention shorter than the budget,
 *      the competitor waits and then SUCCEEDS. (It failed before.)
 *   2. BOUNDED FAILURE. Under saturation longer than the budget, the competitor
 *      still fails, and fails AT the configured ceiling.
 *
 * The second is not a formality. A budget that waits forever would turn an
 * honest, fast, attributable error into a hung request — a worse defect than
 * the one being corrected. Both halves are asserted, and neither is allowed to
 * pass by accident.
 */

const BASE_URL = process.env.DATABASE_URL ?? 'postgresql://sentinel:sentinel@localhost:5433/sentinel';

/** Small enough to saturate deliberately, large enough to be a realistic pool. */
const POOL = 3;

/** Prisma's inherited default — the budget that produced the 2019 ms failure. */
const PRISMA_IMPLICIT_MAX_WAIT_MS = 2_000;

/**
 * Longer than the old 2 s default, comfortably shorter than the canonical
 * budget. This is the "legitimate burst" case: slow, but not pathological.
 */
const CONTENDED_HOLD_MS = 3_500;

/**
 * Longer than the canonical budget. This is the pathological case, and the
 * competitor MUST still fail here.
 */
const SATURATED_HOLD_MS = DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS + 3_000;

/** Occupier budgets, generous on both axes so an occupier can never be the thing that fails. */
const OCCUPIER_OPTIONS = { maxWait: 60_000, timeout: 60_000 } as const;

/** The Prisma error identity TI-03 is about, matched on the stable sentence. */
const ACQUISITION_FAILURE = /Unable to start a transaction in the given time|Transaction API error/i;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A client whose pool size is stated rather than inherited.
 *
 * `pool_timeout` is raised deliberately: Prisma's own connection-pool checkout
 * timeout defaults to 10 s and would raise P2024 ("Timed out fetching a new
 * connection from the connection pool") — a DIFFERENT error from the one under
 * test. Pushing it far out guarantees that what expires here is the interactive
 * transaction's `maxWait` and nothing else.
 *
 * `application_name` is test-only connection identity so these sessions can be
 * attributed if they are ever seen in `pg_stat_activity`. It carries process id
 * and worker only: no organisation, no principal, nothing an identifier could
 * be reconstructed from.
 */
function poolOf(size: number): PrismaClient {
  const separator = BASE_URL.includes('?') ? '&' : '?';
  const tag = encodeURIComponent(`sentinel-ti03:${process.pid}:${process.env.VITEST_WORKER_ID ?? '0'}`);
  const url = `${BASE_URL}${separator}application_name=${tag}&connection_limit=${size}&pool_timeout=60`;
  return new PrismaClient({ datasources: { db: { url } } });
}

interface CompetitionResult {
  readonly acquired: boolean;
  readonly elapsedMs: number;
  readonly error: Error | null;
}

/**
 * Occupies every connection in `prisma`'s pool, then races one competitor
 * against `maxWait` for it.
 *
 * The competitor does not start on a timer. Each occupier signals the instant
 * it is INSIDE its transaction — that is, the instant it actually owns a pool
 * connection — and the competitor starts only once all of them have. A fixed
 * sleep would make the measured elapsed time depend on connection-establishment
 * latency, which is exactly the kind of ambiguity this suite exists to remove.
 */
async function competeForASlot(
  prisma: PrismaClient,
  input: { holdMs: number; maxWaitMs: number }
): Promise<CompetitionResult> {
  const entered: Array<() => void> = [];
  const allOccupied = Promise.all(
    Array.from({ length: POOL }, () => new Promise<void>((resolve) => entered.push(resolve)))
  );

  const occupiers = Array.from({ length: POOL }, (_unused, index) =>
    prisma
      .$transaction(async (tx) => {
        await tx.$queryRaw`SELECT 1`;
        (entered[index] as () => void)();
        await sleep(input.holdMs);
        return true;
      }, OCCUPIER_OPTIONS)
      .catch(() => false)
  );

  await allOccupied;

  const startedAt = Date.now();
  let error: Error | null = null;
  let acquired = false;
  try {
    await prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT 1`;
      },
      { maxWait: input.maxWaitMs, timeout: 30_000 }
    );
    acquired = true;
  } catch (caught) {
    error = caught instanceof Error ? caught : new Error(String(caught));
  }
  const elapsedMs = Date.now() - startedAt;

  // Every occupier must have held its slot for real; if one of them failed, the
  // pool was never saturated and the competitor's result means nothing.
  const held = await Promise.all(occupiers);
  expect(held, 'all occupiers must have held their connection').toEqual(Array(POOL).fill(true));

  return { acquired, elapsedMs, error };
}

describe('TI-03 interactive-transaction acquisition budget (live)', () => {
  let prisma: PrismaClient;

  /**
   * SATURATION ONLY MEANS SOMETHING ONCE THE POOL ACTUALLY HOLDS ITS CONNECTIONS.
   *
   * Measured, not assumed: on a cold client the first competitor was admitted at
   * 1310 ms against a 2000 ms budget with all three occupiers demonstrably inside
   * their transactions and three sessions visible in `pg_stat_activity` — while
   * the identical round run later against the same client failed at 2002 ms. A
   * pool that has not yet established `connection_limit` physical connections is
   * not the thing under test, and a suite that measured it would report the
   * budget as working when it was not.
   *
   * So the pool is driven to its full size here — plain queries first, then one
   * interactive transaction per slot, which is the path that actually pins a
   * connection. After this, "occupied" means occupied.
   */
  beforeAll(async () => {
    prisma = poolOf(POOL);
    await prisma.$connect();
    await Promise.all(Array.from({ length: POOL }, () => prisma.$queryRaw`SELECT 1`));
    await Promise.all(
      Array.from({ length: POOL }, () =>
        prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT 1`;
        }, OCCUPIER_OPTIONS)
      )
    );
  }, 60_000);

  afterAll(async () => {
    if (prisma !== undefined) await prisma.$disconnect();
  }, 60_000);

  it('BEFORE: on Prisma’s implicit 2000 ms, a legitimate burst fails without ever starting', async () => {
    const result = await competeForASlot(prisma, {
      holdMs: CONTENDED_HOLD_MS,
      maxWaitMs: PRISMA_IMPLICIT_MAX_WAIT_MS,
    });

    // This is the reported defect, reproduced deterministically: no lock, no
    // blocker, no row contention — the caller simply ran out of permission to wait.
    expect(result.acquired).toBe(false);
    expect(result.error?.message ?? '').toMatch(ACQUISITION_FAILURE);
    // It gave up at its own ceiling, well before the slot would have freed.
    expect(result.elapsedMs).toBeGreaterThanOrEqual(PRISMA_IMPLICIT_MAX_WAIT_MS - 200);
    expect(result.elapsedMs).toBeLessThan(CONTENDED_HOLD_MS);
  }, 120_000);

  it('AFTER: on the canonical budget, the same burst waits and then succeeds', async () => {
    const result = await competeForASlot(prisma, {
      holdMs: CONTENDED_HOLD_MS,
      maxWaitMs: DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS,
    });

    expect(result.error).toBeNull();
    expect(result.acquired).toBe(true);
    // It WAITED — it did not find a free slot. Anything below the old 2 s
    // ceiling would mean the pool was never actually saturated and this test
    // proved nothing about the budget.
    expect(result.elapsedMs).toBeGreaterThan(PRISMA_IMPLICIT_MAX_WAIT_MS);
    // And it was let in as soon as an occupier released, not later.
    expect(result.elapsedMs).toBeLessThan(DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS);
  }, 120_000);

  it('BOUND: under saturation longer than the budget, it still fails — at the ceiling, not forever', async () => {
    const result = await competeForASlot(prisma, {
      holdMs: SATURATED_HOLD_MS,
      maxWaitMs: DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS,
    });

    // The correction bought a bigger budget, NOT an unbounded one.
    expect(result.acquired).toBe(false);
    expect(result.error?.message ?? '').toMatch(ACQUISITION_FAILURE);
    // Failure lands at the configured ceiling: not early (which would mean the
    // budget was never applied) and not late (which would mean it is unbounded,
    // a worse defect than the one being fixed).
    expect(result.elapsedMs).toBeGreaterThanOrEqual(DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS - 500);
    expect(result.elapsedMs).toBeLessThan(SATURATED_HOLD_MS);
  }, 120_000);
});
