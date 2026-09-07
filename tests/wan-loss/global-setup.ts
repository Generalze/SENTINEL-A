/**
 * WP-30 — ONE TOPOLOGY FOR THE WHOLE SUITE.
 *
 * Vitest's `globalSetup` runs ONCE for the run, before any worker starts.
 * Everything in this suite shares one Docker topology, and it has to: bringing
 * a severable WAN up per test file would mean several sets of containers
 * fighting over the same fixed container names, the same published ports and
 * the same `172.30.30.0/24` subnet. The companion setting is
 * `fileParallelism: false` in the config — two files cutting the same network
 * concurrently would produce a suite whose result depended on scheduling,
 * which is the exact class of defect TI-01/02/03 were spent removing.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DO: MIGRATE.
 * -------------------------------------------------
 * `prisma migrate deploy` is a discrete step in CI, run between the stack
 * starting and the live suites running, and this harness keeps that shape
 * rather than inventing a fourth place the schema can change. The central
 * image ships no Prisma CLI on purpose. `assertSchemaDeployed()` runs in the
 * suite's own setup and turns a missing schema into one sentence naming the
 * command, instead of a 500 three assertions deep.
 *
 * `bringUp()` is idempotent, so it is a cheap safety net when CI has already
 * started the stack in its own step, and the whole thing when a developer runs
 * the suite alone.
 */

import { bringUp, tearDown } from './harness/topology';

/**
 * THE GATE IS CHECKED HERE TOO, NOT ONLY IN THE SUITES.
 *
 * `WP30_WAN_LOSS_LIVE` gates the `describe`s, so an ungated run reports every
 * scenario as SKIPPED. Without this check it would nonetheless build two
 * images and start nine containers first — several minutes of Docker work to
 * run nothing at all, and, worse, it would mutate the developer's Docker state
 * as a side effect of a command that executed no test.
 *
 * The gate belongs in both places for different reasons: here so an accidental
 * run is CHEAP, and in the suites so an accidental run is HONEST — reported as
 * not-run rather than as a pass it never earned.
 */
const live = process.env.WP30_WAN_LOSS_LIVE === '1';

export async function setup(): Promise<void> {
  if (!live) return;
  await bringUp();
}

export async function teardown(): Promise<void> {
  if (!live) return;
  // A failed run is worth inspecting. `WP30_KEEP_TOPOLOGY=1` leaves the
  // containers, the networks and — crucially — the Edge volume in place so an
  // engineer can look at the state the failure happened in, rather than at a
  // reconstruction of it. Off by default: leaving a stack running is a
  // surprise, and one that holds a published postgres port.
  if (process.env.WP30_KEEP_TOPOLOGY === '1') {
    console.log('WP30_KEEP_TOPOLOGY=1 — leaving the WAN-loss topology up. Tear it down with:\n' +
      '  docker compose -p sentinel-wp30 -f infrastructure/compose/docker-compose.wan-loss.yml down -v');
    return;
  }
  await tearDown();
}
