import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

/**
 * WP-30 — THE WAN-LOSS SUITE'S OWN RUNNER CONFIG.
 *
 * Follows the `vitest.proof-a.config.ts` precedent deliberately: a separate
 * config, a separate env flag, and a separate CI step. The reason is stronger
 * here than it was for Proof A.
 *
 * WHY THIS MUST NOT JOIN `pnpm -r test`.
 * --------------------------------------
 * This suite builds two container images, starts nine containers, severs and
 * restores Docker networks, and restarts services. Three consequences, any one
 * of which would be sufficient on its own:
 *
 *   1. IT WOULD CONTEND FOR THE SHARED DATABASE. The recorded engineering debt
 *      on `MILESTONE-3-ROADMAP.md` already names "shared-Postgres live-suite
 *      contention" — twelve live suites against one database, one intermittent
 *      failure per full local run. Adding a suite that restarts services into
 *      that sweep would make the intermittency worse and much harder to
 *      attribute. This harness runs its own postgres on its own port with its
 *      own volume for exactly that reason.
 *
 *   2. IT WOULD MUTATE HOST NETWORK STATE. `docker network disconnect` is not
 *      scoped to a test process. A developer running `pnpm -r test` should not
 *      have containers detached from networks as a side effect.
 *
 *   3. IT IS MINUTES, NOT SECONDS. The ordinary sweep is a fast feedback loop
 *      and must stay one.
 *
 * `WP30_WAN_LOSS_LIVE=1` gates the suites themselves via `describe.skip`, so an
 * accidental run reports SKIPPED — visibly not run — rather than a pass it
 * never earned. Running the config without the flag executes no scenario.
 */
export default defineConfig({
  root: '../../',

  resolve: {
    alias: {
      // -----------------------------------------------------------------------
      // The proof-a aliases exist because this config is executed from
      // `services/core-api` (so vitest resolves from a workspace member that
      // actually HAS these packages) while `root` is the repository root — so
      // an import from `tests/` resolves upward to a root `node_modules` that
      // does not contain them.
      //
      // `@prisma/client` is the addition WP-30 needs, and it is needed for one
      // specific reason: every identity endpoint on central is guarded, and
      // `DevAuthGuard` resolves its principal by looking the header's user id
      // up in the database — so the first user of a namespace cannot be created
      // through an API that requires a user to exist. The harness seeds
      // directly, through `seedIdentity`, exactly as proof-a does.
      // -----------------------------------------------------------------------
      '@prisma/client': resolve('../../services/core-api/node_modules/@prisma/client'),
      '@nestjs/core': resolve('../../services/core-api/node_modules/@nestjs/core'),
      '@nestjs/platform-express': resolve('../../services/core-api/node_modules/@nestjs/platform-express'),
    },
  },

  test: {
    globals: true,
    environment: 'node',
    include: ['tests/wan-loss/**/*.test.ts'],

    /**
     * ONE TOPOLOGY FOR THE WHOLE RUN. Brought up once, before any worker
     * starts, and torn down after — unless `WP30_KEEP_TOPOLOGY=1`, which
     * leaves a failed run inspectable.
     */
    globalSetup: ['tests/wan-loss/global-setup.ts'],

    /**
     * NO PARALLELISM, AND THIS IS A CORRECTNESS SETTING RATHER THAN A
     * PERFORMANCE ONE.
     *
     * There is exactly one WAN in this topology. Two files cutting and
     * restoring it concurrently would produce a suite whose result depended on
     * scheduling — one file's `restore()` landing inside another file's outage
     * and quietly reconnecting the link mid-assertion. That is precisely the
     * class of nondeterminism TI-01, TI-02 and TI-03 were spent removing from
     * this repository, and a WAN-loss harness is the easiest place in the
     * codebase to reintroduce it.
     *
     * Both settings are required: `fileParallelism: false` serialises the
     * FILES, and the single-fork pool stops the runner from spawning workers
     * that would each hold their own view of shared Docker state.
     */
    fileParallelism: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },

    /**
     * Generous timeouts, and they are GUARDS RATHER THAN MEASUREMENTS.
     *
     * Nothing in this suite asserts on elapsed time; every stall is expressed
     * as a timestamp and every wait polls a condition. These bounds exist so a
     * genuinely hung docker daemon fails the job instead of blocking CI
     * forever. `hookTimeout` is the larger of the two because `beforeAll` may
     * be waiting on a container restart.
     */
    testTimeout: 300_000,
    hookTimeout: 600_000,
    /** A cold `up --build` builds two images from scratch. */
    teardownTimeout: 600_000,
  },
});
