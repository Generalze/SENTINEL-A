/**
 * WP-30 — BRINGING THE TOPOLOGY UP, RESTARTING ITS PARTS, AND TEARING IT DOWN.
 *
 * RESTARTS ARE PART OF THE PROOF, NOT PART OF THE PLUMBING.
 * ---------------------------------------------------------
 * The acceptance definition names an Edge restart in the middle of an outage.
 * That is not a convenience; it is the case that separates a system whose
 * offline state is DURABLE from one whose offline state is a variable in a
 * process. An Edge that buffers perfectly and loses everything to a power cut
 * has not survived anything, and a wiring closet is exactly where power cuts
 * happen.
 *
 * So restarting is a first-class harness operation, and each of the three
 * kinds means something different:
 *
 *   EDGE restart      — does site-local state survive the process? This is the
 *                       one the volume exists for, and the one the harness can
 *                       and does drive.
 *   CENTRAL restart   — does committed state survive central? Drives the
 *                       "stale authority cannot rewrite current state" and
 *                       "complete audit trail" ends of the scenario.
 *   FIELD APP restart — DOCUMENTED, MANUAL, AND DELIBERATELY NOT AUTOMATED
 *                       HERE. WP-26's Field client is an Android application
 *                       on a physical handset; there is no container for it,
 *                       and there must not be a stand-in that behaves like
 *                       one. See `docs/execution/WP-30-WAN-LOSS-HARNESS.md`.
 *
 * NO SLEEPS. ANYWHERE.
 * --------------------
 * `docker compose up --wait` blocks on the containers' own HEALTHCHECKs, and
 * the restart helpers poll a CONDITION with a deadline. Nothing here waits a
 * fixed period and hopes, and no assertion downstream reads how long anything
 * took. The deadlines are guards against a hung CI job, not measurements.
 */

import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  CONTAINERS,
  REPO_ROOT,
  compose,
  containerFacts,
  docker,
  run,
  waitForCondition,
  type ContainerRuntimeFacts,
} from './docker';

/**
 * Host-side endpoints. Every one is a PUBLISHED port, which is the point:
 * published ports bypass the user-defined networks entirely, so the harness
 * keeps its view of both sides of the topology while the WAN between them is
 * severed. A witness that went blind at the moment of the outage would be
 * useless.
 */
export const ENDPOINTS = {
  /** Central, reached DIRECTLY — the out-of-band channel the harness uses to ask what was committed. */
  centralDirect: 'http://127.0.0.1:3230',
  /** Central, reached THROUGH the WAN — how a client behind the link sees it. */
  centralThroughWan: 'http://127.0.0.1:3240',
  /** The wan-link's control plane. Never reachable from the Edge. */
  wanLinkControl: 'http://127.0.0.1:3241',
  /** The Edge. Published, so it stays reachable during the cut — which is the whole question. */
  edge: 'http://127.0.0.1:3210',
  /** The harness's own database URL, for `prisma migrate deploy` and namespace seeding. */
  databaseUrl: 'postgresql://sentinel:sentinel@127.0.0.1:5453/sentinel',
} as const;

/**
 * THE THREE-PHASE START, AND WHY IT CANNOT BE ONE PHASE.
 *
 * Central does not tolerate an unmigrated database. Its constitution module
 * queries `constitution_policies` during bootstrap, so a central started
 * against an empty schema does not come up degraded — it exits 1 with
 * "The table `public.constitution_policies` does not exist", and
 * `up --wait` then reports `dependency failed to start` for everything behind
 * it. Migrations are therefore not something that can be applied to a running
 * stack; they are a precondition of it.
 *
 * That is not a workaround, it is the correct shape, and it is the same shape
 * CI's `build` job already has: start the datastores, deploy the chain, start
 * the services. The central image ships no Prisma CLI and does not migrate
 * itself, because a service that migrates on boot races the day two replicas
 * start together.
 *
 *   1. `bringUpDatastores()` — postgres, nats, redis, minio; wait for healthy.
 *   2. `deployMigrations()`  — the existing chain, unchanged. WP-30 adds none.
 *   3. `bringUpServices()`   — central, wan-link, edge, the LAN witness.
 *
 * Every phase is idempotent, so when CI has already run these as its own
 * explicit steps, `globalSetup` calling them again costs a few seconds and
 * changes nothing.
 *
 * `--build` is present because the images are built from this repository and a
 * harness that silently ran a stale central would be proving things about code
 * that is no longer in the tree.
 */
export async function bringUp(): Promise<void> {
  await bringUpDatastores();
  await deployMigrations();
  await bringUpServices();
}

export async function bringUpDatastores(): Promise<void> {
  await compose(['up', '-d', '--wait', 'postgres', 'nats', 'redis', 'minio'], 600_000);
}

export async function bringUpServices(): Promise<void> {
  await compose(['up', '-d', '--build', '--wait'], 1_800_000);
}

/**
 * `down -v` — containers, networks AND volumes.
 *
 * The `-v` is safe ONLY because the project name is pinned (see
 * `COMPOSE_PROJECT`). Compose derives an unset project name from the
 * directory, and `docker-compose.dev.yml` lives in that same directory — so an
 * unpinned teardown here would delete the SHARED dev stack's postgres volume
 * and take every other lane's database with it.
 *
 * The volumes must go: an Edge queue volume surviving between runs would let a
 * scenario read state a previous run left behind, which is the same class of
 * defect as tests depending on execution order.
 */
export async function tearDown(): Promise<void> {
  await compose(['down', '-v', '--remove-orphans'], 600_000);
}

/**
 * DEPLOY THE EXISTING MIGRATION CHAIN TO THE HARNESS'S OWN DATABASE.
 *
 * WP-30 ADDS NO MIGRATION. Its migration delta is zero: the scenarios need no
 * central persistence of their own, and if one ever appears to, that is a
 * signal to stop and ask why rather than to add a table to a test harness.
 * This runs the chain that already exists, unchanged, against a database that
 * started empty — a from-zero deploy, like CI's.
 *
 * INVOKED AS `node <prisma-cli> …`, NOT AS `pnpm exec prisma`, and the reason
 * is portability rather than taste. `execFile` deliberately spawns without a
 * shell (see `docker.ts`), and on Windows the pnpm and prisma entry points are
 * `.CMD` shims that a shell-less spawn cannot execute. Resolving the CLI's real
 * JavaScript entry from the `prisma` package's own `bin` field and running it
 * with `process.execPath` works identically on every platform, and reads the
 * path out of package metadata rather than hard-coding `build/index.js`, which
 * is an internal layout Prisma is free to change.
 */
export async function deployMigrations(): Promise<void> {
  const coreApi = resolve(REPO_ROOT, 'services', 'core-api');
  // A `require` rooted in core-api, because `prisma` is that package's
  // devDependency and pnpm does not hoist it to a place `tests/` can see.
  const requireFromCoreApi = createRequire(resolve(coreApi, 'package.json'));
  const manifestPath = requireFromCoreApi.resolve('prisma/package.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as { bin?: Record<string, string> | string };
  const binEntry = typeof manifest.bin === 'string' ? manifest.bin : manifest.bin?.prisma;
  if (!binEntry) {
    throw new Error(`The 'prisma' package at ${manifestPath} declares no prisma bin entry`);
  }

  await run(
    process.execPath,
    [resolve(dirname(manifestPath), binEntry), 'migrate', 'deploy', '--schema', 'prisma/schema'],
    {
      cwd: coreApi,
      // The HARNESS database, never the shared dev one. Passed explicitly
      // rather than inherited so a developer with a `DATABASE_URL` already
      // exported for the shared stack cannot migrate it by running this suite.
      env: { ...process.env, DATABASE_URL: ENDPOINTS.databaseUrl },
    },
  );
}

/**
 * A last-line check that turns the most confusing possible failure — a 500
 * from central three assertions into a scenario, caused by a table that does
 * not exist — into one sentence naming the command that fixes it.
 */
export async function assertSchemaDeployed(): Promise<void> {
  const probeOrg = `wp30_schema_probe_${process.pid}`;
  const response = await fetch(
    `${ENDPOINTS.centralDirect}/api/v1/events?organisation_id=${probeOrg}&limit=1`,
    { headers: { 'x-dev-user-id': 'wp30-schema-probe-no-such-user' } },
  );

  // 401 is the CORRECT answer here and proves what we need: the request
  // reached central, central reached its database to look the user up, and the
  // database answered. An unmigrated database cannot produce a 401 — it
  // produces a 500 from the failed `user.findUnique`.
  if (response.status === 401) return;

  throw new Error(
    `Central did not answer the schema probe with 401 (got HTTP ${response.status}). ` +
      `The most likely cause is an unmigrated harness database. Run:\n` +
      `  DATABASE_URL="${ENDPOINTS.databaseUrl}" pnpm --filter @sentinel/core-api exec prisma migrate deploy --schema prisma/schema\n` +
      `Body: ${await response.text()}`,
  );
}

export interface RestartRecord {
  readonly container: string;
  /** ISO instants. The harness records WHEN, never HOW LONG. */
  readonly stoppedAt: string;
  readonly readyAt: string;
  readonly before: ContainerRuntimeFacts;
  readonly after: ContainerRuntimeFacts;
}

/**
 * Restart the Edge and wait for it to answer liveness again.
 *
 * `docker restart` rather than `compose up --force-recreate`: a recreate
 * builds a NEW container, and a new container would defeat the very assertion
 * the restart exists to make. The claim is "this Edge's durable state survived
 * its process dying", and a fresh container with a fresh identity proves
 * something weaker while looking identical in the logs.
 *
 * `before`/`after` facts are returned so a scenario can assert the process
 * genuinely changed — a restart that silently did nothing would otherwise pass
 * every downstream check trivially.
 */
export async function restartEdge(): Promise<RestartRecord> {
  return restartContainer(CONTAINERS.edge, ENDPOINTS.edge);
}

/**
 * Restart central and wait for liveness.
 *
 * Note that this proves durability across a PROCESS restart only. Central's
 * state lives in postgres, NATS and S3, none of which are in this container
 * and none of which are restarted here — which is correct: the question is
 * whether central holds its commitments across its own death, not whether
 * PostgreSQL does.
 */
export async function restartCentral(): Promise<RestartRecord> {
  return restartContainer(CONTAINERS.central, ENDPOINTS.centralDirect);
}

async function restartContainer(container: string, livenessBase: string): Promise<RestartRecord> {
  const before = await containerFacts(container);
  const stoppedAt = new Date().toISOString();

  // `docker restart` sends SIGTERM and waits for the process to exit before
  // SIGKILL. Both images use exec-form entrypoints so node is PID 1 and
  // receives that signal directly — which is what lets `enableShutdownHooks()`
  // run. A restart that always SIGKILLed would be testing crash recovery while
  // claiming to test restart.
  await docker(['restart', container], 120_000);

  await waitForCondition(
    `${container} answers liveness after restart`,
    async () => {
      try {
        const response = await fetch(`${livenessBase}/health`);
        return { ok: response.ok, observed: `HTTP ${response.status}` };
      } catch (error) {
        return { ok: false, observed: error instanceof Error ? error.message : String(error) };
      }
    },
    { deadlineMs: 120_000 },
  );

  const after = await containerFacts(container);
  if (after.pid === before.pid) {
    throw new Error(
      `${container} reports the same pid (${after.pid}) after a restart — the process was never replaced, ` +
        `so any assertion about surviving a restart would be vacuous`,
    );
  }

  return { container, stoppedAt, readyAt: new Date().toISOString(), before, after };
}
