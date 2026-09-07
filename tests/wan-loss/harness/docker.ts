/**
 * WP-30 — THE DOCKER PRIMITIVES THE WAN-LOSS HARNESS IS BUILT ON.
 *
 * Everything above this file talks about severing a WAN. This file is where
 * that becomes an actual command against an actual daemon, and it is
 * deliberately the only place in the harness that shells out at all.
 *
 * THREE RULES, EACH OF WHICH IS A DEFECT THIS FILE IS PREVENTING.
 *
 * 1. ARGV ARRAYS, NEVER A SHELL STRING. `execFile` with an argument array
 *    means no shell parses anything: a container name containing a space, a
 *    quote or a `;` is a name, not a command. The harness composes these names
 *    from test-owned namespaces, so this is not paranoia about hostile input —
 *    it is about the day someone parameterises a name and a quoting bug turns
 *    a test failure into a `docker rm -f` against the wrong container.
 *
 * 2. NO TIMING ANYWHERE. There is no `sleep`, no polling interval tuned to a
 *    machine, and no assertion in this harness that depends on how long
 *    something took. Where the harness must wait for a CONDITION it polls the
 *    condition and fails on a deadline; where it must record WHEN something
 *    happened it records an ISO instant. This repository spent TI-01, TI-02
 *    and TI-03 removing timing dependence from its suites, and a WAN-loss
 *    harness is the single easiest place to reintroduce it.
 *
 * 3. FAILURES ARE LOUD AND CARRY THE COMMAND. A docker invocation that fails
 *    silently in a harness produces a test that fails three assertions later
 *    for reasons nobody can reconstruct. Every non-zero exit throws with the
 *    exact argv, the exit code, and both streams.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

/**
 * The compose project name, pinned here and in the compose file's `name:` key.
 *
 * It is not cosmetic. Compose derives an unset project name from the
 * DIRECTORY, and `docker-compose.dev.yml` lives in the same directory — so an
 * unpinned project would make this harness's `down -v` reach the SHARED dev
 * stack's volumes, destroying other lanes' databases. The pin is what makes
 * teardown safe.
 */
export const COMPOSE_PROJECT = 'sentinel-wp30';

/**
 * Docker network names are `<project>_<network>`. Derived rather than
 * hard-coded so a project rename cannot leave the cut pointed at a network
 * that no longer exists — which would fail as "network not found", not as
 * "the WAN was never cut", and the second is the failure that matters.
 */
export const WAN_NETWORK = `${COMPOSE_PROJECT}_wan`;
export const FIELD_NETWORK = `${COMPOSE_PROJECT}_field`;

/** Container names, fixed in the compose file so `docker exec` can address them. */
export const CONTAINERS = {
  edge: 'sentinel-wp30-edge',
  central: 'sentinel-wp30-central',
  wanLink: 'sentinel-wp30-wan-link',
  fieldLanWitness: 'sentinel-wp30-field-lan-witness',
  postgres: 'sentinel-wp30-postgres',
} as const;

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HERE, '..', '..', '..');
export const COMPOSE_FILE = resolve(REPO_ROOT, 'infrastructure', 'compose', 'docker-compose.wan-loss.yml');

export interface CommandResult {
  readonly argv: readonly string[];
  readonly stdout: string;
  readonly stderr: string;
}

export class DockerCommandError extends Error {
  constructor(
    readonly argv: readonly string[],
    readonly exitCode: number | null,
    readonly stdout: string,
    readonly stderr: string,
  ) {
    super(`docker command failed (exit ${exitCode ?? 'null'}): ${argv.join(' ')}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`);
    this.name = 'DockerCommandError';
  }
}

interface ExecFileFailure {
  code?: number | null;
  stdout?: string;
  stderr?: string;
}

/**
 * Spawn a command with an argv array and NO SHELL — see rule 1 above.
 *
 * `maxBuffer` is raised well above the 1MB default because a compose build's
 * output exceeds it comfortably, and the failure mode when it does is an
 * ENOBUFS error that reads like a docker failure and is not one.
 */
export async function run(
  command: string,
  args: readonly string[],
  { timeoutMs = 300_000, cwd, env }: { timeoutMs?: number; cwd?: string; env?: Record<string, string | undefined> } = {},
): Promise<CommandResult> {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, [...args], {
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
      cwd,
      env,
    });
    return { argv, stdout, stderr };
  } catch (error) {
    const failure = error as ExecFileFailure;
    throw new DockerCommandError(argv, failure.code ?? null, failure.stdout ?? '', failure.stderr ?? '');
  }
}

/** Run `docker ...`. */
export async function docker(args: readonly string[], timeoutMs = 300_000): Promise<CommandResult> {
  return run('docker', args, { timeoutMs });
}

/** `docker compose -p <project> -f <file> ...`, the only form this harness uses. */
export async function compose(args: readonly string[], timeoutMs = 900_000): Promise<CommandResult> {
  return docker(['compose', '-p', COMPOSE_PROJECT, '-f', COMPOSE_FILE, ...args], timeoutMs);
}

/**
 * THE IN-CONTAINER PROBE — how the harness asks a question FROM somewhere
 * rather than about somewhere.
 *
 * This matters more than it looks. "Central is unreachable" is a claim about a
 * ROUTE, and a route only exists between two points. Asking from the host
 * would answer a different question entirely — the host reaches central
 * through a published port that bypasses every user-defined network and is
 * therefore unaffected by the cut. The only witness whose answer means
 * anything is a process standing where the claim is made.
 *
 * `node -e` rather than `curl`: the slim base images ship no HTTP client, and
 * installing one into a container under test to answer a question about that
 * container is how a harness starts changing the thing it measures.
 */
export async function execInContainer(
  container: string,
  argv: readonly string[],
  timeoutMs = 60_000,
): Promise<CommandResult> {
  return docker(['exec', container, ...argv], timeoutMs);
}

export type ProbeOutcome = 'REACHABLE' | 'UNREACHABLE';

export interface ProbeResult {
  readonly outcome: ProbeOutcome;
  /** `ETIMEDOUT`, `ECONNREFUSED`, `ENOTFOUND`, `EHOSTUNREACH`, … or an HTTP status. */
  readonly detail: string;
  /** ISO instant at which the probe reached its verdict. A timestamp, not a duration. */
  readonly observedAt: string;
  readonly from: string;
  readonly target: string;
}

/**
 * The probe script, run inside a container by `node -e`.
 *
 * ITS TIMEOUT IS A CLIENT TIMEOUT, NOT A TEST WAIT, and the difference is the
 * whole of rule 2 above. After the cut the route is a black hole — packets
 * leave and nothing answers — so a probe with no bound would hang until the
 * kernel gave up minutes later. The bound makes an unreachable target produce
 * a verdict promptly and deterministically. NO ASSERTION ANYWHERE READS HOW
 * LONG IT TOOK; the only thing consumed is `REACHABLE` / `UNREACHABLE` and the
 * error code, both of which are facts about routing rather than about speed.
 *
 * Written as a single expression string because it crosses an `argv` boundary
 * into a container that has no filesystem we may write to (`read_only: true`).
 */
const PROBE_SOURCE = `
const http = require('node:http');
const [host, port, path, timeout] = process.argv.slice(1);
const done = (outcome, detail) => {
  process.stdout.write(JSON.stringify({ outcome, detail, observed_at: new Date().toISOString() }));
  process.exit(0);
};
const req = http.get({ host, port: Number(port), path, timeout: Number(timeout) }, (res) => {
  res.resume();
  res.on('end', () => done('REACHABLE', 'HTTP ' + res.statusCode));
});
req.on('timeout', () => { req.destroy(); done('UNREACHABLE', 'ETIMEDOUT'); });
req.on('error', (e) => done('UNREACHABLE', e.code || e.message));
`;

/**
 * Ask, from inside `from`, whether `target` answers.
 *
 * Exits 0 whether reachable or not — an UNREACHABLE result is a legitimate
 * ANSWER, not a failure of the probe, and conflating the two would make
 * "the WAN is cut" and "the harness is broken" the same observation.
 */
export async function probeFrom(
  from: string,
  target: { host: string; port: number; path?: string },
  clientTimeoutMs = 3_000,
): Promise<ProbeResult> {
  const { stdout } = await execInContainer(from, [
    'node',
    '-e',
    PROBE_SOURCE,
    '--',
    target.host,
    String(target.port),
    target.path ?? '/health',
    String(clientTimeoutMs),
  ]);
  const parsed = JSON.parse(stdout) as { outcome: ProbeOutcome; detail: string; observed_at: string };
  return {
    outcome: parsed.outcome,
    detail: parsed.detail,
    observedAt: parsed.observed_at,
    from,
    target: `${target.host}:${target.port}${target.path ?? '/health'}`,
  };
}

/** The networks a container is currently attached to. The cut's ground truth. */
export async function attachedNetworks(container: string): Promise<string[]> {
  const { stdout } = await docker([
    'inspect',
    '-f',
    '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\\n"}}{{end}}',
    container,
  ]);
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export interface ContainerRuntimeFacts {
  readonly status: string;
  readonly restartCount: number;
  readonly pid: number;
  readonly startedAt: string;
}

/**
 * What the harness uses to prove the cut did not disturb the Edge.
 *
 * `pid` and `startedAt` are the load-bearing fields and they are here for one
 * argument: a container that was restarted and came back would report
 * `status: running` just like one that was never touched. Only an UNCHANGED
 * pid across the cut proves the process was never signalled — which is the
 * claim "severing the WAN does not take down the Edge" actually makes.
 * `restartCount` catches the daemon having done it, which is why both compose
 * services set `restart: 'no'`.
 */
export async function containerFacts(container: string): Promise<ContainerRuntimeFacts> {
  const { stdout } = await docker([
    'inspect',
    '-f',
    '{{.State.Status}}|{{.RestartCount}}|{{.State.Pid}}|{{.State.StartedAt}}',
    container,
  ]);
  const [status, restartCount, pid, startedAt] = stdout.trim().split('|');
  return {
    status,
    restartCount: Number.parseInt(restartCount, 10),
    pid: Number.parseInt(pid, 10),
    startedAt,
  };
}

/**
 * Poll a CONDITION until it holds, or fail on a deadline.
 *
 * The distinction from a sleep is not pedantry. A sleep asserts "this takes
 * less than N"; this asserts "this becomes true", and reports the last
 * observed state when it does not. The deadline is a guard against hanging CI,
 * never a measurement — nothing downstream is allowed to read how many
 * attempts it took, and the failure message deliberately reports the last
 * OBSERVATION rather than the elapsed time, so a failure sends the reader to
 * the state that was wrong instead of to a stopwatch.
 */
export async function waitForCondition(
  description: string,
  check: () => Promise<{ ok: boolean; observed: string }>,
  { deadlineMs = 120_000, intervalMs = 250 }: { deadlineMs?: number; intervalMs?: number } = {},
): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  let lastObserved = '(never evaluated)';
  for (;;) {
    try {
      const result = await check();
      lastObserved = result.observed;
      if (result.ok) return;
    } catch (error) {
      lastObserved = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() >= deadline) {
      throw new Error(`Condition never held: ${description}\nlast observation: ${lastObserved}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
