#!/usr/bin/env node
/**
 * WP-10 CLI entry point. Plain argv parsing, no CLI framework dependency.
 *
 * Usage:
 *   node dist/cli.js --name proof-a-intrusion --org <orgId> --site <siteId> --base-url <url> \
 *     [--zone name=id ...] [--header Name=Value ...] [--speed <n|infinity>] \
 *     [--contradiction] [--trace-id <id>]
 */
import { runScenario } from './runner.js';
import { getScenario, SCENARIO_NAMES } from './scenarios/index.js';

interface ParsedArgs {
  readonly flags: Record<string, string>;
  readonly bools: Set<string>;
  readonly zones: string[];
  readonly headers: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags: Record<string, string> = {};
  const bools = new Set<string>();
  const zones: string[] = [];
  const headers: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    const hasValue = next !== undefined && !next.startsWith('--');

    if (key === 'zone' && hasValue) {
      zones.push(next);
      i++;
      continue;
    }
    if (key === 'header' && hasValue) {
      headers.push(next);
      i++;
      continue;
    }
    if (hasValue) {
      flags[key] = next;
      i++;
    } else {
      bools.add(key);
    }
  }

  return { flags, bools, zones, headers };
}

function parseSpeed(raw: string | undefined): number | undefined {
  if (raw === undefined) {
    return undefined;
  }
  const normalised = raw.trim().toLowerCase();
  if (normalised === 'inf' || normalised === 'infinity') {
    return Infinity;
  }
  const value = Number(raw);
  if (Number.isNaN(value)) {
    throw new Error(`--speed must be a number or "infinity", got "${raw}"`);
  }
  return value;
}

function parsePairs(pairs: string[], flagName: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq === -1) {
      throw new Error(`--${flagName} must be name=value, got "${pair}"`);
    }
    out[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return out;
}

function printUsage(): void {
  process.stderr.write(
    [
      'Usage: node dist/cli.js --name <scenario> --org <orgId> --site <siteId> --base-url <url>',
      '  [--zone name=id ...] [--header Name=Value ...] [--speed <n|infinity>]',
      '  [--contradiction] [--trace-id <id>]',
      '',
      `Known scenarios: ${SCENARIO_NAMES.join(', ')}`,
    ].join('\n') + '\n'
  );
}

async function main(): Promise<void> {
  const { flags, bools, zones, headers } = parseArgs(process.argv.slice(2));

  const name = flags.name;
  const org = flags.org;
  const site = flags.site;
  const baseUrl = flags['base-url'];

  if (!name || !org || !site || !baseUrl) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const scenario = getScenario(name, { contradiction: bools.has('contradiction') });

  const result = await runScenario(scenario, {
    baseUrl,
    orgId: org,
    siteId: site,
    zoneIds: parsePairs(zones, 'zone'),
    apiHeaders: parsePairs(headers, 'header'),
    speed: parseSpeed(flags.speed),
    traceId: flags['trace-id'],
  });

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  const failed = result.results.filter((r) => !r.ok);
  if (failed.length > 0) {
    process.stderr.write(`${failed.length}/${result.results.length} event(s) failed delivery.\n`);
    process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exitCode = 1;
});
