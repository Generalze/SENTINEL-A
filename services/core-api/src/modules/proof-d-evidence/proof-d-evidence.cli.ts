import { readFile, writeFile } from 'node:fs/promises';
import { PrismaClient } from '@prisma/client';
import { PROOF_D_CLAIM, PROOF_D_CLAIM_STATEMENT, PROOF_D_COLLECTOR_GATE_ENV } from './proof-d-evidence.constants';
import { collectProofDEvidence } from './proof-d-evidence.collector';
import { readProofDObservation, type ProofDSqlClient } from './proof-d-evidence.reader';
import { ProofDHarnessAttestationSchema, type ProofDReadWindow } from './proof-d-evidence.types';

/**
 * WP-31 — the gated collector entry point.
 *
 * WHY A GATED SCRIPT AND NOT A ROUTE. An evidence bundle joins offline
 * receipts, gateway decisions, lease provenance and outbox backlog into one
 * artefact. Exposed as an endpoint it would be a new read surface over the
 * device-security audit trail, authorised by something that does not exist
 * yet, and it would need to be defended forever. Run as a script by an
 * operator who already holds database access, it grants nobody anything they
 * did not already have.
 *
 * IT ONLY READS. There is no write statement anywhere in this module, and the
 * bundle is written to a file rather than into the database — a collector that
 * stored its own output would be adding to the state it is supposed to be
 * describing.
 *
 * Usage:
 *
 *   SENTINEL_PROOF_D_EVIDENCE=1 node dist/modules/proof-d-evidence/proof-d-evidence.cli.js \
 *     --attestation ./run-attestation.json \
 *     --out ./proof-d-bundle.json \
 *     [--lookback-ms 3600000]
 */

/**
 * How far BEFORE the attested severance the reader sweeps.
 *
 * It exists so `central_observation_gap` has a "last event before the cut" to
 * report. An hour is a judgement, not a rule, which is exactly why it is
 * overridable and why the window it produces is recorded in the bundle: a
 * reader who thinks the window was too narrow can see that it was.
 */
export const PROOF_D_DEFAULT_LOOKBACK_MS = 3_600_000;

interface CliArguments {
  attestationPath: string;
  outPath: string;
  lookbackMs: number;
}

export class ProofDCollectorGateError extends Error {}

function parseArguments(argv: readonly string[]): CliArguments {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token !== undefined && token.startsWith('--')) {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new ProofDCollectorGateError(`${token} requires a value`);
      }
      values.set(token.slice(2), next);
      index += 1;
    }
  }
  const attestationPath = values.get('attestation');
  const outPath = values.get('out');
  if (attestationPath === undefined || outPath === undefined) {
    throw new ProofDCollectorGateError('both --attestation and --out are required');
  }
  const lookback = values.get('lookback-ms');
  const lookbackMs = lookback === undefined ? PROOF_D_DEFAULT_LOOKBACK_MS : Number(lookback);
  if (!Number.isSafeInteger(lookbackMs) || lookbackMs < 0) {
    throw new ProofDCollectorGateError('--lookback-ms must be a non-negative integer');
  }
  return { attestationPath, outPath, lookbackMs };
}

/**
 * The gate.
 *
 * An explicit environment variable rather than an inferred condition, for the
 * reason `security-source-gate.sh` states about scanners: a check that can be
 * satisfied by accident is indistinguishable from no check. Someone running
 * this has to say so.
 */
export function assertCollectorGateOpen(env: Readonly<Record<string, string | undefined>>): void {
  if (env[PROOF_D_COLLECTOR_GATE_ENV] !== '1') {
    throw new ProofDCollectorGateError(
      `${PROOF_D_COLLECTOR_GATE_ENV}=1 is required. This collector reads the device-security audit trail across four modules; it is not run by accident.`,
    );
  }
}

/**
 * Derive the sweep window from the attestation.
 *
 * `to` is the attested restoration plus the same lookback, or the read time
 * when the link is still down — reconciliation happens AFTER restoration, so a
 * window that stopped at the restore instant would miss the entire half of the
 * run that Proof D is about.
 */
export function deriveReadWindow(
  severedAt: string,
  restoredAt: string | null,
  readAt: string,
  lookbackMs: number,
): ProofDReadWindow {
  const severed = Date.parse(severedAt);
  const from = new Date(severed - lookbackMs).toISOString();
  const to =
    restoredAt === null ? readAt : new Date(Math.max(Date.parse(restoredAt) + lookbackMs, Date.parse(readAt))).toISOString();
  return { from, to };
}

/**
 * A Prisma client narrowed to the reader's seam.
 *
 * `$queryRawUnsafe` names the statement text, not the parameters: the values
 * still travel as Postgres bind parameters, so no caller-supplied value is
 * ever interpolated into SQL. The statements themselves are the constants
 * written in the reader.
 */
export function prismaSqlClient(prisma: PrismaClient): ProofDSqlClient {
  return {
    async query(sql: string, params: readonly unknown[]): Promise<readonly unknown[]> {
      const rows = await prisma.$queryRawUnsafe(sql, ...params);
      return Array.isArray(rows) ? rows : [];
    },
  };
}

export async function runProofDCollector(argv: readonly string[]): Promise<void> {
  assertCollectorGateOpen(process.env);
  const args = parseArguments(argv);

  const attestation = ProofDHarnessAttestationSchema.parse(
    JSON.parse(await readFile(args.attestationPath, 'utf8')),
  );

  const readAt = new Date().toISOString();
  const window = deriveReadWindow(attestation.wan.severed_at, attestation.wan.restored_at, readAt, args.lookbackMs);

  const prisma = new PrismaClient();
  try {
    const observation = await readProofDObservation(prismaSqlClient(prisma), attestation.scope, window, readAt);
    const bundle = collectProofDEvidence(observation, attestation, readAt);
    await writeFile(args.outPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');

    /**
     * The banner is printed on every run, including a run whose every check
     * held. A collector that congratulated the operator on a clean bundle
     * would be the first step toward somebody quoting it as a result.
     */
    console.log(`Proof D evidence bundle written to ${args.outPath}`);
    console.log(`  Proof C                       ${PROOF_D_CLAIM.proof_c}`);
    console.log(`  Proof D                       ${PROOF_D_CLAIM.proof_d}`);
    console.log(`  WP-26 physical acceptance     ${PROOF_D_CLAIM.wp_26_physical_acceptance}`);
    console.log(`  WP-28                         ${PROOF_D_CLAIM.wp_28}`);
    console.log(`  physical acceptance eligible  ${String(bundle.acceptance.physical_acceptance_eligible)}`);
    for (const reason of bundle.acceptance.reasons) {
      console.log(`    - ${reason}`);
    }
    console.log(PROOF_D_CLAIM_STATEMENT);
  } finally {
    await prisma.$disconnect();
  }
}

/**
 * Run only when this file IS the program.
 *
 * Matched against `process.argv[1]` rather than `require.main`, because the
 * repository's lint configuration declares the runtime globals it permits and
 * CommonJS module internals are not among them. The effect is the same: an
 * import of this module for its exported functions — which is how the tests
 * reach `deriveReadWindow` and the gate — must not start a collection run.
 */
const INVOKED_DIRECTLY = /proof-d-evidence\.cli(\.[cm]?[jt]s)?$/.test(process.argv[1] ?? '');

if (INVOKED_DIRECTLY) {
  runProofDCollector(process.argv.slice(2)).catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
