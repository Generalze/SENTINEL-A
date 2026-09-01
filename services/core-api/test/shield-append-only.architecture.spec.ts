import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * WP-24/D24-12 + D24-13 — the SOURCE half of the Shield boundary guard.
 *
 * Its sibling, `shield.registry.integration.spec.ts`, drives the live services
 * against real Postgres and proves what the registry DOES. This one asks two
 * questions a behavioural test cannot answer honestly:
 *
 *   1. Is there any code path AT ALL that could mutate or erase a security
 *      event, a trust transition or an attestation observation?
 *   2. Does the Shield module publish an HTTP surface?
 *
 * A behavioural test can only prove that the paths it happens to call do not
 * mutate history. It cannot prove the absence of a path, and "append-only"
 * is precisely an absence claim. So this is a pure source scan: no stack, no
 * database, nothing to race — the same discipline, and the same reasoning, as
 * `whisper-boundary.architecture.spec.ts`.
 *
 * D24-12 puts it plainly: "there is no application update or delete path, and
 * a source guard regression protects that property rather than trusting review
 * to notice."
 */

const CORE_API_SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const SHIELD_DIR = join(CORE_API_SRC, 'modules', 'shield');

/** The three models whose rows are HISTORY and may only ever be appended to. */
const APPEND_ONLY_MODELS = ['deviceSecurityEvent', 'deviceTrustTransition', 'deviceAttestationObservation'] as const;

/** Their table names, for the raw-SQL half of the scan. */
const APPEND_ONLY_TABLES = ['device_security_events', 'device_trust_transitions', 'device_attestation_observations'] as const;

/**
 * A Prisma mutation call against one of the three models, in the shapes a
 * caller could plausibly reach it by. `create` is deliberately ABSENT: an
 * append is the one legal write, and banning it would ban the audit trail.
 */
const PRISMA_MUTATION = new RegExp(
  `(?:\\?\\.|\\.)\\s*(?:${APPEND_ONLY_MODELS.join('|')})\\s*(?:\\?\\.|\\.)\\s*(?:update|updateMany|delete|deleteMany|upsert)\\s*\\(`,
  'u',
);

/**
 * The same prohibition at the SQL level, because a raw statement bypasses
 * Prisma's model API entirely and would otherwise sail past the scan above.
 */
const RAW_MUTATION = new RegExp(`(?:UPDATE|DELETE\\s+FROM|TRUNCATE)\\s+"?(?:${APPEND_ONLY_TABLES.join('|')})"?`, 'iu');

/** Strips line and block comments so prose about the prohibition stays legal. */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/(^|[^:])\/\/[^\n]*/gu, '$1');
}

function collectTypeScriptFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    const full = join(directory, entry);
    if (statSync(full).isDirectory()) {
      found.push(...collectTypeScriptFiles(full));
      continue;
    }
    if (entry.endsWith('.ts')) found.push(full);
  }
  return found;
}

describe('WP-24/D24-12 Shield history is append-only in source', () => {
  const shieldFiles = collectTypeScriptFiles(SHIELD_DIR);
  const shieldSource = shieldFiles.filter((file) => !file.endsWith('.spec.ts'));

  it('actually found the Shield module, so an empty scan cannot pass forever', () => {
    // The lesson the security-source gate learned the hard way: a guard that
    // silently stops looking is worse than no guard, because it reads as
    // evidence. These are the files the whole property rests on.
    expect(shieldSource.length).toBeGreaterThan(8);
    for (const required of ['shield.repository.ts', 'device-security-audit.ts', 'shield.module.ts']) {
      expect(shieldSource.some((file) => file.endsWith(required)), required).toBe(true);
    }
  });

  it('no Shield source updates, deletes or upserts an append-only model', () => {
    const offenders = shieldSource.filter((file) => PRISMA_MUTATION.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('no Shield source issues raw SQL that mutates or erases an append-only table', () => {
    const offenders = shieldSource.filter((file) => RAW_MUTATION.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('the repository still WRITES to all three — the guard bans mutation, not the audit trail', () => {
    // Banning the models outright would be both wrong and trivially routed
    // around. The property that matters is that the only verb is `create`.
    const repository = readFileSync(join(SHIELD_DIR, 'shield.repository.ts'), 'utf8');
    expect(repository).toContain('deviceTrustTransition.create');
    expect(repository).toContain('deviceAttestationObservation.create');
    const auditWriter = readFileSync(join(SHIELD_DIR, 'device-security-audit.ts'), 'utf8');
    expect(auditWriter).toContain('deviceSecurityEvent.create');
  });

  it('the tripwire fires on the shapes a future edit could reach a mutation by', () => {
    // Proving the guard is not decoration. If these stop matching, the scans
    // above have quietly become comments.
    for (const shape of [
      'await tx.deviceSecurityEvent.update({ where: { id }, data: {} });',
      'await this.prisma.deviceTrustTransition.deleteMany({ where: { organisationId } });',
      'await tx.deviceAttestationObservation.upsert({ where: {}, create: {}, update: {} });',
      'await tx?.deviceSecurityEvent?.delete({ where: { id } });',
    ]) {
      expect(PRISMA_MUTATION.test(shape), shape).toBe(true);
    }
    for (const shape of [
      'Prisma.sql`UPDATE device_security_events SET payload = ...`',
      'Prisma.sql`DELETE FROM "device_trust_transitions" WHERE id = ...`',
      'Prisma.sql`TRUNCATE device_attestation_observations`',
    ]) {
      expect(RAW_MUTATION.test(shape), shape).toBe(true);
    }
    // ... and that appends and prose remain legal.
    for (const legal of [
      'await tx.deviceSecurityEvent.create({ data });',
      'await this.prisma.deviceTrustTransition.findMany({ where: { organisationId } });',
      '// there is no update or delete path for deviceSecurityEvent, by design',
      '/** deviceTrustTransition rows are never updated or deleted (D24-12). */',
      'Prisma.sql`SELECT * FROM device_security_events`',
    ]) {
      expect(PRISMA_MUTATION.test(withoutComments(legal)), legal).toBe(false);
      expect(RAW_MUTATION.test(withoutComments(legal)), legal).toBe(false);
    }
  });
});

describe('WP-24/D24-13 Shield publishes no HTTP surface', () => {
  const shieldFiles = collectTypeScriptFiles(SHIELD_DIR);

  it('the module directory contains no controller file at all', () => {
    // Not `POST /devices/enroll`, not `POST /device-context`, not
    // `POST /devices/authenticate`, not a Command-side management endpoint.
    // There is still no production facility that authenticates an incoming
    // physical device, and a route published before one exists would accept a
    // device identity from a JSON body. WP-25 is the work package that lifts
    // this prohibition.
    expect(shieldFiles.filter((file) => file.endsWith('.controller.ts'))).toEqual([]);
  });

  it('the module registers no controllers and declares no route decorator', () => {
    const source = withoutComments(readFileSync(join(SHIELD_DIR, 'shield.module.ts'), 'utf8'));
    expect(/controllers\s*:/u.test(source)).toBe(false);
    for (const file of shieldFiles) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(/@(?:Controller|Get|Post|Put|Patch|Delete|All)\s*\(/u.test(body), file).toBe(false);
    }
  });

  it('D24-13: nothing in Shield wires itself to the frozen Whisper device-key resolver', () => {
    // `WHISPER_DEVICE_KEY_RESOLVER` resolves Ed25519 under the frozen Whisper
    // v1 contract; this registry holds P-256 under the M3 profile. Connecting a
    // real physical-device Whisper path is WP-27's work, not a side effect of
    // building a registry.
    //
    // Comments are stripped first: the module header EXPLAINS why the resolver
    // is not wired, and prose about a prohibition must stay legal — the same
    // rule the Whisper boundary guard applies to its own scan.
    for (const file of shieldFiles) {
      expect(withoutComments(readFileSync(file, 'utf8')).includes('WHISPER_DEVICE_KEY_RESOLVER'), file).toBe(false);
      expect(withoutComments(readFileSync(file, 'utf8')).includes("from '../whisper/"), file).toBe(false);
    }
  });

  it('the module header names WP-25 as the work package that lifts the prohibition', () => {
    const source = readFileSync(join(SHIELD_DIR, 'shield.module.ts'), 'utf8');
    expect(source).toContain('WP-25');
    expect(source).toContain('D24-13');
  });
});
