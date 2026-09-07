/* global __dirname -- CJS global; not in this repo's shared ESLint globals list (see ledger.append-only.spec.ts for the same gap) */
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS,
  DEFAULT_INTERACTIVE_TRANSACTION_OPTIONS,
} from './transaction-budget';

/**
 * TI-03 — THE BUDGET IS CONFIGURED, SO PROVE IT STAYS CONFIGURED.
 *
 * The defect this pins was not a wrong value someone typed. It was an ABSENT
 * value: 41 of 43 `$transaction` call sites passed no options at all, silently
 * inherited Prisma's 2000 ms `maxWait`, and failed with
 * "Unable to start a transaction in the given time" at elapsed 2019 ms while
 * Postgres held zero locks and zero blocking chains.
 *
 * An absence cannot be caught by reading a diff, because the next `$transaction`
 * anyone writes is implicit BY DEFAULT — doing nothing reintroduces the defect.
 * So this is an automated source scan, in the same shape as
 * ledger.append-only.spec.ts and events.append-only.spec.ts: it parses every
 * `$transaction(` call in core-api's production source and requires each one to
 * name the shared budget.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * It does not assert a call-site COUNT. New transactions are legitimate; new
 * transactions on the 2 s default are not. And it says nothing about `timeout`,
 * which is an execution budget and stays a per-call-site decision — the two are
 * different limits and TI-03 changed only one of them.
 */

/** core-api's production source root; `__dirname` is `src/prisma`. */
const SRC_ROOT = join(__dirname, '..');

const OPTIONS_CONSTANT = 'DEFAULT_INTERACTIVE_TRANSACTION_OPTIONS';
const MAX_WAIT_CONSTANT = 'DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS';

const BACKSLASH = String.fromCharCode(92);

interface CallSite {
  readonly file: string;
  readonly line: number;
  /** Everything between the call's parentheses, verbatim. */
  readonly argumentText: string;
}

function listProductionSources(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionSources(full));
      continue;
    }
    if (!entry.name.endsWith('.ts')) continue;
    // Specs and test-support fixtures are not the production budget surface.
    if (/\.(spec|test|test-support)\.ts$/.test(entry.name)) continue;
    files.push(full);
  }
  return files;
}

/** Skips a single- or double-quoted string starting at `i`; returns the index after it. */
function skipQuoted(source: string, start: number): number {
  const quote = source[start];
  let i = start + 1;
  while (i < source.length && source[i] !== quote) {
    if (source[i] === BACKSLASH) i++;
    i++;
  }
  return i + 1;
}

/**
 * Finds the closing parenthesis of the call whose `(` is at `open`.
 *
 * Written as a brace matcher rather than a regex on purpose. The call sites are
 * multi-line arrow functions containing object literals, tagged template SQL
 * (`tx.$executeRaw` with `${}` interpolation) and comments — every one of which
 * defeats a line-oriented match, and one of which (a doc comment quoting
 * "$transaction(") would otherwise be scanned as if it were code.
 */
function findCallEnd(source: string, open: number): number {
  let i = open + 1;
  let depth = 1;
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (c === '/' && next === '/') {
      i = source.indexOf('\n', i);
      if (i < 0) return -1;
      continue;
    }
    if (c === '/' && next === '*') {
      i = source.indexOf('*/', i) + 2;
      continue;
    }
    if (c === "'" || c === '"') {
      i = skipQuoted(source, i);
      continue;
    }
    if (c === '`') {
      i++;
      while (i < source.length) {
        if (source[i] === BACKSLASH) {
          i += 2;
          continue;
        }
        if (source[i] === '`') {
          i++;
          break;
        }
        if (source[i] === '$' && source[i + 1] === '{') {
          let braces = 1;
          i += 2;
          while (i < source.length && braces > 0) {
            if (source[i] === '{') braces++;
            else if (source[i] === '}') braces--;
            else if (source[i] === "'" || source[i] === '"' || source[i] === '`') {
              i = skipQuoted(source, i);
              continue;
            }
            i++;
          }
          continue;
        }
        i++;
      }
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

function collectCallSites(): CallSite[] {
  const marker = '$transaction(';
  const sites: CallSite[] = [];
  for (const file of listProductionSources(SRC_ROOT)) {
    const source = readFileSync(file, 'utf8');
    for (let idx = source.indexOf(marker); idx !== -1; idx = source.indexOf(marker, idx + 1)) {
      const open = idx + marker.length - 1;
      // A `$transaction(` quoted inside this module's own documentation is prose,
      // not a call. Documentation lives only in transaction-budget.ts, which has
      // no transactions of its own, so excluding the whole file is exact.
      if (file === join(SRC_ROOT, 'prisma', 'transaction-budget.ts')) continue;
      const end = findCallEnd(source, open);
      expect(end, `unterminated $transaction( in ${file}`).toBeGreaterThan(open);
      sites.push({
        file: relative(SRC_ROOT, file).split(sep).join('/'),
        line: source.slice(0, open).split('\n').length,
        argumentText: source.slice(open + 1, end),
      });
    }
  }
  return sites;
}

/**
 * True when the call names the shared budget, either by spreading the canonical
 * options object or by writing `maxWait:` against the canonical constant.
 *
 * A literal (`maxWait: 10_000`) is deliberately NOT accepted. A copied number
 * is how the ledger's correct value stayed trapped at one call site while the
 * other 41 ran on the default.
 */
function namesTheSharedBudget(site: CallSite): boolean {
  if (site.argumentText.includes(OPTIONS_CONSTANT)) return true;
  return new RegExp(`maxWait:\\s*${MAX_WAIT_CONSTANT}`).test(site.argumentText);
}

describe('TI-03 interactive-transaction acquisition budget', () => {
  const sites = collectCallSites();

  it('pins the configured budget, so Prisma’s implicit 2000 ms cannot silently return', () => {
    // The measured failure was at elapsed 2019 ms against exactly this default.
    expect(DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS).toBe(10_000);
    expect(DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS).not.toBe(2_000);
    expect(DEFAULT_INTERACTIVE_TRANSACTION_OPTIONS.maxWait).toBe(
      DEFAULT_INTERACTIVE_TRANSACTION_MAX_WAIT_MS
    );
  });

  it('governs acquisition only — the shared options carry no execution timeout', () => {
    // `timeout` is how long an ACQUIRED transaction may run. Folding one into the
    // shared default would quietly relax every transaction body in the service,
    // which is the change TI-03 was explicitly forbidden to make.
    expect(Object.keys(DEFAULT_INTERACTIVE_TRANSACTION_OPTIONS)).toEqual(['maxWait']);
  });

  it('found the call sites it claims to guard (the scan is not vacuous)', () => {
    // 43 sites existed when TI-03 landed. The floor guards against a broken
    // scanner silently passing; it is not an assertion about the exact count,
    // because new transactions are legitimate and new implicit ones are not.
    expect(sites.length).toBeGreaterThanOrEqual(40);
  });

  it('leaves no $transaction call on Prisma’s implicit default', () => {
    const implicit = sites.filter((site) => !namesTheSharedBudget(site));
    expect(
      implicit.map((site) => `${site.file}:${site.line}`),
      'these $transaction call sites inherit Prisma’s 2000 ms maxWait; pass ' +
        `${OPTIONS_CONSTANT} (or maxWait: ${MAX_WAIT_CONSTANT} alongside their own options)`
    ).toEqual([]);
  });

  it('keeps the two seams that already had an explicit budget reading the constant', () => {
    // These were the ONLY two explicit call sites before TI-03, and the ledger's
    // value is the one that was promoted. If either drifts back to a literal the
    // policy has forked again, which is the exact failure being corrected.
    const seams = [
      'modules/ledger/ledger.repository.ts',
      'modules/device-gateway/device-gateway.repository.ts',
    ];
    for (const seam of seams) {
      const source = readFileSync(join(SRC_ROOT, seam), 'utf8');
      expect(source, `${seam} should read the shared budget`).toContain(
        `maxWait: ${MAX_WAIT_CONSTANT}`
      );
      expect(source, `${seam} should not hard-code an acquisition budget`).not.toMatch(
        /maxWait:\s*\d/
      );
    }
  });
});
