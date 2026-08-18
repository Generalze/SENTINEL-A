import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * Regression for the security source gate itself.
 *
 * The inline version of this gate was a false green for the entire life of the
 * pipeline: `ripgrep` is absent from the GitHub runner image, `if rg ...` read
 * the resulting exit 127 as "no matches", and `|| true` swallowed the rest. The
 * step reported success having scanned nothing. A gate that cannot distinguish
 * "found nothing" from "never ran" manufactures evidence, so the gate now needs
 * its own tests — otherwise the next silent breakage is invisible again.
 *
 * NOTE ON THIS FILE'S OWN VOCABULARY
 * ----------------------------------
 * This spec lives inside the tree the gate scans, so it cannot contain the
 * forbidden markers anywhere — not in fixture strings, not in identifiers, and
 * not in test titles. They are assembled at runtime instead and everything here
 * is worded around them. Spelling them out made the gate fail on its own test,
 * which was a pleasing demonstration that it works.
 */

/**
 * Walks upward from the working directory to find the gate. Avoids `__dirname`
 * (not in this project's eslint environment) and avoids hard-coding a depth, so
 * the spec works whether vitest runs from the package or the repository root.
 * Throws rather than silently skipping if the script cannot be found.
 */
function locateGate(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = join(dir, 'scripts', 'security-source-gate.sh');
    if (existsSync(candidate)) return candidate;
    dir = resolve(dir, '..');
  }
  throw new Error('security-source-gate.sh not found above ' + process.cwd());
}

const GATE = locateGate();

/**
 * Resolves bash absolutely where possible.
 *
 * The scanner-unavailable test removes PATH entries that provide `rg`, and on
 * Linux `rg` and `bash` share /usr/bin — so relying on PATH to find bash made
 * that test measure a spawn failure instead of the gate's exit code. Calling
 * bash by absolute path keeps the PATH edit meaning only "the scanner is
 * missing". Falls back to PATH lookup on platforms where these paths do not
 * exist (Git Bash on Windows).
 */
function resolveBash(): string {
  for (const candidate of ['/bin/bash', '/usr/bin/bash']) {
    if (existsSync(candidate)) return candidate;
  }
  return 'bash';
}

const BASH = resolveBash();

/** The deferred-work marker the gate rejects, assembled so it is not a literal here. */
const DEFERRED_MARKER = ['TO', 'DO'].join('');
/** The type-suppression directive the gate rejects, likewise assembled. */
const SUPPRESSION_DIRECTIVE = ['@ts', 'ignore'].join('-');
/** The loose type name, assembled so this file contains no annotation the gate would flag. */
const LOOSE_TYPE = ['a', 'ny'].join('');

interface GateResult {
  status: number;
  output: string;
}

function runGate(root: string, env: Record<string, string | undefined> = process.env): GateResult {
  try {
    const stdout = execFileSync(BASH, [GATE, root], { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, output: stdout };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? -1, output: `${failure.stdout ?? ''}${failure.stderr ?? ''}` };
  }
}

/**
 * Strips only the PATH entries that actually provide `rg`, so `bash` itself
 * stays reachable. Blanking PATH entirely would make the test prove that bash
 * is missing rather than that the scanner is.
 */
function pathWithoutScanner(): string {
  const separator = process.platform === 'win32' ? ';' : ':';
  return (process.env.PATH ?? '')
    .split(separator)
    .filter((entry) => entry.length > 0 && !existsSync(join(entry, 'rg')) && !existsSync(join(entry, 'rg.exe')))
    .join(separator);
}

const fixtures: string[] = [];

/** Every canonical root the gate requires. */
const REQUIRED_ROOTS = ['services', 'apps', 'packages', 'tests'] as const;

/**
 * Builds a throwaway tree containing ALL required roots, with one source file
 * under `services/`. The gate refuses a partially-present tree, so a fixture
 * that created only `services/` would now be indistinguishable from a broken
 * checkout.
 */
function fixture(fileName: string, contents: string, omit: readonly string[] = []): string {
  const root = mkdtempSync(join(tmpdir(), 'sentinel-gate-'));
  fixtures.push(root);
  for (const dir of REQUIRED_ROOTS) {
    if (!omit.includes(dir)) mkdirSync(join(root, dir), { recursive: true });
  }
  if (!omit.includes('services')) writeFileSync(join(root, 'services', fileName), contents, 'utf8');
  return root;
}

afterAll(() => {
  for (const root of fixtures) rmSync(root, { recursive: true, force: true });
});

describe('security source gate', () => {
  it('passes a clean tree', () => {
    const root = fixture('clean.ts', 'export const value: string = "ok";\n');
    const result = runGate(root);
    expect(result.status).toBe(0);
    // The log line is itself the evidence of scope, so pin it in full.
    expect(result.output).toContain('Security source gate passed: scanned services apps packages tests');
  });

  it('rejects a deferred-work marker', () => {
    const root = fixture('deferred.ts', `export const value = 1;\n// ${DEFERRED_MARKER}: finish this\n`);
    const result = runGate(root);
    expect(result.status).toBe(1);
    expect(result.output).toContain(`${DEFERRED_MARKER} marker or ${SUPPRESSION_DIRECTIVE} found`);
  });

  it('rejects a type-suppression directive', () => {
    const root = fixture('suppressed.ts', `// ${SUPPRESSION_DIRECTIVE}\nexport const value = 1;\n`);
    const result = runGate(root);
    expect(result.status).toBe(1);
    expect(result.output).toContain(`${DEFERRED_MARKER} marker or ${SUPPRESSION_DIRECTIVE} found`);
  });

  it('rejects a loosely typed annotation', () => {
    const root = fixture('loose.ts', `export function widen(input: ${LOOSE_TYPE}): void {
  void input;
}
`);
    const result = runGate(root);
    expect(result.status).toBe(1);
    expect(result.output).toContain('untyped any detected');
  });

  it('still allows the bare word in prose and the Vitest matcher', () => {
    const root = fixture('prose.ts', '// any of these values is fine\nexport const matcher = expect.any(String);\n');
    expect(runGate(root).status).toBe(0);
  });

  it('FAILS CLOSED when the scanner is unavailable, rather than reporting a pass', () => {
    // The exact defect this gate had in CI. A missing scanner must never be
    // indistinguishable from a clean scan.
    const root = fixture('clean.ts', 'export const value: string = "ok";\n');
    const result = runGate(root, { ...process.env, PATH: pathWithoutScanner() });
    expect(result.status).toBe(2);
    expect(result.output).toContain('CANNOT RUN');
    expect(result.output).not.toContain('passed');
  });

  it('FAILS CLOSED when ANY single required root is missing, not only when all are', () => {
    // The partial-omission false green: accepting whichever roots existed made
    // a tree missing one of them report a clean scan of the whole repository.
    for (const missing of REQUIRED_ROOTS) {
      const root = fixture('clean.ts', 'export const value: string = "ok";\n', [missing]);
      const result = runGate(root);
      expect(result.status, `omitting ${missing} must fail closed`).toBe(2);
      expect(result.output).toContain(`required source root '${missing}' is missing`);
      expect(result.output).not.toContain('passed');
    }
  });

  it('FAILS CLOSED when no expected source root exists', () => {
    const root = mkdtempSync(join(tmpdir(), 'sentinel-gate-empty-'));
    fixtures.push(root);
    const result = runGate(root);
    expect(result.status).toBe(2);
    expect(result.output).toContain('CANNOT RUN');
  });
});
