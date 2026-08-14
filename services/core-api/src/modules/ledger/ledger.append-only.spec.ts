/* global __dirname -- CJS global; not in this repo's shared ESLint globals list (see events.append-only.spec.ts for the same kind of gap) */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Acceptance criterion 1 (WP-08): "no update/delete path exists (review grep + test that the
 * service surface has no such method)". Unlike the Event model (which has two narrow, documented
 * mutation exceptions), the Decision Ledger has NONE — append-only means append-only. This test
 * mirrors events.append-only.spec.ts's automated-source-scan pattern exactly, but asserts zero
 * occurrences rather than an exhaustive documented list.
 *
 * Matches the actual Prisma delegate call shape (`.decisionLedgerEntry.update(` /
 * `.decisionLedgerEntry.delete(`), not the bare substrings ".update("/".delete(" — several doc
 * comments in this module quote those substrings in prose, and a naive text match would trip on
 * its own documentation.
 */
const MODULE_DIR = __dirname;
const MUTATION_PATTERN = /\.decisionLedgerEntry\.(update|delete)\(/g;

interface Occurrence {
  file: string;
  kind: 'update' | 'delete';
  line: number;
}

function listSourceFiles(dir: string): string[] {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listSourceFiles(fullPath));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts') && !entry.name.endsWith('.test.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

function findMutationCalls(files: string[]): Occurrence[] {
  const occurrences: Occurrence[] = [];
  for (const file of files) {
    const content = readFileSync(file, 'utf8');
    const lines = content.split('\n');
    lines.forEach((lineText, index) => {
      const matches = lineText.matchAll(MUTATION_PATTERN);
      for (const match of matches) {
        occurrences.push({ file, kind: match[1] as 'update' | 'delete', line: index + 1 });
      }
    });
  }
  return occurrences;
}

describe('DecisionLedgerEntry model append-only invariant', () => {
  const occurrences = findMutationCalls(listSourceFiles(MODULE_DIR));

  it('never calls .decisionLedgerEntry.update( anywhere in the module', () => {
    const updates = occurrences.filter((o) => o.kind === 'update');
    expect(updates).toEqual([]);
  });

  it('never calls .decisionLedgerEntry.delete( anywhere in the module', () => {
    const deletes = occurrences.filter((o) => o.kind === 'delete');
    expect(deletes).toEqual([]);
  });

  it('LedgerService and LedgerRepository expose no update/delete method on their public surface', async () => {
    const { LedgerService } = await import('./ledger.service');
    const { LedgerRepository } = await import('./ledger.repository');

    for (const ctor of [LedgerService, LedgerRepository]) {
      const methodNames = Object.getOwnPropertyNames(ctor.prototype).filter((name) => name !== 'constructor');
      const forbidden = methodNames.filter((name) => /update|delete|remove/i.test(name));
      expect(forbidden, `${ctor.name} exposes forbidden-looking method(s): ${forbidden.join(', ')}`).toEqual([]);
    }
  });
});
