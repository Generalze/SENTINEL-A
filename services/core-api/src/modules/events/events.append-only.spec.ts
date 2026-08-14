/* global __dirname -- CJS global; not in this repo's shared ESLint globals list (see common/http-types.ts for the same kind of gap) */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Acceptance criterion 5 (WP-04): "no .update(/.delete( on the Event model
 * anywhere" — except the two documented, narrow exceptions this module
 * relies on (see the class doc on events.repository.ts and on the `Event`
 * Prisma model): markPublished(id) and the receivedCount increment inside
 * recordDuplicateDelivery. This test makes that grep-level review check
 * automatic and enforced in CI rather than manual.
 *
 * It matches the actual Prisma delegate call shape (`.event.update(` /
 * `.event.delete(`), not the bare substrings ".update(" / ".delete(" —
 * several doc comments in this module quote those substrings in prose, and
 * a naive text match would trip on its own documentation.
 */
const MODULE_DIR = __dirname;
const MUTATION_PATTERN = /\.event\.(update|delete)\(/g;

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

describe('Event model append-only invariant', () => {
  const occurrences = findMutationCalls(listSourceFiles(MODULE_DIR));

  it('never calls .event.delete( anywhere in the module', () => {
    const deletes = occurrences.filter((o) => o.kind === 'delete');
    expect(deletes).toEqual([]);
  });

  it('calls .event.update( in exactly two places, both in events.repository.ts (markPublished + receivedCount increment)', () => {
    const updates = occurrences.filter((o) => o.kind === 'update');
    expect(updates).toHaveLength(2);
    for (const occurrence of updates) {
      expect(occurrence.file.endsWith('events.repository.ts')).toBe(true);
    }
  });
});
