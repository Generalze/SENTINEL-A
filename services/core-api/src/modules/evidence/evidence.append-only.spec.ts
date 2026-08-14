/* global __dirname -- CJS global; not in this repo's shared ESLint globals list (see common/http-types.ts / events.append-only.spec.ts for the same kind of gap) */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Directive WP-09: "No update/delete on either model anywhere in the
 * codebase — enforce with an automated source-scan spec copied from the
 * events pattern." Same technique as events.append-only.spec.ts, but
 * unlike Event (which has two documented, narrow update exceptions), this
 * module's models have none: EvidenceRepository never touches an existing
 * Evidence or EvidenceCustodyEvent row after it's created.
 *
 * Matches the actual Prisma delegate call shape (`.evidence.update(` /
 * `.evidenceCustodyEvent.delete(` etc.), not the bare substrings
 * ".update(" / ".delete(" — several doc comments in this module quote
 * those substrings in prose, and a naive text match would trip on its own
 * documentation.
 */
const MODULE_DIR = __dirname;
const MUTATION_PATTERN = /\.(evidence|evidenceCustodyEvent)\.(update|delete)\(/g;

interface Occurrence {
  file: string;
  model: string;
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
        occurrences.push({ file, model: match[1], kind: match[2] as 'update' | 'delete', line: index + 1 });
      }
    });
  }
  return occurrences;
}

describe('Evidence / EvidenceCustodyEvent append-only invariant', () => {
  const occurrences = findMutationCalls(listSourceFiles(MODULE_DIR));

  it('never calls .evidence.update( anywhere in the module', () => {
    expect(occurrences.filter((o) => o.model === 'evidence' && o.kind === 'update')).toEqual([]);
  });

  it('never calls .evidence.delete( anywhere in the module', () => {
    expect(occurrences.filter((o) => o.model === 'evidence' && o.kind === 'delete')).toEqual([]);
  });

  it('never calls .evidenceCustodyEvent.update( anywhere in the module', () => {
    expect(occurrences.filter((o) => o.model === 'evidenceCustodyEvent' && o.kind === 'update')).toEqual([]);
  });

  it('never calls .evidenceCustodyEvent.delete( anywhere in the module', () => {
    expect(occurrences.filter((o) => o.model === 'evidenceCustodyEvent' && o.kind === 'delete')).toEqual([]);
  });
});
