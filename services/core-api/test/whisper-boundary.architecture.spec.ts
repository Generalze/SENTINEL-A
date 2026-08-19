import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * WP-22/C13-02b — the SOURCE half of the Whisper boundary guard.
 *
 * Its sibling in `m2-field-loop.integration.spec.ts` reads the live route
 * table and pins the public `/api/v1/whisper/**` surface to exactly the seven
 * Studio routes, rejecting any path shaped like recognition. That catches a
 * route someone *names* like the thing it does.
 *
 * It does not catch a route that hides what it does. A neutral-looking
 * endpoint —
 *
 *   POST /api/v1/field/help  ->  whisperService.recognise(...)
 *
 * — passes the `/whisper/**` whitelist (it is not under whisper) and passes
 * the `/recogni|invoke|device-action/i` path scan (its path says none of
 * those), while exposing the exact seam B11-08 forbids: device-action
 * recognition reachable over HTTP without an authenticated device identity.
 *
 * So the two guards are deliberately independent and neither replaces the
 * other: one asks "what is registered?", this one asks "what may a controller
 * call?". The prohibition is narrow and specific — a controller may keep
 * depending on `WhisperService` for Studio operations, which the real
 * `WhisperController` does. It may not invoke `recognise()`.
 *
 * This is a pure source scan: no stack, no database, nothing to race.
 */

// Lives in `test/` alongside the security-source gate, the repo's other pure
// source-level guard, rather than beside the heavy live integration spec — a
// scan that needs no stack should not be booting an app in parallel with one.
const CORE_API_SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** Every `*.controller.ts` under core-api's source tree. */
function collectControllerFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    const full = join(directory, entry);
    if (statSync(full).isDirectory()) {
      found.push(...collectControllerFiles(full));
      continue;
    }
    if (entry.endsWith('.controller.ts') && !entry.endsWith('.spec.ts')) found.push(full);
  }
  return found;
}

/**
 * An invocation of the recognition seam, in any of the shapes a controller
 * could plausibly reach it by: `x.recognise(`, `x?.recognise(`, and
 * `recognise.call/apply/bind`. Deliberately matches the CALL, not the word —
 * a comment explaining why recognition has no route must stay legal.
 */
const RECOGNISE_INVOCATION = /(?:\?\.|\.)\s*recognise\s*(?:\(|\.\s*(?:call|apply|bind)\s*\()/u;

/** Strips line and block comments so prose about the seam cannot trip the scan. */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/(^|[^:])\/\/[^\n]*/gu, '$1');
}

describe('WP-22/C13-02b Whisper recognition has no controller surface', () => {
  const controllers = collectControllerFiles(CORE_API_SRC);

  it('actually found the controllers, so an empty scan cannot pass forever', () => {
    // The same lesson as the route-table guard: a guard that silently stops
    // looking is worse than no guard, because it reads as evidence.
    expect(controllers.length).toBeGreaterThan(5);
    expect(controllers.some((file) => file.endsWith('whisper.controller.ts'))).toBe(true);
  });

  it('no controller invokes the internal recognise() seam', () => {
    const offenders = controllers.filter((file) => RECOGNISE_INVOCATION.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => file.replace(CORE_API_SRC, ''))).toEqual([]);
  });

  it('the Whisper controller may still depend on WhisperService for Studio work', () => {
    // The prohibition is precise. Banning the dependency outright would be
    // both wrong and easy to route around; banning the CALL is the property
    // that matters.
    const whisperController = controllers.find((file) => file.endsWith('whisper.controller.ts'));
    expect(whisperController).toBeDefined();
    const source = readFileSync(whisperController as string, 'utf8');
    expect(source).toContain('WhisperService');
    expect(RECOGNISE_INVOCATION.test(withoutComments(source))).toBe(false);
  });

  it('the tripwire fires on the shapes a controller could reach the seam by', () => {
    // Proving the guard is not vacuous. If these stop matching, the scan above
    // has quietly become decoration.
    for (const shape of [
      'return this.whisper.recognise(context, body, principal);',
      'await this.whisper?.recognise(context, body, principal);',
      'this.whisper.recognise.call(this.whisper, context, body, principal);',
    ]) {
      expect(RECOGNISE_INVOCATION.test(shape), shape).toBe(true);
    }
    // And that prose about the seam remains legal.
    for (const legal of [
      '// recognise() is deliberately internal: there is no route.',
      '/** The recognise seam has no HTTP surface (B11-08). */',
      'const recognised = await somethingElse(input);',
    ]) {
      expect(RECOGNISE_INVOCATION.test(withoutComments(legal)), legal).toBe(false);
    }
  });
});
