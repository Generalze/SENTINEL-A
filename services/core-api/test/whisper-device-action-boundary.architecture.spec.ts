import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * WP-27 — the SOURCE half of the v2 device-action boundary guard.
 *
 * WP-25's `device-gateway-boundary.architecture.spec.ts` asserts that the
 * gateway imports nothing from `../whisper/` and never names
 * `WHISPER_DEVICE_KEY_RESOLVER`. WP-27 makes the gateway depend on a NEW module
 * — `whisper-device-action` — and an indirection is only a boundary if the far
 * side is guarded too. Without this file, D25-07's prohibition could be honoured
 * by the gateway and broken one import away from it.
 *
 * Every question below is an ABSENCE claim, which is exactly what a behavioural
 * test cannot answer honestly: it can only prove that the paths it happens to
 * call do not do these things, never that no such path exists.
 *
 *   1. Does the v2 module import, name or re-wire the FROZEN Whisper v1 runtime
 *      — the service, the verifier, the resolver token, or the v1 contract
 *      symbols (D25-07 / the WP-27 freeze)?
 *   2. Does it name Ed25519, or admit an algorithm union?
 *   3. Does it coerce the genuine `AuthenticatedDeviceContext` into
 *      `AuthenticatedWhisperDeviceContext`?
 *   4. Does it open an HTTP surface of its own?
 *   5. Does it build a second replay store, or a second freshness ceiling?
 *   6. Does the GATEWAY still import nothing from `../whisper/` now that it
 *      imports the v2 module?
 */

const CORE_API_SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const V2_DIR = join(CORE_API_SRC, 'modules', 'whisper-device-action');
const GATEWAY_DIR = join(CORE_API_SRC, 'modules', 'device-gateway');

/** Strips line and block comments so prose about a prohibition stays legal. */
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

const v2Files = collectTypeScriptFiles(V2_DIR);
const v2Source = v2Files.filter((file) => !file.endsWith('.spec.ts'));
const gatewaySource = collectTypeScriptFiles(GATEWAY_DIR).filter((file) => !file.endsWith('.spec.ts'));

describe('WP-27 the v2 module exists and is actually scanned', () => {
  it('found the module, so an empty scan cannot pass forever', () => {
    // The lesson the security-source gate learned the hard way: a guard that
    // silently stops looking is worse than no guard, because it reads as
    // evidence.
    expect(v2Source.length).toBeGreaterThanOrEqual(4);
    for (const required of [
      'whisper-device-action.service.ts',
      'whisper-device-action.key-resolver.ts',
      'whisper-device-action.module.ts',
      'whisper-device-action.constants.ts',
    ]) {
      expect(v2Source.some((file) => file.endsWith(required)), required).toBe(true);
    }
  });
});

describe('WP-27/D25-07 the v2 path never touches the FROZEN Whisper v1 runtime', () => {
  it('imports nothing from the v1 module', () => {
    for (const file of v2Source) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(body.includes("from '../whisper/"), file).toBe(false);
      expect(body.includes('WHISPER_DEVICE_KEY_RESOLVER'), file).toBe(false);
      expect(body.includes('WhisperSignatureVerifier'), file).toBe(false);
      expect(body.includes('FailClosedWhisperDeviceKeyResolver'), file).toBe(false);
      expect(body.includes('WhisperService'), file).toBe(false);
      expect(body.includes('WhisperRepository'), file).toBe(false);
    }
  });

  it('names no v1 contract symbol, so a v1 statement cannot be built or judged here', () => {
    for (const file of v2Source) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      for (const v1Symbol of [
        'DeviceActionWhisperResultSchema',
        'canonicalWhisperSignedStatement',
        'whisperRecognitionFingerprint',
        'deviceActionWhisperReplayIdentity',
        'deviceActionWhisperReplayKey',
        'evaluateWhisperRuntimeEligibility',
        'WHISPER_SIGNATURE_ALGORITHM',
        'AuthenticatedWhisperDeviceContext',
      ]) {
        expect(body.includes(v1Symbol), `${file} names ${v1Symbol}`).toBe(false);
      }
    }
  });

  it('names no Ed25519 and admits no algorithm union', () => {
    for (const file of v2Source) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(/ed25519/iu.test(body), file).toBe(false);
      // An `Ed25519 | P256` union in any spelling is the one shape the freeze
      // forbids: the moment two algorithms share a decision, something chooses
      // between them, and whatever chooses can be steered.
      expect(/P256[^\n]*\|[^\n]*Ed|Ed[^\n]*\|[^\n]*P256/iu.test(body), file).toBe(false);
    }
  });

  it('never invokes the v1 recognition seam', () => {
    const invocation = /(?:\?\.|\.)\s*recognise\s*(?:\(|\.\s*(?:call|apply|bind)\s*\()/u;
    for (const file of [...v2Source, ...gatewaySource]) {
      expect(invocation.test(withoutComments(readFileSync(file, 'utf8'))), file).toBe(false);
    }
    // The tripwire is not decoration.
    expect(invocation.test('return this.whisper.recognise(context, body, principal);')).toBe(true);
  });
});

describe('WP-27 the genuine device context is never coerced into another module’s context type', () => {
  it('no file anywhere coerces a value into the v1 AuthenticatedWhisperDeviceContext', () => {
    // `as X`, `as unknown as X` and a bare `<X>` cast are the three shapes such
    // a coercion could take, and the union below catches all three. The
    // security-source gate already bans `as any`.
    const coercion = /(?:as\s+(?:unknown\s+as\s+)?|<\s*)AuthenticatedWhisperDeviceContext/u;
    for (const file of [...v2Source, ...gatewaySource]) {
      expect(coercion.test(withoutComments(readFileSync(file, 'utf8'))), file).toBe(false);
    }
    for (const shape of [
      'const ctx = row as AuthenticatedWhisperDeviceContext;',
      'const ctx = context as unknown as AuthenticatedWhisperDeviceContext;',
      'const ctx = <AuthenticatedWhisperDeviceContext>context;',
    ]) {
      expect(coercion.test(shape), shape).toBe(true);
    }
  });

  it('the v2 module launders no type through `unknown` at all', () => {
    // Narrower than the rule above and deliberately absolute for this module:
    // every value it handles is either parsed by a contract schema or is a
    // server-established row, so there is nothing here that a cast could
    // legitimately be needed for. (The WP-25 adapters DO carry
    // `semanticPayload as unknown as FieldStateSemanticPayload` casts, which
    // are a different thing — a payload the envelope already parsed strictly,
    // re-typed at its use site — and are outside this rule.)
    for (const file of v2Source) {
      expect(/as\s+unknown\s+as/u.test(withoutComments(readFileSync(file, 'utf8'))), file).toBe(false);
    }
  });
});

describe('WP-27 the v2 module has no HTTP surface of its own', () => {
  it('declares no controller, no route decorator and no socket ingress', () => {
    for (const file of v2Source) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(/@Controller\s*\(/u.test(body), file).toBe(false);
      expect(/@(?:Post|Get|Put|Patch|Delete)\s*\(/u.test(body), file).toBe(false);
      expect(/@(?:WebSocketGateway|SubscribeMessage|WebSocketServer)\s*\(/u.test(body), file).toBe(false);
      expect(body.includes("from '@nestjs/websockets'"), file).toBe(false);
    }
    expect(v2Source.some((file) => file.endsWith('.controller.ts'))).toBe(false);
  });
});

describe('WP-27 there is no second replay store and no second freshness opinion', () => {
  it('spends Shield’s ONE store, under its own ceremony label, declared once', () => {
    const declarations = v2Source.filter((file) =>
      withoutComments(readFileSync(file, 'utf8')).includes('WHISPER_DEVICE_ACTION_V2_CEREMONY = '),
    );
    expect(declarations.map((file) => relative(CORE_API_SRC, file))).toEqual([
      relative(CORE_API_SRC, join(V2_DIR, 'whisper-device-action.constants.ts')),
    ]);
    const service = withoutComments(readFileSync(join(V2_DIR, 'whisper-device-action.service.ts'), 'utf8'));
    expect(service).toContain('DeviceReplayService');
    // A raw write to the consumption table would be a second implementation of
    // the one security decision D24-11 owns.
    expect(/deviceNonceConsumption\s*[.?]/u.test(service)).toBe(false);
    expect(/INSERT\s+INTO\s+"?device_nonce_consumptions"?/iu.test(service)).toBe(false);
  });

  it('restates no frozen timing ceiling as a literal', () => {
    // 120_000 and 5_000 are `whisper.ts`'s; 300_000, 60_000 and 5_000 are the
    // device contract's. A copy in a service is a second freshness opinion.
    for (const file of v2Source) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      for (const literal of ['120_000', '120000', '300_000', '300000', '60_000', '60000', '5_000']) {
        expect(body.includes(literal), `${file} contains ${literal}`).toBe(false);
      }
    }
  });

  it('creates no new Prisma model of its own — WP-27 adds no migration', () => {
    const migrations = join(CORE_API_SRC, '..', 'prisma', 'schema', 'migrations');
    const directories = readdirSync(migrations).filter((entry) => statSync(join(migrations, entry)).isDirectory());
    expect(directories.length, 'WP-27 adds no migration; replay reuses Shield’s DeviceNonceConsumption').toBe(23);
  });
});

describe('WP-27 the gateway still imports nothing from the frozen v1 module', () => {
  it('depends on the v2 module and on no v1 symbol', () => {
    const module = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.module.ts'), 'utf8'));
    expect(module).toContain('WhisperDeviceActionModule');
    for (const file of gatewaySource) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(body.includes("from '../whisper/"), file).toBe(false);
      expect(body.includes('WHISPER_DEVICE_KEY_RESOLVER'), file).toBe(false);
      expect(/ed25519/iu.test(body), file).toBe(false);
    }
  });

  it('the route, the purpose and the required action are chosen by SERVER-owned tables', () => {
    const envelope = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.envelope.ts'), 'utf8'));
    expect(envelope).toContain("DEVICE_ACTION: 'WHISPER_DEVICE_ACTION'");
    expect(envelope).toContain("DEVICE_ACTION: 'whisper.device-action.invoke'");
    expect(envelope).toContain("DEVICE_ACTION: 'DEVICE_ACTION_STATEMENT'");
    // The purpose is read from the table, never spelled at the decision site.
    const service = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.service.ts'), 'utf8'));
    expect(service).toContain('DEVICE_GATEWAY_PURPOSE_FOR_KIND[input.kind]');
    expect(service).toContain('deviceGatewayPermittedTrustFor(input.kind)');
    expect(service.includes("expectedPurpose: 'FIELD_OPERATION'")).toBe(false);
    // And the controller's route carries no signal identifier.
    const controller = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.controller.ts'), 'utf8'));
    expect(controller).toContain("@Post('operations/device-action')");
    expect(/@Post\('operations\/device-action\/:/u.test(controller)).toBe(false);
  });
});
