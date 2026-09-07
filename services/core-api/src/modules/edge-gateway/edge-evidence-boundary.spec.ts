import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * M3B §12 / §14 — THE EDGE EVIDENCE PATH MAY NOT REACH THE DOMAIN-EFFECT PATH.
 *
 * WHY THIS IS A SOURCE TEST AND NOT A CODE REVIEW NOTE
 * ---------------------------------------------------
 * The rule this defends is a TRUST BOUNDARY, and it is one a single convenient
 * import would erase:
 *
 *     an authenticated EDGE is not an authenticated HUMAN
 *
 * `evaluateDeviceOperationPrincipals` refuses `USER_NOT_AUTHENTICATED` before
 * anything else, and the human-authenticated replay path is the only thing
 * allowed to satisfy it. If the evidence ingress ever calls that path -- even
 * "just to reuse the parsing" -- then whatever principal it passes becomes the
 * answer to "which human authorised this operation?", and the split the device
 * gateway exists to preserve is gone.
 *
 * Nothing in the type system prevents that import. A reviewer would have to
 * notice it. This notices it every run.
 *
 * IT ASSERTS ABSENCE, WHICH IS THE HARD KIND OF ASSERTION. A behavioural test
 * can only show that the effect did not happen in the cases it thought to try;
 * this shows the module cannot reach the machinery at all.
 */

// `import.meta.url` rather than `__dirname`: this package is ESM, and the lint
// rules say so. Resolving from the module's own URL keeps the test anchored to
// the directory it guards even if it is ever run from elsewhere.
const EDGE_GATEWAY_DIR = dirname(fileURLToPath(import.meta.url));

/**
 * The domain-effect entry points, by the names an import would have to use.
 *
 * `DeviceGatewayService.execute` is the effect transaction. The others are the
 * services that own a device's authoritative replay and cursor. An Edge that
 * could call any of them could cause a Field effect without a human.
 */
const FORBIDDEN_DOMAIN_SYMBOLS = [
  'DeviceGatewayService',
  'DeviceOfflineIngressService',
  'DeviceContextService',
  'FieldOfflineReplayService',
  'device-gateway.service',
  'device-offline-ingress.service',
] as const;

function edgeGatewaySources(): ReadonlyArray<{ file: string; text: string }> {
  return readdirSync(EDGE_GATEWAY_DIR)
    .filter((name) => name.endsWith('.ts') && !name.endsWith('.spec.ts'))
    .map((name) => ({ file: name, text: readFileSync(join(EDGE_GATEWAY_DIR, name), 'utf8') }));
}

/** Import statements only. A name inside a comment is documentation, not reach. */
function importLines(text: string): readonly string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('import ') || line.startsWith('} from ') || line.includes("require("));
}

describe('M3B §14 the Edge evidence ingress cannot reach the domain-effect path', () => {
  it('imports no device gateway or offline replay service', () => {
    for (const source of edgeGatewaySources()) {
      const imports = importLines(source.text).join('\n');
      for (const symbol of FORBIDDEN_DOMAIN_SYMBOLS) {
        expect(imports, `${source.file} must not import ${symbol}`).not.toContain(symbol);
      }
    }
  });

  it('the module declares no domain-effect provider', () => {
    const moduleText = readFileSync(join(EDGE_GATEWAY_DIR, 'edge-gateway.module.ts'), 'utf8');
    // `DeviceGatewayModule` would drag the effect path in transitively, which
    // is the same defect arriving through the module graph rather than through
    // an import line.
    expect(moduleText).not.toContain('DeviceGatewayModule');
    expect(moduleText).not.toContain('FieldOfflineModule');
  });

  it('nothing in the module writes a FieldOfflineOperationReceipt', () => {
    // That table is the AUTHORITATIVE replay record. An Edge observation must
    // never create one: doing so would let the party that delivered the
    // evidence also declare the operation replayed.
    for (const source of edgeGatewaySources()) {
      expect(source.text, `${source.file} must not write the authoritative replay record`).not.toMatch(
        /fieldOfflineOperationReceipt\s*\.\s*(create|upsert|update|delete)/,
      );
    }
  });

  it('the standing service only reads', () => {
    const text = readFileSync(join(EDGE_GATEWAY_DIR, 'edge-evidence-standing.service.ts'), 'utf8');
    // A standing lookup that could write would be a lookup that could settle an
    // operation nobody replayed.
    expect(text).not.toMatch(/\.(create|update|upsert|delete|createMany|updateMany|deleteMany)\s*\(/);
    expect(text).not.toContain('$transaction');
  });
});
