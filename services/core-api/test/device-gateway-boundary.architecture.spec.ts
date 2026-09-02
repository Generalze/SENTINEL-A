import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * WP-25 — the SOURCE half of the device-gateway boundary guard.
 *
 * Its sibling, `src/modules/device-gateway/device-gateway.acceptance.integration.spec.ts`,
 * drives the live services against real Postgres and proves what the gateway
 * DOES. This one asks the questions a behavioural test cannot answer honestly,
 * because every one of them is an ABSENCE claim:
 *
 *   1. Is there any code path AT ALL that could mutate or erase a gateway
 *      operation event (D25-13)?
 *   2. Does the gateway reach into Field or Field Messaging REPOSITORIES
 *      instead of calling their services (D25-16)?
 *   3. Does it construct an assignment action other than accept or decline
 *      (D25-10)?
 *   4. Does it wire itself to the frozen Whisper device-key resolver (D25-07)?
 *   5. Does it open a device WebSocket ingress path (D25-10)?
 *   6. Does ANY route in it exempt itself from human authentication, or file an
 *      audit row under a tenant the REQUEST named (C17-01 / C17-02)?
 *
 * A behavioural test can only prove that the paths it happens to call do not do
 * these things. It cannot prove the absence of a path. So this is a pure source
 * scan: no stack, no database, nothing to race — the same discipline, and the
 * same reasoning, as `shield-append-only.architecture.spec.ts` and
 * `whisper-boundary.architecture.spec.ts`.
 */

const CORE_API_SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const GATEWAY_DIR = join(CORE_API_SRC, 'modules', 'device-gateway');

/** The one model whose rows are HISTORY and may only ever be appended to. */
const APPEND_ONLY_MODEL = 'deviceGatewayOperationEvent';
const APPEND_ONLY_TABLE = 'device_gateway_operation_events';

/**
 * A Prisma mutation call against the event model, in the shapes a caller could
 * plausibly reach it by. `create` is deliberately ABSENT: an append is the one
 * legal write, and banning it would ban the audit trail.
 */
const PRISMA_EVENT_MUTATION = new RegExp(
  `(?:\\?\\.|\\.)\\s*${APPEND_ONLY_MODEL}\\s*(?:\\?\\.|\\.)\\s*(?:update|updateMany|delete|deleteMany|upsert)\\s*\\(`,
  'u',
);

/** The same prohibition at the SQL level, which bypasses Prisma's model API entirely. */
const RAW_EVENT_MUTATION = new RegExp(`(?:UPDATE|DELETE\\s+FROM|TRUNCATE)\\s+"?${APPEND_ONLY_TABLE}"?`, 'iu');

/**
 * The repository imports D25-16 forbids.
 *
 * The gateway calls domain SERVICES. Importing a Field or Field Messaging
 * REPOSITORY would be the gateway acquiring the ability to write a Field row,
 * reconstruct DELIVERED -> ACKNOWLEDGED or create a Field audit/outbox row
 * itself — which is the ownership leakage the CTO ruling explicitly is not.
 */
const FORBIDDEN_REPOSITORY_IMPORT = /from\s+'[^']*(?:field|field-messaging)\/[a-z-]*\.repository(?:\.js)?'/u;

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

const gatewayFiles = collectTypeScriptFiles(GATEWAY_DIR);
const gatewaySource = gatewayFiles.filter((file) => !file.endsWith('.spec.ts'));

describe('WP-25/D25-13 the gateway audit is append-only in source', () => {
  it('actually found the module, so an empty scan cannot pass forever', () => {
    // The lesson the security-source gate learned the hard way: a guard that
    // silently stops looking is worse than no guard, because it reads as
    // evidence.
    expect(gatewaySource.length).toBeGreaterThan(8);
    for (const required of [
      'device-gateway.repository.ts',
      'device-gateway.service.ts',
      'device-context.service.ts',
      'device-gateway.controller.ts',
      'device-gateway.module.ts',
    ]) {
      expect(gatewaySource.some((file) => file.endsWith(required)), required).toBe(true);
    }
  });

  it('no gateway source updates, deletes or upserts a gateway operation event', () => {
    const offenders = gatewaySource.filter((file) => PRISMA_EVENT_MUTATION.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('no gateway source issues raw SQL that mutates or erases the event table', () => {
    const offenders = gatewaySource.filter((file) => RAW_EVENT_MUTATION.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('the repository still WRITES events — the guard bans mutation, not the audit trail', () => {
    const repository = readFileSync(join(GATEWAY_DIR, 'device-gateway.repository.ts'), 'utf8');
    expect(repository).toContain('deviceGatewayOperationEvent.create');
  });

  it('the tripwire fires on the shapes a future edit could reach a mutation by', () => {
    for (const shape of [
      'await tx.deviceGatewayOperationEvent.update({ where: { id }, data: {} });',
      'await this.prisma.deviceGatewayOperationEvent.deleteMany({ where: { organisationId } });',
      'await db.deviceGatewayOperationEvent.upsert({ where: {}, create: {}, update: {} });',
      'await tx?.deviceGatewayOperationEvent?.delete({ where: { id } });',
    ]) {
      expect(PRISMA_EVENT_MUTATION.test(shape), shape).toBe(true);
    }
    for (const shape of [
      'Prisma.sql`UPDATE device_gateway_operation_events SET payload = ...`',
      'Prisma.sql`DELETE FROM "device_gateway_operation_events" WHERE id = ...`',
      'Prisma.sql`TRUNCATE device_gateway_operation_events`',
    ]) {
      expect(RAW_EVENT_MUTATION.test(shape), shape).toBe(true);
    }
    for (const legal of [
      'await db.deviceGatewayOperationEvent.create({ data });',
      'await this.prisma.deviceGatewayOperationEvent.findMany({ where: { organisationId } });',
      'Prisma.sql`SELECT * FROM device_gateway_operation_events`',
    ]) {
      expect(PRISMA_EVENT_MUTATION.test(withoutComments(legal)), legal).toBe(false);
      expect(RAW_EVENT_MUTATION.test(withoutComments(legal)), legal).toBe(false);
    }
  });
});

describe('WP-25/D25-16 the gateway calls domain SERVICES, never their repositories', () => {
  it('nothing in the gateway imports a Field or Field Messaging repository', () => {
    const offenders = gatewaySource.filter((file) => FORBIDDEN_REPOSITORY_IMPORT.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('the tripwire fires on the import shapes that would breach the boundary', () => {
    for (const shape of [
      "import { FieldRepository } from '../field/field.repository';",
      "import { FieldMessagingRepository } from '../field-messaging/field-messaging.repository';",
      "import type { StateInput } from '../field/field.repository.js';",
    ]) {
      expect(FORBIDDEN_REPOSITORY_IMPORT.test(shape), shape).toBe(true);
    }
    for (const legal of [
      "import { FieldService } from '../field/field.service';",
      "import { FieldMessagingService } from '../field-messaging/field-messaging.service';",
      "import { DeviceGatewayRepository } from './device-gateway.repository';",
      "import { ShieldRepository } from '../shield/shield.repository';",
    ]) {
      expect(FORBIDDEN_REPOSITORY_IMPORT.test(legal), legal).toBe(false);
    }
  });

  it('nothing in the gateway writes a Field or Field Messaging table through Prisma', () => {
    // The other half of the same rule. Importing a service and then reaching
    // for `tx.fieldAssignment.update` would satisfy the import scan above and
    // still be the gateway implementing Field's rules.
    const forbiddenModels =
      /(?:\?\.|\.)\s*(?:fieldAssignment|fieldOperativeCurrentState|fieldOperativeStateHistory|fieldAuditLog|fieldOutbox|fieldAssignmentActionIdempotency|fieldStateUpdateIdempotency|incidentFieldMessage|incidentFieldMessageRecipient|incidentFieldMessageOutbox|incidentFieldMessageActionIdempotency|incidentTimelineEntry)\s*(?:\?\.|\.)/u;
    const offenders = gatewaySource.filter((file) => forbiddenModels.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
    expect(forbiddenModels.test('await tx.fieldAssignment.update({});')).toBe(true);
    expect(forbiddenModels.test('await db.incidentFieldMessageRecipient.updateMany({});')).toBe(true);
  });
});

describe('WP-25/D25-10 the reachable assignment actions are accept and decline, and no others', () => {
  it('no gateway source constructs start, complete, cancel or reassign', () => {
    const forbidden = /'(?:start|complete|cancel|reassign)'/u;
    const offenders = gatewaySource.filter((file) => forbidden.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('the action table names exactly two actions', () => {
    const envelope = readFileSync(join(GATEWAY_DIR, 'device-gateway.envelope.ts'), 'utf8');
    expect(envelope).toContain("ASSIGNMENT_ACCEPT: 'accept'");
    expect(envelope).toContain("ASSIGNMENT_DECLINE: 'decline'");
  });
});

describe('WP-25/D25-07 the gateway is not the physical-device Whisper path', () => {
  it('nothing in the gateway names the frozen Whisper device-key resolver or imports Whisper', () => {
    // `WHISPER_DEVICE_KEY_RESOLVER` verifies Ed25519 under frozen Whisper v1;
    // the Shield registry holds P-256 under the M3 profile. WP-25 is the first
    // work package with the technical means to break this prohibition, so the
    // scan matters more here than it did in Shield. Comments are stripped
    // first: prose about a prohibition must stay legal.
    for (const file of gatewaySource) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(body.includes('WHISPER_DEVICE_KEY_RESOLVER'), file).toBe(false);
      expect(body.includes("from '../whisper/"), file).toBe(false);
    }
  });
});

describe('WP-25/D25-10 REST only — there is no device socket ingress', () => {
  it('nothing in the gateway declares a WebSocket gateway or subscribes to a message', () => {
    for (const file of gatewaySource) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(/@(?:WebSocketGateway|SubscribeMessage|WebSocketServer)\s*\(/u.test(body), file).toBe(false);
      expect(body.includes("from '@nestjs/websockets'"), file).toBe(false);
      expect(body.includes("from 'socket.io'"), file).toBe(false);
    }
  });

  it('the module imports Field, Field Messaging, Shield and Prisma, and nothing realtime', () => {
    const module = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.module.ts'), 'utf8'));
    for (const required of ['FieldModule', 'FieldMessagingModule', 'ShieldModule', 'PrismaModule']) {
      expect(module.includes(required), required).toBe(true);
    }
    expect(module.includes('RealtimeModule')).toBe(false);
  });
});

describe('WP-25/D25-12 the frozen timing constants are imported, never restated', () => {
  it('no gateway source spells a frozen ceiling as a literal', () => {
    // 300_000, 60_000 and 5_000 belong to the contracts. A copy in a service is
    // a second freshness opinion, and D25-12 forbids acquiring one. The single
    // approved WP-25 ceiling has its own name and lives in one file.
    for (const file of gatewaySource) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      for (const literal of ['300_000', '300000', '60_000', '60000']) {
        expect(body.includes(literal), `${file} contains ${literal}`).toBe(false);
      }
    }
  });

  it('the one new ceiling is declared exactly once, in the constants file', () => {
    const declarations = gatewaySource.filter((file) =>
      withoutComments(readFileSync(file, 'utf8')).includes('DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS = '),
    );
    expect(declarations.map((file) => relative(CORE_API_SRC, file))).toEqual([
      relative(CORE_API_SRC, join(GATEWAY_DIR, 'device-gateway.constants.ts')),
    ]);
  });
});

describe('WP-25/C17-01 no gateway route exempts itself from human authentication', () => {
  it('nothing in the gateway declares @Public() or imports the decorator', () => {
    // A behavioural test can only prove that the routes it happens to call
    // require a session. It cannot prove that the SIXTH route somebody adds
    // next quarter does, and `@Public()` is a one-line edit with no visible
    // consequence at the call site. So the absence is asserted as a source fact.
    //
    // The prohibition is absolute HERE and nowhere else: `@Public()` is
    // legitimate on liveness probes and is used elsewhere in this service. What
    // it may never mark is a route that consumes a device possession proof,
    // because on such a route it removes the SECOND PRINCIPAL - and the two
    // principals are the whole of §62.1.
    for (const file of gatewaySource) {
      const body = withoutComments(readFileSync(file, 'utf8'));
      expect(/@Public\s*\(/u.test(body), file).toBe(false);
      expect(/\bPublic\b[^\n]*from\s+'[^']*requires-action\.decorator'/u.test(body), file).toBe(false);
    }
  });

  it('every effect-causing route reads the authenticated principal', () => {
    const controller = withoutComments(readFileSync(join(GATEWAY_DIR, 'device-gateway.controller.ts'), 'utf8'));
    for (const route of [
      "@Post('contexts/establishment')",
      "@Post('contexts')",
      "@Post('operations/field-state')",
      "@Post('operations/assignments/:id/accept')",
      "@Post('operations/assignments/:id/decline')",
      "@Post('operations/messages/:id/acknowledge')",
    ]) {
      expect(controller.includes(route), route).toBe(true);
    }
    // The six routes, and exactly two handlers that reach a service without
    // going through `run` - so three `requirePrincipal` call sites cover all six.
    expect(controller.split('requirePrincipal(req)').length - 1).toBe(3);
    // The principal is PASSED, never re-derived inside the services.
    expect(controller).toContain('this.gateway.execute(principal,');
    expect(controller).toContain('this.contexts.completeEstablishment(principal,');
    expect(controller).toContain('this.contexts.requestEstablishment(principal,');
  });

  it('the tripwire fires on the shapes a future edit could reach an exemption by', () => {
    for (const shape of ['@Public()', '@Public ()', "import { Public } from '../../common/security/requires-action.decorator';"]) {
      const publicDecorator = /@Public\s*\(/u.test(shape);
      const publicImport = /\bPublic\b[^\n]*from\s+'[^']*requires-action\.decorator'/u.test(shape);
      expect(publicDecorator || publicImport, shape).toBe(true);
    }
    expect(/@Public\s*\(/u.test("@Post('contexts')")).toBe(false);
  });
});

describe('WP-25/C17-02 no lookup and no audit row is anchored on a claimed tenant', () => {
  /**
   * `proof.organisation_id` is a CLAIM. It may be equality-bound against a
   * persisted row, and it may appear in an internal refusal reason. It may never
   * SELECT a row or OWN an audit event - the gateway audit has no lifecycle
   * foreign key, so write-time provenance is the only provenance it has, and a
   * tenant an attacker merely named must not be able to acquire it.
   */
  const CLAIMED_TENANT_AS_ANCHOR =
    /(?:find|lock|list)[A-Za-z]*\(\s*(?:tx\s*,\s*)?proof\.organisation_id|organisationId:\s*proof\.organisation_id|organisationId:\s*input\.organisationId/u;

  it('no gateway source uses a claimed organisation as a lookup or audit anchor', () => {
    const offenders = gatewaySource.filter((file) => CLAIMED_TENANT_AS_ANCHOR.test(withoutComments(readFileSync(file, 'utf8'))));
    expect(offenders.map((file) => relative(CORE_API_SRC, file))).toEqual([]);
  });

  it('the tripwire fires on the exact shapes C17-02 found', () => {
    for (const shape of [
      'const contextRow = await this.repository.findContext(proof.organisation_id, proof.context_id);',
      'await this.repository.lockEstablishmentChallenge(tx, proof.organisation_id, id);',
      'this.replay.peek(tx, { organisationId: proof.organisation_id, replayKey })',
      'appendOperationEventOutsideTransaction({ organisationId: input.organisationId, contextId: null })',
    ]) {
      expect(CLAIMED_TENANT_AS_ANCHOR.test(shape), shape).toBe(true);
    }
    for (const legal of [
      'const contextRow = await this.repository.findContext(principal.organisation_id, proof.context_id);',
      'if (proof.organisation_id !== contextRow.organisationId) return refuse();',
      'organisationId: contextRow.organisationId,',
      'organisationId: auditOrganisationId,',
    ]) {
      expect(CLAIMED_TENANT_AS_ANCHOR.test(legal), legal).toBe(false);
    }
  });
});
