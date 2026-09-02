import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * WP-26 — the SOURCE half of the device-enrollment-ingress boundary guard.
 *
 * Its sibling,
 * `src/modules/device-enrollment-ingress/device-enrollment-ingress.acceptance.integration.spec.ts`,
 * drives the live services against real Postgres and proves what the ingress
 * DOES. This one asks the questions a behavioural test cannot answer honestly,
 * because every one of them is an ABSENCE claim:
 *
 *   1. Does the ingress write a SHIELD table instead of calling a Shield
 *      service (D26-09)?
 *   2. Is there any code path at all that could mutate or erase an attestation
 *      artifact (D26-04B)?
 *   3. Can the raw certificate chain be READ anywhere but the one writer?
 *   4. Does any route on the mobile surface exempt itself from human
 *      authentication (C17-01)?
 *   5. Can the mobile surface approve anything (D26-01)?
 *   6. Is the session bound BEFORE anything enters Shield (C17-01/C17-02)?
 *   7. Does Shield still have zero controllers (D24-13/D26-09)?
 *   8. Did WP-26 acquire a background scheduler (D25-08)?
 *   9. Did it wire itself to the frozen Whisper resolver, or open a device
 *      socket (D26-07 / D25-10)?
 *  10. Did the test-only DER ENCODER leak into a production path?
 *
 * A behavioural test can only prove that the paths it happens to call do not do
 * these things. It cannot prove the absence of a path. So this is a pure source
 * scan: no stack, no database, nothing to race — the same discipline, and the
 * same reasoning, as `device-gateway-boundary.architecture.spec.ts`,
 * `shield-append-only.architecture.spec.ts` and
 * `whisper-boundary.architecture.spec.ts`.
 */

const CORE_API_SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const INGRESS_DIR = join(CORE_API_SRC, 'modules', 'device-enrollment-ingress');
const SHIELD_DIR = join(CORE_API_SRC, 'modules', 'shield');

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

const ingressFiles = collectTypeScriptFiles(INGRESS_DIR);
/**
 * PRODUCTION source: not a spec, and not the test-support builder.
 *
 * `android-attestation.test-support.ts` is the only DER *encoder* in the
 * module and it exists to build synthetic chains for the Crucible. It is
 * excluded here and then separately asserted to be unreachable from production
 * — an exclusion that is not itself checked is a hole.
 */
const productionSource = ingressFiles.filter((file) => !file.endsWith('.spec.ts') && !file.endsWith('.test-support.ts'));
const read = (file: string): string => withoutComments(readFileSync(file, 'utf8'));
const shortName = (file: string): string => relative(CORE_API_SRC, file);

describe('WP-26 the guard is actually looking at something', () => {
  it('found the module, so an empty scan cannot pass forever', () => {
    // The lesson the security-source gate learned the hard way: a guard that
    // silently stops looking is worse than no guard, because it reads as
    // evidence.
    expect(productionSource.length).toBeGreaterThan(7);
    for (const required of [
      'mobile-enrollment.controller.ts',
      'command-enrollment.controller.ts',
      'device-enrollment-ingress.service.ts',
      'device-enrollment-ingress.repository.ts',
      'device-enrollment-ingress.module.ts',
      'android-key-attestation.verifier.ts',
      'android-key-attestation.evaluator.ts',
      'android-attestation.der.ts',
      'android-attestation.trust-material.ts',
      'android-attestation.artifact-reader.ts',
    ]) {
      expect(
        productionSource.some((file) => file.endsWith(required)),
        required,
      ).toBe(true);
    }
  });
});

describe('WP-26/D26-09 the ingress calls Shield SERVICES, never its tables', () => {
  /**
   * Every Prisma model Shield owns. The ingress may read them only through an
   * exported Shield service — which is where the isolation rules, the §62
   * authority checks, the replay store and the security audit live. A module
   * that can write `enrollment_requests` itself is a module that can create an
   * approved enrollment nobody approved.
   */
  const SHIELD_MODELS =
    /(?:\?\.|\.)\s*(?:device|deviceKey|deviceSiteScope|deviceCustodyRegime|enrollmentRequest|enrollmentApproval|enrollmentBootstrapGrant|possessionChallenge|possessionVerification|deviceSecurityEvent|deviceTrustTransition|deviceAttestationObservation|deviceNonceConsumption|deviceKeyRotationRequest|deviceKeyRotationChallenge|deviceKeyRotationVerification)\s*(?:\?\.|\.)/u;

  it('no ingress source touches a Shield Prisma model', () => {
    const offenders = productionSource.filter((file) => SHIELD_MODELS.test(read(file)));
    expect(offenders.map(shortName)).toEqual([]);
  });

  it('the tripwire fires on the shapes a future edit could breach the boundary by', () => {
    for (const shape of [
      'await tx.enrollmentRequest.update({ where: { id }, data: {} });',
      'await this.prisma.device.create({ data });',
      'await db.enrollmentApproval.create({ data });',
      'await this.prisma?.deviceSecurityEvent?.create({ data });',
    ]) {
      expect(SHIELD_MODELS.test(shape), shape).toBe(true);
    }
    for (const legal of [
      'await this.prisma.deviceAttestationChallenge.create({ data });',
      'await this.prisma.androidKeyAttestationArtifact.create({ data });',
      'await this.enrollment.createEnrollmentRequest(submission);',
    ]) {
      expect(SHIELD_MODELS.test(legal), legal).toBe(false);
    }
  });

  it('nothing in the ingress imports a Shield repository', () => {
    const forbidden = /from\s+'[^']*shield\/shield\.repository(?:\.js)?'/u;
    const offenders = productionSource.filter((file) => forbidden.test(read(file)));
    expect(offenders.map(shortName)).toEqual([]);
    expect(forbidden.test("import { ShieldRepository } from '../shield/shield.repository';")).toBe(true);
  });
});

describe('WP-26/D26-04B the attestation artifact is append-only, and its raw chain is restricted', () => {
  const ARTIFACT_MUTATION =
    /(?:\?\.|\.)\s*androidKeyAttestationArtifact\s*(?:\?\.|\.)\s*(?:update|updateMany|delete|deleteMany|upsert)\s*\(/u;
  const RAW_ARTIFACT_MUTATION = /(?:UPDATE|DELETE\s+FROM|TRUNCATE)\s+"?android_key_attestation_artifacts"?/iu;

  it('no ingress source updates, deletes or upserts an attestation artifact', () => {
    const offenders = productionSource.filter((file) => ARTIFACT_MUTATION.test(read(file)));
    expect(offenders.map(shortName)).toEqual([]);
  });

  it('no ingress source issues raw SQL that mutates or erases the artifact table', () => {
    const offenders = productionSource.filter((file) => RAW_ARTIFACT_MUTATION.test(read(file)));
    expect(offenders.map(shortName)).toEqual([]);
  });

  it('the repository still WRITES artifacts — the guard bans mutation, not the record', () => {
    const repository = readFileSync(join(INGRESS_DIR, 'device-enrollment-ingress.repository.ts'), 'utf8');
    expect(repository).toContain('androidKeyAttestationArtifact.create');
  });

  it('the tripwire fires on the shapes a future edit could reach a mutation by', () => {
    for (const shape of [
      'await tx.androidKeyAttestationArtifact.update({ where: { id }, data: {} });',
      'await this.prisma.androidKeyAttestationArtifact.deleteMany({ where: {} });',
      'await db.androidKeyAttestationArtifact.upsert({ where: {}, create: {}, update: {} });',
    ]) {
      expect(ARTIFACT_MUTATION.test(shape), shape).toBe(true);
    }
    for (const shape of [
      'Prisma.sql`UPDATE android_key_attestation_artifacts SET outcome = ...`',
      'Prisma.sql`DELETE FROM "android_key_attestation_artifacts" WHERE id = ...`',
    ]) {
      expect(RAW_ARTIFACT_MUTATION.test(shape), shape).toBe(true);
    }
    expect(ARTIFACT_MUTATION.test('await db.androidKeyAttestationArtifact.create({ data });')).toBe(false);
  });

  /**
   * THE RESTRICTED COLUMN, AS A SOURCE FACT.
   *
   * `certificate_chain_der` may be WRITTEN by exactly one method and READ by
   * nothing. The guarantee is enforced by absence: `AndroidAttestationArtifactReader`
   * — the only reader of the table — does not select the column, and no
   * controller, service or evaluator names it at all. What cannot be loaded
   * cannot reach an audit payload, a fingerprint, a log or a response.
   */
  it('the raw certificate chain is named ONLY on the write path: the service that supplies it, and the repository that stores it', () => {
    const namesTheColumn = productionSource.filter((file) => read(file).includes('certificateChainDer')).map(shortName).sort();
    expect(namesTheColumn).toEqual(
      [
        shortName(join(INGRESS_DIR, 'device-enrollment-ingress.repository.ts')),
        shortName(join(INGRESS_DIR, 'device-enrollment-ingress.service.ts')),
      ].sort(),
    );
  });

  it('the service names it EXACTLY once, and only as an argument to the artifact write', () => {
    // Two files is one more than ideal and it is the minimum: something has to
    // hand the bytes to the writer. What matters is that the service mentions
    // them once, inside the `recordAttestationArtifact` call, and never again —
    // not in a response, not in a log line, not in a Shield submission.
    const service = read(join(INGRESS_DIR, 'device-enrollment-ingress.service.ts'));
    expect(service.split('certificateChainDer').length - 1).toBe(1);
    const call = service.slice(service.indexOf('recordAttestationArtifact('));
    expect(call.slice(0, call.indexOf('});')).includes('certificateChainDer')).toBe(true);
  });

  it('the ONE reader of the artifact table cannot load the chain', () => {
    const reader = read(join(INGRESS_DIR, 'android-attestation.artifact-reader.ts'));
    expect(reader).toContain('androidKeyAttestationArtifact.findFirst');
    expect(reader.includes('certificateChainDer')).toBe(false);
    expect(reader.includes('certificate_chain_der')).toBe(false);
  });

  it('nothing outside the writer selects the chain through Prisma at all', () => {
    for (const file of productionSource) {
      const body = read(file);
      if (file.endsWith('device-enrollment-ingress.repository.ts')) continue;
      expect(body.includes('certificate_chain_der'), shortName(file)).toBe(false);
    }
  });
});

describe('WP-26/C17-01 no ingress route exempts itself from human authentication', () => {
  it('nothing in the ingress declares @Public() or imports the decorator', () => {
    // A behavioural test can only prove that the routes it happens to call
    // require a session. It cannot prove that the sixth route somebody adds next
    // quarter does, and `@Public()` is a one-line edit with no visible
    // consequence at the call site.
    //
    // The prohibition is absolute HERE: `@Public()` is legitimate on liveness
    // probes and is used elsewhere in this service. What it may never mark is a
    // route in the enrollment ceremony, because on such a route it removes the
    // ONLY human principal there is — the device is not authenticated here and
    // cannot be.
    for (const file of productionSource) {
      const body = read(file);
      expect(/@Public\s*\(/u.test(body), shortName(file)).toBe(false);
      expect(/\bPublic\b[^\n]*from\s+'[^']*requires-action\.decorator'/u.test(body), shortName(file)).toBe(false);
    }
  });

  it('every mobile route exists and reads the authenticated principal', () => {
    const controller = read(join(INGRESS_DIR, 'mobile-enrollment.controller.ts'));
    for (const route of [
      "@Post('attestation-challenge')",
      "@Post('requests')",
      "@Post('possession-challenge')",
      "@Post('possession')",
      "@Post('commit')",
    ]) {
      expect(controller.includes(route), route).toBe(true);
    }
    // Five routes, five `requirePrincipal` call sites. Not four.
    expect(controller.split('requirePrincipal(req)').length - 1).toBe(5);
    // The principal is PASSED, never re-derived inside the service.
    for (const call of [
      'this.ingress.issueAttestationChallenge(principal,',
      'this.ingress.submitEnrollmentRequest(principal,',
      'this.ingress.issuePossessionChallenge(principal,',
      'this.ingress.verifyPossession(principal,',
      'this.ingress.commitEnrollment(principal,',
    ]) {
      expect(controller.includes(call), call).toBe(true);
    }
  });

  it('every Command route exists, reads the principal and carries its §62 action', () => {
    const controller = read(join(INGRESS_DIR, 'command-enrollment.controller.ts'));
    for (const route of [
      "@Post('bootstrap-grants')",
      "@Post('bootstrap-grants/:id/revoke')",
      "@Get('pending')",
      "@Post('enrollment-requests/:id/approve')",
    ]) {
      expect(controller.includes(route), route).toBe(true);
    }
    expect(controller.split('requirePrincipal(req)').length - 1).toBe(4);
    expect(controller.split('@RequiresAction(').length - 1).toBe(4);
    expect(controller).toContain('ACTION_DEVICE_ENROLLMENT_APPROVE');
    expect(controller).toContain('ACTION_DEVICE_ENROLLMENT_ISSUE');
    expect(controller).toContain('ACTION_DEVICE_REGISTRY_READ');
  });
});

describe('WP-26/D26-01 the mobile surface cannot approve, and cannot reach an approval', () => {
  it('the mobile controller never names an approval route or an approval call', () => {
    const controller = read(join(INGRESS_DIR, 'mobile-enrollment.controller.ts'));
    expect(/@Post\(\s*'[^']*approv/iu.test(controller)).toBe(false);
    expect(controller.includes('approveEnrollmentRequest')).toBe(false);
    expect(controller.includes('ACTION_DEVICE_ENROLLMENT_APPROVE')).toBe(false);
  });

  it('the ingress SERVICE — everything the mobile controller can reach — never approves', () => {
    // The controller not naming an approval is not enough on its own: what
    // matters is that nothing it CALLS can approve either.
    const service = read(join(INGRESS_DIR, 'device-enrollment-ingress.service.ts'));
    expect(service.includes('approveEnrollmentRequest')).toBe(false);
    expect(service.includes('issueBootstrapGrant')).toBe(false);
    expect(service.includes('revokeBootstrapGrant')).toBe(false);
    expect(service.includes('listPendingEnrollments')).toBe(false);
  });
});

describe('WP-26/C17-02 the session is bound BEFORE anything enters Shield', () => {
  /**
   * The ORDER is the property, not a detail. An org-A session naming org-B must
   * cause ZERO rows under org-B — refusal rows included — and the only way to
   * guarantee that is to refuse before the first Shield call. This scan reads
   * the first executable statement of every public method on the ingress service
   * and requires it to be a binding.
   */
  const PUBLIC_METHODS = [
    'issueAttestationChallenge',
    'submitEnrollmentRequest',
    'issuePossessionChallenge',
    'verifyPossession',
    'commitEnrollment',
  ];

  it('every public ingress method binds the session first', () => {
    const service = read(join(INGRESS_DIR, 'device-enrollment-ingress.service.ts'));
    for (const method of PUBLIC_METHODS) {
      const start = service.indexOf(`async ${method}(`);
      expect(start, method).toBeGreaterThan(-1);
      const body = service.slice(start, start + 1400);
      const firstStatement = body
        .slice(body.indexOf('): Promise<'))
        .split('\n')
        .map((line) => line.trim())
        .find((line) => line.startsWith('const ') || line.startsWith('return ') || line.startsWith('await '));
      expect(firstStatement, `${method} first statement: ${String(firstStatement)}`).toMatch(
        /^const bound = (await )?this\.(bindSession|bindCeremonySession|bindIntendedUser)\(/u,
      );
    }
  });

  it('the bindings compare the SESSION, and nothing a request named', () => {
    const service = read(join(INGRESS_DIR, 'device-enrollment-ingress.service.ts'));
    expect(service).toContain('principal.organisation_id !== input.organisationId');
    expect(service).toContain('principal.user.id !== input.intendedUserId');
  });
});

describe('WP-26/D24-13 Shield still has ZERO controllers', () => {
  it('the Shield module declares no controller, and no Shield file is one', () => {
    const module = read(join(SHIELD_DIR, 'shield.module.ts'));
    expect(module.includes('controllers')).toBe(false);
    for (const file of collectTypeScriptFiles(SHIELD_DIR)) {
      expect(/@Controller\s*\(/u.test(read(file)), shortName(file)).toBe(false);
    }
  });
});

describe('WP-26/D25-08 no background scheduler, and D25-10 REST only', () => {
  it('nothing in the ingress starts a timer, an interval or a scheduled job', () => {
    for (const file of productionSource) {
      const body = read(file);
      for (const forbidden of ['setInterval(', 'setTimeout(', '@Cron(', '@Interval(', '@Timeout(', 'node-cron']) {
        expect(body.includes(forbidden), `${shortName(file)} contains ${forbidden}`).toBe(false);
      }
    }
  });

  it('nothing in the ingress declares a WebSocket gateway or subscribes to a message', () => {
    for (const file of productionSource) {
      const body = read(file);
      expect(/@(?:WebSocketGateway|SubscribeMessage|WebSocketServer)\s*\(/u.test(body), shortName(file)).toBe(false);
      expect(body.includes("from '@nestjs/websockets'"), shortName(file)).toBe(false);
      expect(body.includes("from 'socket.io'"), shortName(file)).toBe(false);
    }
  });
});

describe('WP-26/D26-07 the ingress is not the physical-device Whisper path', () => {
  it('nothing in the ingress names the frozen Whisper device-key resolver or imports Whisper', () => {
    // WP-26 is the first work package with a REAL hardware-attested key, which
    // makes it the first with a plausible-sounding argument for wiring one into
    // Whisper. `WHISPER_DEVICE_KEY_RESOLVER` verifies Ed25519 under frozen
    // Whisper v1; this registry holds P-256 under the M3 profile. WP-27 owns
    // that path, and a real phone existing does not authorise touching a frozen
    // M2 cryptographic domain.
    for (const file of productionSource) {
      const body = read(file);
      expect(body.includes('WHISPER_DEVICE_KEY_RESOLVER'), shortName(file)).toBe(false);
      expect(body.includes("from '../whisper/"), shortName(file)).toBe(false);
    }
    const module = read(join(INGRESS_DIR, 'device-enrollment-ingress.module.ts'));
    expect(module.includes('WhisperModule')).toBe(false);
    expect(module.includes('RealtimeModule')).toBe(false);
  });
});

describe('WP-26/D26-04A the one new ceiling has its own name and one declaration', () => {
  it('no ingress source spells a frozen ceiling as a literal', () => {
    // 600_000 (the bootstrap grant), 300_000 (the device context) and 60_000
    // belong to the contracts and to WP-25. A copy here would be a second
    // freshness opinion.
    for (const file of productionSource) {
      const body = read(file);
      for (const literal of ['600_000', '600000', '300_000', '300000', '60_000', '60000']) {
        expect(body.includes(literal), `${shortName(file)} contains ${literal}`).toBe(false);
      }
    }
  });

  it('DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS is declared exactly once, in the constants file', () => {
    const declarations = productionSource.filter((file) => read(file).includes('DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS = '));
    expect(declarations.map(shortName)).toEqual([shortName(join(INGRESS_DIR, 'device-enrollment-ingress.constants.ts'))]);
  });
});

describe('WP-26 the test-only DER encoder never reaches a production path', () => {
  it('no production file imports the synthetic-chain builder', () => {
    for (const file of productionSource) {
      expect(read(file).includes('android-attestation.test-support'), shortName(file)).toBe(false);
    }
  });

  it('the exclusion this guard relies on is real — the builder exists and is excluded', () => {
    // An exclusion that is not itself checked is a hole: if the file were
    // renamed, the scan above would pass by scanning nothing.
    const builder = join(INGRESS_DIR, 'android-attestation.test-support.ts');
    expect(ingressFiles).toContain(builder);
    expect(productionSource).not.toContain(builder);
  });

  it('the PRODUCTION DER file decodes and never encodes', () => {
    const der = read(join(INGRESS_DIR, 'android-attestation.der.ts'));
    // `encodeObjectIdentifier` is the ONE encoder in production, and it exists
    // so the attestation OID can be written in the dotted form a reviewer can
    // check rather than as an opaque byte constant. There is no certificate
    // builder, no TBS assembler and no signature producer here.
    expect(der.includes('function encodeObjectIdentifier')).toBe(true);
    for (const forbidden of ['buildCertificate', 'buildKeyDescription', 'cryptoSign', 'generateKeyPairSync']) {
      expect(der.includes(forbidden), forbidden).toBe(false);
    }
  });
});
