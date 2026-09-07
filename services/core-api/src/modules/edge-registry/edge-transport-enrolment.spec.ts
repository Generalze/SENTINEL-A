import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { P256_CURVE_ORDER, P256_HALF_CURVE_ORDER, encodeCanonicalP256Signature } from '@sentinel/contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import { P256KeyImporter } from '../shield/p256-key.importer';
import {
  EdgeTransportEnrolmentService,
  canonicalEdgeTransportBindingStatement,
  deriveTlsSpkiSha256,
} from './edge-transport-enrolment.service';

/**
 * M3B §4 — BOTH POSSESSIONS, BOUND TO EACH OTHER.
 *
 * The two halves are useless apart:
 *
 *   application key only   registers SOMEBODY ELSE'S TLS key, and every device
 *                          on the site pins a certificate this Edge cannot
 *                          present
 *   TLS key only           claims to be an Edge it is not
 *
 * So the tests that matter are the ones where each signature alone is valid.
 */

const ORG = 'org-1';
const EDGE = 'edge-1';
const SITE = 'site-1';
const CHALLENGE = 'central-chosen-challenge';
const VERSION = 1;

let applicationKey: KeyObject;
let applicationPublic: string;
let tlsKey: KeyObject;
let tlsPublic: string;
let importer: P256KeyImporter;

function canonicalPoint(key: KeyObject): string {
  const jwk = key.export({ format: 'jwk' });
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(String(jwk.x), 'base64url'),
    Buffer.from(String(jwk.y), 'base64url'),
  ]).toString('base64url');
}

/** Low-S canonical, because the contract brands only low-S (C14-01). */
function sign(key: KeyObject, message: string): string {
  const signer = createSign('sha256');
  signer.update(Buffer.from(message, 'utf8'));
  signer.end();
  const raw = signer.sign({ key, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
  const rawS = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
  const s = rawS > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - rawS : rawS;
  return encodeCanonicalP256Signature(r, s);
}

function statementFor(overrides: { tlsPublicKey?: string; challenge?: string; siteId?: string } = {}): string {
  return canonicalEdgeTransportBindingStatement({
    organisationId: ORG,
    edgeId: EDGE,
    siteId: overrides.siteId ?? SITE,
    challenge: overrides.challenge ?? CHALLENGE,
    tlsPublicKey: overrides.tlsPublicKey ?? tlsPublic,
    transportKeyVersion: VERSION,
  });
}

interface FakeState {
  edge?: Record<string, unknown> | null;
  registryKey?: Record<string, unknown> | null;
  existingIdentity?: Record<string, unknown> | null;
}

function serviceWith(state: FakeState): { service: EdgeTransportEnrolmentService; created: Record<string, unknown>[] } {
  const created: Record<string, unknown>[] = [];
  const prisma = {
    edgeNode: {
      findFirst: async () =>
        state.edge === undefined
          ? { enrolmentState: 'ACTIVE', edgeTrust: 'TRUSTED', withdrawnAt: null }
          : state.edge,
    },
    edgeRegistryKey: {
      findFirst: async () =>
        state.registryKey === undefined
          ? { publicKey: applicationPublic, signatureProfile: 'P256_ECDSA_SHA256', revokedAt: null }
          : state.registryKey,
    },
    edgeTransportIdentity: {
      findFirst: async () => state.existingIdentity ?? null,
      create: async (args: { data: Record<string, unknown> }) => {
        created.push(args.data);
        return { id: 'ti-created' };
      },
    },
  } as never;
  return { service: new EdgeTransportEnrolmentService(prisma, importer), created };
}

function validInput(overrides: Record<string, unknown> = {}): Parameters<EdgeTransportEnrolmentService['activate']>[0] {
  const statement = statementFor();
  return {
    organisationId: ORG,
    edgeId: EDGE,
    siteId: SITE,
    challenge: CHALLENGE,
    tlsPublicKey: tlsPublic,
    tlsSignature: sign(tlsKey, statement),
    applicationSignature: sign(applicationKey, statement),
    transportKeyVersion: VERSION,
    httpsEndpoint: 'https://edge-1.site-1.internal:8443',
    ...overrides,
  } as Parameters<EdgeTransportEnrolmentService['activate']>[0];
}

beforeAll(() => {
  importer = new P256KeyImporter();
  const app = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  applicationKey = app.privateKey;
  applicationPublic = canonicalPoint(app.publicKey);
  const tls = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  tlsKey = tls.privateKey;
  tlsPublic = canonicalPoint(tls.publicKey);
});

describe('activating an Edge TLS transport identity', () => {
  it('activates when BOTH possessions are proven over the same statement', async () => {
    const { service, created } = serviceWith({});
    const result = await service.activate(validInput());

    expect(result.outcome).toBe('ACTIVATED');
    if (result.outcome !== 'ACTIVATED') return;
    expect(result.tlsSpkiSha256).toMatch(/^[0-9a-f]{64}$/);
    // The stored pin is the DERIVED one.
    expect(created[0]?.tlsSpkiSha256).toBe(result.tlsSpkiSha256);
    expect(created[0]?.transportPublicKey).toBe(tlsPublic);
  });

  // THE TWO TESTS THIS FILE EXISTS FOR. In each, one signature is entirely
  // valid -- which is exactly how a real attack would look.
  it('refuses when only the APPLICATION key signed', async () => {
    const statement = statementFor();
    const { service } = serviceWith({});
    const result = await service.activate(
      validInput({ tlsSignature: sign(applicationKey, statement) }),
    );
    expect(result).toMatchObject({ refusal: 'TLS_POSSESSION_NOT_PROVEN' });
  });

  it('refuses when only the TLS key signed', async () => {
    const statement = statementFor();
    const { service } = serviceWith({});
    const result = await service.activate(
      validInput({ applicationSignature: sign(tlsKey, statement) }),
    );
    expect(result).toMatchObject({ refusal: 'APPLICATION_POSSESSION_NOT_PROVEN' });
  });

  // A BARE SPKI CLAIM IS THE DOOR PINNING EXISTS TO CLOSE. Registering a key
  // the Edge does not hold would make every device on the site pin a
  // certificate that Edge can never present -- a self-inflicted outage at
  // best, and an attacker's key at worst.
  it('refuses a TLS key the Edge does not hold', async () => {
    const foreign = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const foreignPublic = canonicalPoint(foreign.publicKey);
    const statement = statementFor({ tlsPublicKey: foreignPublic });
    const { service } = serviceWith({});
    const result = await service.activate(
      validInput({
        tlsPublicKey: foreignPublic,
        // Signed with the key the Edge actually holds, not the one it claims.
        tlsSignature: sign(tlsKey, statement),
        applicationSignature: sign(applicationKey, statement),
      }),
    );
    expect(result).toMatchObject({ refusal: 'TLS_POSSESSION_NOT_PROVEN' });
  });

  // The two signatures must cover the SAME bytes. A TLS proof captured from
  // one ceremony must not be usable beside a different application proof.
  it('refuses signatures made over different statements', async () => {
    const { service } = serviceWith({});
    const result = await service.activate(
      validInput({ applicationSignature: sign(applicationKey, statementFor({ challenge: 'a-different-challenge' })) }),
    );
    expect(result).toMatchObject({ refusal: 'APPLICATION_POSSESSION_NOT_PROVEN' });
  });

  it('binds a claimed digest by equality and never consults it', async () => {
    const { service } = serviceWith({});
    const wrong = await service.activate(validInput({ claimedSpkiSha256: 'f'.repeat(64) }));
    expect(wrong).toMatchObject({ refusal: 'SPKI_DIGEST_MISMATCH' });

    const derived = deriveTlsSpkiSha256(importer, tlsPublic);
    const right = await serviceWith({}).service.activate(validInput({ claimedSpkiSha256: derived ?? '' }));
    expect(right.outcome).toBe('ACTIVATED');
  });

  it('refuses a malformed TLS key before it is used for anything', async () => {
    const { service } = serviceWith({});
    const result = await service.activate(validInput({ tlsPublicKey: 'not-a-key' }));
    expect(result).toMatchObject({ refusal: 'TLS_KEY_MALFORMED' });
  });

  // An Edge the estate has disowned cannot acquire a fresh pin.
  it.each([
    ['withdrawn', { enrolmentState: 'ACTIVE', edgeTrust: 'TRUSTED', withdrawnAt: new Date() }, 'EDGE_NOT_ACTIVE'],
    ['pending', { enrolmentState: 'PENDING', edgeTrust: 'TRUSTED', withdrawnAt: null }, 'EDGE_NOT_ACTIVE'],
    ['revoked', { enrolmentState: 'ACTIVE', edgeTrust: 'REVOKED', withdrawnAt: null }, 'EDGE_NOT_TRUSTED'],
  ])('refuses a %s Edge', async (_label, edge, expected) => {
    const { service } = serviceWith({ edge });
    expect(await service.activate(validInput())).toMatchObject({ refusal: expected });
  });

  it('refuses when the application key has been revoked', async () => {
    const { service } = serviceWith({
      registryKey: { publicKey: applicationPublic, signatureProfile: 'P256_ECDSA_SHA256', revokedAt: new Date() },
    });
    expect(await service.activate(validInput())).toMatchObject({ refusal: 'APPLICATION_KEY_NOT_CURRENT' });
  });

  // One CURRENT identity per site. Refusing here gives a clear answer; the
  // partial unique index enforces it regardless.
  it('refuses a second CURRENT identity for the same site', async () => {
    const { service } = serviceWith({ existingIdentity: { id: 'ti-existing' } });
    expect(await service.activate(validInput())).toMatchObject({ refusal: 'TRANSPORT_IDENTITY_ALREADY_CURRENT' });
  });

  // THE ENDPOINT IS NOT THE EDGE'S TO ASSERT. There is no parameter through
  // which the enrolling box could influence it; this proves the operator's
  // value is what lands.
  it('stores the operator-supplied endpoint', async () => {
    const { service, created } = serviceWith({});
    await service.activate(validInput({ httpsEndpoint: 'https://operator-chosen.internal:9443' }));
    expect(created[0]?.httpsEndpoint).toBe('https://operator-chosen.internal:9443');
  });
});
