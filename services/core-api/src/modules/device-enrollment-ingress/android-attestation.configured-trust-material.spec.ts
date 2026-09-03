import { X509Certificate } from 'node:crypto';
import { Test } from '@nestjs/testing';
import { beforeAll, describe, expect, it } from 'vitest';
import { AppConfigService } from '../../config/config.service';
import { loadConfig, type AppConfig } from '../../config/env.schema';
import {
  ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER,
  ConfiguredAndroidAttestationTrustMaterial,
  androidAttestationTrustMaterialIsConfigured,
} from './android-attestation.configured-trust-material';
import {
  ANDROID_ATTESTATION_TRUST_MATERIAL,
  UnconfiguredAndroidAttestationTrustMaterial,
  type AndroidAttestationTrustMaterialProvider,
} from './android-attestation.trust-material';
import { ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS } from './device-enrollment-ingress.constants';
import { buildCertificate, generateEcKeyPair } from './android-attestation.test-support';

/**
 * ============================================================================
 * WP-26/D26-04B/C18-01 — THE CONFIGURATION-BACKED TRUST MATERIAL.
 *
 * WHAT THIS SPEC IS FOR, AND WHAT IT IS NOT.
 *
 * Before C18-01 the ingress module hard-bound the UNCONFIGURED provider, so
 * "supplying the real Google roots is a deployment act" described nothing a
 * deployment could actually do — the only route to `VERIFIED` was a Vitest
 * `.overrideProvider(...)`, and a candidate SHA that needs a test override to
 * reach its own acceptance path cannot perform D26-10's physical-device
 * acceptance against the code that ships.
 *
 * So this spec asks exactly two kinds of question:
 *
 *   1. does SETTING CONFIGURATION — and nothing else — reach the configured
 *      provider through the module's OWN provider object, with no override
 *      anywhere; and
 *   2. does every incomplete, malformed or stale configuration still answer
 *      `configured: false`, so a deployment can never half-arrive at a trust
 *      anchor set nobody chose.
 *
 * IT PROVES NOTHING ABOUT HARDWARE, AND IT CONTAINS NO GOOGLE ROOT. The
 * certificates below are generated in-process, exactly as every other WP-26
 * fixture is. What is being tested is the LOADER: whether the server refuses
 * material it cannot stand behind. The actual anchors are a deployment's
 * responsibility and are not, and must never be, in this repository.
 * ============================================================================
 */

const BASE_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
};

const PACKAGE_NAME = 'com.sentinel.field';
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

let anchorDerBase64: string;
let anchorPem: string;
let nonCaDerBase64: string;

beforeAll(() => {
  const rootKeyPair = generateEcKeyPair();
  const now = new Date();
  const root = buildCertificate({
    subjectCommonName: 'C18-01 Test Anchor',
    issuerCommonName: 'C18-01 Test Anchor',
    subjectPublicKey: rootKeyPair.publicKey,
    issuerPrivateKey: rootKeyPair.privateKey,
    serial: 0x4d2,
    notBefore: new Date(now.getTime() - 86_400_000),
    notAfter: new Date(now.getTime() + 86_400_000),
    isCertificateAuthority: true,
  });
  anchorDerBase64 = root.base64;
  anchorPem = root.certificate.toString();

  const leafKeyPair = generateEcKeyPair();
  const leaf = buildCertificate({
    subjectCommonName: 'C18-01 Not A CA',
    issuerCommonName: 'C18-01 Test Anchor',
    subjectPublicKey: leafKeyPair.publicKey,
    issuerPrivateKey: rootKeyPair.privateKey,
    serial: 7,
    notBefore: new Date(now.getTime() - 86_400_000),
    notAfter: new Date(now.getTime() + 86_400_000),
    isCertificateAuthority: false,
  });
  nonCaDerBase64 = leaf.base64;
});

/** A complete, healthy configuration — the shape a deployment must supply. */
function healthyEnv(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    ...BASE_ENV,
    ANDROID_ATTESTATION_TRUST_ANCHORS: anchorDerBase64,
    ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION: 'google-hardware-roots/2026-02',
    ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: JSON.stringify({ entries: {} }),
    ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION: 'google-status-list/2026-09-02',
    ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: new Date().toISOString(),
    ANDROID_ATTESTATION_PACKAGE_NAME: PACKAGE_NAME,
    ANDROID_ATTESTATION_SIGNING_DIGESTS: `${DIGEST_A},${DIGEST_B}`,
    ...overrides,
  };
}

function configOf(env: Record<string, string | undefined>): AppConfig {
  return loadConfig(env);
}

async function materialFrom(env: Record<string, string | undefined>, now = new Date()) {
  return new ConfiguredAndroidAttestationTrustMaterial(configOf(env)).current(now);
}

describe('C18-01 the module binds the configured provider from CONFIGURATION ALONE', () => {
  /**
   * THE SHIPPING PROVIDER OBJECT, in a small injector.
   *
   * `ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER` is the exact value
   * `device-enrollment-ingress.module.ts` lists in its `providers` array — the
   * same token, the same factory, the same `AppConfigService` injection. There
   * is no `.overrideProvider(...)` in this file and no test-only branch in the
   * factory, which is what makes "reachable purely by setting configuration"
   * a claim about the code that ships rather than about a stub.
   */
  async function resolveProvider(env: Record<string, string | undefined>): Promise<AndroidAttestationTrustMaterialProvider> {
    const previous = { ...process.env };
    try {
      for (const key of Object.keys(process.env)) {
        if (key.startsWith('ANDROID_ATTESTATION_')) delete process.env[key];
      }
      for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      const moduleRef = await Test.createTestingModule({
        providers: [AppConfigService, ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER],
      }).compile();
      return moduleRef.get<AndroidAttestationTrustMaterialProvider>(ANDROID_ATTESTATION_TRUST_MATERIAL);
    } finally {
      process.env = previous;
    }
  }

  it('with NO trust-material configuration at all, the SAFE DEFAULT is bound and pins nothing', async () => {
    const provider = await resolveProvider(BASE_ENV);
    expect(provider).toBeInstanceOf(UnconfiguredAndroidAttestationTrustMaterial);
    const material = await provider.current(new Date());
    expect(material.configured).toBe(false);
  });

  it('with configuration present, the CONFIGURED provider is bound and returns usable material', async () => {
    const provider = await resolveProvider(healthyEnv());
    expect(provider).toBeInstanceOf(ConfiguredAndroidAttestationTrustMaterial);
    const material = await provider.current(new Date());
    expect(material.configured).toBe(true);
    if (!material.configured) throw new Error('unreachable');
    expect(material.anchors).toHaveLength(1);
    expect(material.expectedPackageName).toBe(PACKAGE_NAME);
    expect(material.trustAnchorSetVersion).toBe('google-hardware-roots/2026-02');
  });

  it('a PARTIALLY configured deployment gets the configured provider, and it answers UNAVAILABLE', async () => {
    // The distinction that matters: a deployment which set SOME keys has tried
    // and failed, and must learn that from a named refusal rather than by
    // silently falling back to the shipped default as though it had never tried.
    const provider = await resolveProvider({ ...BASE_ENV, ANDROID_ATTESTATION_PACKAGE_NAME: PACKAGE_NAME });
    expect(provider).toBeInstanceOf(ConfiguredAndroidAttestationTrustMaterial);
    const material = await provider.current(new Date());
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('TRUST_MATERIAL_INCOMPLETE');
  });

  it('"configured" means ANY key present — one key is an attempt, not silence', () => {
    expect(androidAttestationTrustMaterialIsConfigured(configOf(BASE_ENV))).toBe(false);
    expect(androidAttestationTrustMaterialIsConfigured(configOf(healthyEnv()))).toBe(true);
    expect(
      androidAttestationTrustMaterialIsConfigured(configOf({ ...BASE_ENV, ANDROID_ATTESTATION_TRUST_ANCHORS: anchorDerBase64 })),
    ).toBe(true);
  });
});

describe('C18-01 anchors are parsed and validated at LOAD', () => {
  it('accepts base64 DER and PEM, and produces real X509 certificates', async () => {
    for (const anchors of [anchorDerBase64, anchorPem]) {
      const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_TRUST_ANCHORS: anchors }));
      expect(material.configured).toBe(true);
      if (!material.configured) throw new Error('unreachable');
      expect(material.anchors[0]).toBeInstanceOf(X509Certificate);
    }
  });

  it('accepts SEVERAL anchors — a fleet may legitimately chain to more than one root', async () => {
    const material = await materialFrom(
      healthyEnv({ ANDROID_ATTESTATION_TRUST_ANCHORS: `${anchorDerBase64} ${anchorDerBase64}` }),
    );
    expect(material.configured).toBe(true);
    if (!material.configured) throw new Error('unreachable');
    expect(material.anchors).toHaveLength(2);
  });

  it('ONE malformed anchor makes the WHOLE material unconfigured — never a smaller anchor set', async () => {
    // The rule that matters most in this file. A set that quietly shrank is a
    // set nobody chose, and the anchor that failed to parse may be the only one
    // a given device chains to — so the failure must be total and visible.
    const material = await materialFrom(
      healthyEnv({ ANDROID_ATTESTATION_TRUST_ANCHORS: `${anchorDerBase64},not-a-certificate` }),
    );
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('TRUST_ANCHORS_UNPARSEABLE');
  });

  it('refuses a truncated PEM block rather than re-reading it as base64', async () => {
    const truncated = anchorPem.replace('-----END CERTIFICATE-----', '');
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_TRUST_ANCHORS: truncated }));
    expect(material.configured).toBe(false);
  });

  it('refuses a pinned anchor that is not a CA (C18-04, applied to the anchor set)', async () => {
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_TRUST_ANCHORS: nonCaDerBase64 }));
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('TRUST_ANCHOR_NOT_CERTIFICATE_AUTHORITY');
  });
});

describe('C18-01 partial material is NEVER partially applied', () => {
  // Each of these leaves out exactly one term of the conjunction. A conjunction
  // missing a term is not a weaker conjunction, it is no answer at all.
  for (const key of [
    'ANDROID_ATTESTATION_TRUST_ANCHORS',
    'ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION',
    'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT',
    'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION',
    'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT',
    'ANDROID_ATTESTATION_PACKAGE_NAME',
    'ANDROID_ATTESTATION_SIGNING_DIGESTS',
  ]) {
    it(`without ${key} the material is UNAVAILABLE`, async () => {
      const material = await materialFrom(healthyEnv({ [key]: undefined }));
      expect(material.configured).toBe(false);
      if (material.configured) throw new Error('unreachable');
      expect(material.reason).toBe('TRUST_MATERIAL_INCOMPLETE');
    });
  }

  it('ANCHORS WITHOUT REVOCATION DATA is the case this rule exists for', async () => {
    // "Not revoked" is a required conjunct of VERIFIED. A deployment holding
    // roots but no status list has not looked, and a server that has not looked
    // must not answer.
    const material = await materialFrom(
      healthyEnv({
        ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: undefined,
        ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION: undefined,
        ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: undefined,
      }),
    );
    expect(material.configured).toBe(false);
  });
});

describe('C18-01 the revocation snapshot: parsed, keyed and BOUNDED', () => {
  it("reads Google's status-list shape and keys it by NORMALISED serial", async () => {
    const material = await materialFrom(
      healthyEnv({
        ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: JSON.stringify({
          // Uppercase, zero-padded, `0x`-prefixed — three spellings of one
          // serial. A revocation check that silently never matched would fail
          // OPEN, which is the worst outcome available on this path.
          entries: { '00004D2': { status: 'REVOKED', reason: 'KEY_COMPROMISE' } },
        }),
      }),
    );
    expect(material.configured).toBe(true);
    if (!material.configured) throw new Error('unreachable');
    expect(material.revocations.get('4d2')).toEqual({ status: 'REVOKED', reason: 'KEY_COMPROMISE' });
  });

  it('accepts an entry with no reason — Google omits it for some', async () => {
    const material = await materialFrom(
      healthyEnv({ ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: JSON.stringify({ entries: { ab: { status: 'SUSPENDED' } } }) }),
    );
    expect(material.configured).toBe(true);
    if (!material.configured) throw new Error('unreachable');
    expect(material.revocations.get('ab')).toEqual({ status: 'SUSPENDED', reason: null });
  });

  it.each([
    ['not json at all', 'REVOCATION_SNAPSHOT_UNPARSEABLE'],
    ['{"entries": []}', 'REVOCATION_SNAPSHOT_UNPARSEABLE'],
    ['{"wrong_key": {}}', 'REVOCATION_SNAPSHOT_UNPARSEABLE'],
    ['{"entries": {"4d2": {"reason": "x"}}}', 'REVOCATION_SNAPSHOT_UNPARSEABLE'],
  ])('refuses an unparseable snapshot (%s)', async (snapshot, reason) => {
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: snapshot }));
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe(reason);
  });

  it('refuses a fetched-at that is not a real instant', async () => {
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: 'yesterday' }));
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('REVOCATION_SNAPSHOT_FETCHED_AT_INVALID');
  });

  it('STALE material is UNAVAILABLE, bounded by the named constant', async () => {
    const fetchedAt = new Date(Date.now() - ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS - 1_000);
    const material = await materialFrom(
      healthyEnv({ ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: fetchedAt.toISOString() }),
    );
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('REVOCATION_SNAPSHOT_STALE');
    // The versions are STILL recorded on a refusal: a verdict that cannot name
    // the trust material it was reached against is an assertion, not evidence.
    expect(material.trustAnchorSetVersion).toBe('google-hardware-roots/2026-02');
    expect(material.revocationSnapshotVersion).toBe('google-status-list/2026-09-02');
  });

  it('the freshness bound is EXCLUSIVE, and is applied at request time not load time', async () => {
    const fetchedAt = new Date();
    const env = healthyEnv({ ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: fetchedAt.toISOString() });
    const provider = new ConfiguredAndroidAttestationTrustMaterial(configOf(env));

    const justInside = await provider.current(
      new Date(fetchedAt.getTime() + ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS - 1),
    );
    expect(justInside.configured).toBe(true);

    const exactlyAt = await provider.current(new Date(fetchedAt.getTime() + ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS));
    expect(exactlyAt.configured).toBe(false);
  });

  it('a fetched-at in the FUTURE is refused — it does not describe a possible history', async () => {
    const material = await materialFrom(healthyEnv(), new Date(Date.now() - 5_000));
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('REVOCATION_SNAPSHOT_STALE');
  });
});

describe('C18-01 the application identity is configuration, and is validated', () => {
  it('accepts one or more hex SHA-256 digests, lowercased', async () => {
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_SIGNING_DIGESTS: DIGEST_A.toUpperCase() }));
    expect(material.configured).toBe(true);
    if (!material.configured) throw new Error('unreachable');
    expect(material.expectedSigningDigests).toEqual([DIGEST_A]);
  });

  it.each(['deadbeef', `${DIGEST_A},zz`, 'not-hex'])('refuses a digest that is not a SHA-256 (%s)', async (digests) => {
    const material = await materialFrom(healthyEnv({ ANDROID_ATTESTATION_SIGNING_DIGESTS: digests }));
    expect(material.configured).toBe(false);
    if (material.configured) throw new Error('unreachable');
    expect(material.reason).toBe('SIGNING_DIGESTS_INVALID');
  });
});

describe('C18-01 nothing here ships a default, and no Google root is committed', () => {
  it('the environment schema gives every trust-material key NO default', () => {
    const config = configOf(BASE_ENV);
    expect(config.ANDROID_ATTESTATION_TRUST_ANCHORS).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_PACKAGE_NAME).toBeUndefined();
    expect(config.ANDROID_ATTESTATION_SIGNING_DIGESTS).toBeUndefined();
  });
});
