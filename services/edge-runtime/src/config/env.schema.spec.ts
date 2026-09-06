import { describe, expect, it } from 'vitest';
import { ConfigValidationError, envSchema, loadConfig, toEdgeIdentityContext } from './env.schema';
import { EDGE_SIGNATURE_PROFILE, EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS } from '../edge-runtime.constants';
import { DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS } from '@sentinel/contracts';

const validEnv = {
  EDGE_ORGANISATION_ID: 'org-1',
  EDGE_ID: 'edge-17',
  EDGE_KEY_ID: 'edge-key-1',
  EDGE_KEY_VERSION: '1',
  EDGE_AUTHORISED_SITE_IDS: 'site-1,site-2',
  SENTINEL_CENTRAL_URL: 'https://central.example.test',
  EDGE_QUEUE_PATH: '/var/lib/sentinel-edge/queue',
};

describe('loadConfig', () => {
  it('parses a complete environment and applies defaults', () => {
    const config = loadConfig(validEnv);
    expect(config.EDGE_ID).toBe('edge-17');
    expect(config.EDGE_KEY_VERSION).toBe(1);
    expect(config.EDGE_AUTHORISED_SITE_IDS).toEqual(['site-1', 'site-2']);
    expect(config.PORT).toBe(3100);
    expect(config.LOG_LEVEL).toBe('info');
  });

  it('lists every bad variable in one error rather than the first', () => {
    const partial: Partial<typeof validEnv> = { ...validEnv };
    delete partial.EDGE_ID;
    delete partial.EDGE_QUEUE_PATH;
    try {
      loadConfig({ ...partial, SENTINEL_CENTRAL_URL: 'not-a-url', EDGE_KEY_VERSION: 'x' });
      throw new Error('expected loadConfig to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigValidationError);
      const joined = (error as ConfigValidationError).issues.join('\n');
      expect(joined).toContain('EDGE_ID');
      expect(joined).toContain('EDGE_QUEUE_PATH');
      expect(joined).toContain('SENTINEL_CENTRAL_URL');
      expect(joined).toContain('EDGE_KEY_VERSION');
    }
  });

  it('refuses to boot an Edge that has not been told which sites it serves', () => {
    // No default and no wildcard: an Edge with no site binding must fail to
    // boot rather than quietly serve all of them.
    expect(() => loadConfig({ ...validEnv, EDGE_AUTHORISED_SITE_IDS: '' })).toThrow(ConfigValidationError);
    const missing: Partial<typeof validEnv> = { ...validEnv };
    delete missing.EDGE_AUTHORISED_SITE_IDS;
    expect(() => loadConfig(missing)).toThrow(ConfigValidationError);
  });

  it('tolerates whitespace and trailing separators in the site list', () => {
    const config = loadConfig({ ...validEnv, EDGE_AUTHORISED_SITE_IDS: ' site-1 , site-2 ,' });
    expect(config.EDGE_AUTHORISED_SITE_IDS).toEqual(['site-1', 'site-2']);
  });
});

/**
 * THE PERMANENT GUARD ON THE CONFIGURATION DOCTRINE.
 *
 * Each key below would move a decision about WHAT EDGE IS WILLING TO WITNESS
 * out of a reviewed diff and into a file on a box in a wiring closet. The
 * schema has no `.passthrough()`, so an unknown key is simply ignored rather
 * than rejected — which means this suite, not the parser, is what stops one
 * being added and then read. If a key here ever starts parsing, someone has
 * added it deliberately and must justify it.
 */
describe('security-relevant policy is NEVER an env var', () => {
  const forbidden = [
    'EDGE_TRUSTED',
    'EDGE_TRUST_STATUS',
    'EDGE_ANCHOR_HOLDOVER_MS',
    'EDGE_TRUSTED_TIME_MAX_AGE_MS',
    'EDGE_STALE_TOLERANT_OPERATION_KINDS',
    'EDGE_WITNESS_ALL_KINDS',
    'EDGE_SIGNATURE_PROFILE',
    'EDGE_ALLOW_UNTRUSTED_TIME',
    'EDGE_FALLBACK_TO_SYSTEM_CLOCK',
    'EDGE_SIGNING_KEY',
    'EDGE_PRIVATE_KEY',
    'EDGE_TRUSTED_TIME_SIGNING_KEY',
    'EDGE_TRUSTED_TIME_SIGNING_KEY_FILE',
    'EDGE_TRUSTED_TIME_KEY_FETCH_URL',
    'EDGE_TRUSTED_TIME_KEYRING_REFRESH_MS',
    'EDGE_TRUST_ANY_SIGNER',
    'DATABASE_URL',
  ] as const;

  it.each(forbidden)('has no %s key in the schema', (key) => {
    expect(Object.keys(envSchema.shape)).not.toContain(key);
  });

  it.each(forbidden)('ignores %s if a deployment sets it anyway', (key) => {
    const config = loadConfig({ ...validEnv, [key]: 'true' }) as Record<string, unknown>;
    expect(config[key]).toBeUndefined();
  });

  it('keeps the holdover ceiling hard-wired to the frozen lease ceiling', () => {
    expect(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS).toBe(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
  });

  it('keeps the signature profile hard-wired to the one approved profile', () => {
    expect(EDGE_SIGNATURE_PROFILE).toBe('P256_ECDSA_SHA256');
  });
});

describe('toEdgeIdentityContext', () => {
  it('builds the frozen identity shape from configuration', () => {
    const identity = toEdgeIdentityContext(loadConfig(validEnv));
    expect(identity).toEqual({
      schema_version: 1,
      organisation_id: 'org-1',
      edge_id: 'edge-17',
      edge_key_id: 'edge-key-1',
      edge_key_version: 1,
      claimed_signature_profile: 'P256_ECDSA_SHA256',
      authorised_site_ids: ['site-1', 'site-2'],
    });
  });

  it('takes the signature profile from the constant, never from the environment', () => {
    const identity = toEdgeIdentityContext(loadConfig({ ...validEnv, EDGE_SIGNATURE_PROFILE: 'RSA_PKCS1' }));
    expect(identity.claimed_signature_profile).toBe(EDGE_SIGNATURE_PROFILE);
  });

  it('produces an identity with no trust field and no key material', () => {
    // `.strict()` on the frozen schema is the enforcement; this asserts the
    // bridge from config actually goes through it.
    const identity = toEdgeIdentityContext(loadConfig(validEnv)) as Record<string, unknown>;
    for (const field of ['edge_trust', 'trust', 'trusted', 'private_key', 'signing_key', 'public_key']) {
      expect(identity[field]).toBeUndefined();
    }
  });
});

/**
 * WP-29B/FW2-11. The keyring is PUBLIC trust material and it is configuration
 * for the same reason the pinned Google attestation roots are: it says WHOSE
 * SIGNATURE COUNTS, which is a binding rather than a policy, and it cannot fail
 * open — a wrong or missing key verifies nothing at all.
 */
describe('the trusted-time verification keyring', () => {
  it('is optional, and absent by default', () => {
    const config = loadConfig(validEnv);
    expect(config.EDGE_TRUSTED_TIME_VERIFICATION_KEYS).toBeUndefined();
    expect(config.EDGE_TRUSTED_TIME_KEYRING_VERSION).toBeUndefined();
  });

  it('is carried through verbatim when supplied', () => {
    const keys = '[{"signer_key_id":"k1","public_key":"p","role":"ACTIVE"}]';
    const config = loadConfig({ ...validEnv, EDGE_TRUSTED_TIME_VERIFICATION_KEYS: keys, EDGE_TRUSTED_TIME_KEYRING_VERSION: 'v1' });
    expect(config.EDGE_TRUSTED_TIME_VERIFICATION_KEYS).toBe(keys);
    expect(config.EDGE_TRUSTED_TIME_KEYRING_VERSION).toBe('v1');
  });

  it('refuses an empty value rather than treating it as absent', () => {
    // A blank value is a deployment that TRIED and got it wrong; it must be a
    // configuration error at boot, not a mystery refusal in production.
    expect(() => loadConfig({ ...validEnv, EDGE_TRUSTED_TIME_VERIFICATION_KEYS: '' })).toThrow(ConfigValidationError);
    expect(() => loadConfig({ ...validEnv, EDGE_TRUSTED_TIME_KEYRING_VERSION: '' })).toThrow(ConfigValidationError);
  });

  it('has NO key by which Edge could sign an anchor of its own', () => {
    // Edge verifies; it never signs. An Edge that could author its own anchor
    // could choose what time it believed it was.
    const shape = Object.keys(envSchema.shape);
    expect(shape.filter((key) => key.includes('SIGNING'))).toEqual([]);
    expect(shape.filter((key) => key.includes('PRIVATE'))).toEqual([]);
  });
});
