import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  EDGE_TRUSTED_TIME_KEYRING_KEYS,
  edgeTrustedTimeKeyringIsConfigured,
  loadEdgeTrustedTimeKeyring,
  unconfiguredEdgeTrustedTimeKeyring,
} from './edge-trusted-time.keyring';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';
import { generateTestAnchorSigner } from './edge-trusted-time.test-support';
import type { EdgeConfig } from '../../config/env.schema';

/**
 * WP-29B Crucible — the deployment-pinned verification keyring.
 *
 * Each rule below is a way this could fail OPEN, which is why they are tested
 * as rules rather than through a booted injector.
 */

const verifier = new P256AnchorSignatureVerifier();
const isOnCurve = (key: string): boolean => verifier.isRuntimeValidPublicKey(key);

const active = generateTestAnchorSigner();
const previous = generateTestAnchorSigner();

const ACTIVE_ENTRY = { signer_key_id: 'central-tta-2026-01', public_key: active.publicKey, role: 'ACTIVE' };
const PREVIOUS_ENTRY = { signer_key_id: 'central-tta-2025-07', public_key: previous.publicKey, role: 'PREVIOUS' };

function config(overrides: Record<string, unknown> = {}): EdgeConfig {
  return {
    EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([ACTIVE_ENTRY]),
    EDGE_TRUSTED_TIME_KEYRING_VERSION: 'keyring-2026-01',
    ...overrides,
  } as unknown as EdgeConfig;
}

function load(overrides: Record<string, unknown> = {}) {
  return loadEdgeTrustedTimeKeyring(config(overrides), isOnCurve);
}

/**
 * A STRUCTURALLY PERFECT point that is not on the P-256 curve — the exact value
 * the runtime import exists for. It passes every check the contract performs
 * and satisfies no curve equation.
 */
function offCurvePublicKey(): string {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const point = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(26));
  point[point.length - 1] = (point[point.length - 1] as number) ^ 0x01;
  return point.toString('base64url');
}

// ---------------------------------------------------------------------------

describe('the safe default pins nothing', () => {
  it('is unconfigured when the deployment has said nothing', () => {
    expect(edgeTrustedTimeKeyringIsConfigured({} as EdgeConfig)).toBe(false);
    const keyring = unconfiguredEdgeTrustedTimeKeyring();
    expect(keyring.configured).toBe(false);
  });

  it.each(EDGE_TRUSTED_TIME_KEYRING_KEYS)('counts %s alone as an ATTEMPT to configure', (key) => {
    // A deployment that set one of the two has attempted this and got it wrong,
    // and must learn from a named refusal rather than from a silent fall back
    // as though it had never tried.
    expect(edgeTrustedTimeKeyringIsConfigured({ [key]: 'x' } as unknown as EdgeConfig)).toBe(true);
  });
});

describe('all or nothing', () => {
  it('loads a complete keyring', () => {
    const keyring = load();
    expect(keyring.configured).toBe(true);
    if (keyring.configured) {
      expect(keyring.version).toBe('keyring-2026-01');
      expect(keyring.resolve('central-tta-2026-01')?.public_key).toBe(active.publicKey);
    }
  });

  it.each(EDGE_TRUSTED_TIME_KEYRING_KEYS)('refuses when %s is missing', (key) => {
    const partial = config();
    delete (partial as Record<string, unknown>)[key];
    const keyring = loadEdgeTrustedTimeKeyring(partial, isOnCurve);
    expect(keyring).toEqual({ configured: false, reason: 'KEYRING_INCOMPLETE' });
  });

  it.each(EDGE_TRUSTED_TIME_KEYRING_KEYS)('refuses when %s is blank', (key) => {
    expect(load({ [key]: '   ' })).toEqual({ configured: false, reason: 'KEYRING_INCOMPLETE' });
  });
});

describe('a malformed entry poisons the whole set', () => {
  it('refuses unparseable JSON', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: '{not json' })).toEqual({ configured: false, reason: 'KEYRING_UNPARSEABLE' });
  });

  it('refuses an empty array', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: '[]' })).toEqual({ configured: false, reason: 'KEYRING_EMPTY' });
  });

  it('refuses the WHOLE set when one entry is malformed, never a smaller set', () => {
    // The entry that failed to parse may be the ACTIVE one. An Edge silently
    // reduced to a previous key would stop being able to verify anything
    // current while appearing perfectly configured.
    const keyring = load({
      EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([ACTIVE_ENTRY, { signer_key_id: 'broken', public_key: 'nope', role: 'PREVIOUS' }]),
    });
    expect(keyring.configured).toBe(false);
  });

  it('refuses an entry with an unknown role', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([{ ...ACTIVE_ENTRY, role: 'ARCHIVED' }]) }).configured).toBe(false);
  });

  it('refuses an entry carrying an extra field', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([{ ...ACTIVE_ENTRY, trusted: true }]) }).configured).toBe(false);
  });

  it.each(['private_key', 'signing_key', 'd', 'secret'])('refuses an entry carrying %s', (field) => {
    // PUBLIC MATERIAL ONLY. A deployment that pasted a private key gets a parse
    // failure rather than a running Edge holding central's signing key on a
    // customer LAN.
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([{ ...ACTIVE_ENTRY, [field]: 'x' }]) }).configured).toBe(false);
  });

  it('refuses a structurally perfect but OFF-CURVE pinned key, at LOAD', () => {
    // Only the runtime import can refuse this, and doing it at boot means a
    // deployment learns it pinned an unusable point immediately rather than
    // when an anchor arrives.
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([{ ...ACTIVE_ENTRY, public_key: offCurvePublicKey() }]) })).toEqual({
      configured: false,
      reason: 'KEYRING_KEY_NOT_ON_CURVE',
    });
  });
});

describe('exactly one ACTIVE key, and no ambiguity', () => {
  it('accepts one ACTIVE plus one PREVIOUS', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([ACTIVE_ENTRY, PREVIOUS_ENTRY]) }).configured).toBe(true);
  });

  it('refuses a keyring with no ACTIVE key', () => {
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([PREVIOUS_ENTRY]) })).toEqual({
      configured: false,
      reason: 'KEYRING_NO_ACTIVE_KEY',
    });
  });

  it('refuses two ACTIVE keys', () => {
    // A rotation that never completed. "Which key is current" would otherwise
    // be answered by whichever appeared first.
    const two = [ACTIVE_ENTRY, { ...PREVIOUS_ENTRY, role: 'ACTIVE' }];
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify(two) })).toEqual({
      configured: false,
      reason: 'KEYRING_MULTIPLE_ACTIVE_KEYS',
    });
  });

  it('refuses two entries claiming one signer_key_id', () => {
    const duplicate = [ACTIVE_ENTRY, { ...PREVIOUS_ENTRY, signer_key_id: ACTIVE_ENTRY.signer_key_id }];
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify(duplicate) })).toEqual({
      configured: false,
      reason: 'KEYRING_DUPLICATE_SIGNER_KEY_ID',
    });
  });

  it('refuses more than two keys, bounding the set by the six-hour ceiling', () => {
    // Every anchor a key could have signed expires at most six hours after that
    // key stopped being used, so a third key is a thing that can still vouch
    // for time and no longer needs to.
    const third = { signer_key_id: 'central-tta-2024-01', public_key: generateTestAnchorSigner().publicKey, role: 'PREVIOUS' };
    expect(load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([ACTIVE_ENTRY, PREVIOUS_ENTRY, third]) }).configured).toBe(false);
  });
});

describe('resolution is by id, never by trial', () => {
  it('resolves the named key', () => {
    const keyring = load({ EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([ACTIVE_ENTRY, PREVIOUS_ENTRY]) });
    expect(keyring.configured).toBe(true);
    if (keyring.configured) {
      expect(keyring.resolve(ACTIVE_ENTRY.signer_key_id)?.role).toBe('ACTIVE');
      expect(keyring.resolve(PREVIOUS_ENTRY.signer_key_id)?.role).toBe('PREVIOUS');
    }
  });

  it('answers null for an unknown id rather than offering another key', () => {
    // Trying every pinned key until one verified would make the statement's own
    // `signer_key_id` decorative.
    const keyring = load();
    expect(keyring.configured).toBe(true);
    if (keyring.configured) expect(keyring.resolve('central-tta-NOPE')).toBeNull();
  });
});
