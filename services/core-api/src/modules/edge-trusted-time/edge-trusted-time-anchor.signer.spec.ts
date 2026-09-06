import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS,
  SignedEdgeTrustedTimeAnchorSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  edgeTrustedTimeAnchorFingerprint,
} from '@sentinel/contracts';
import { CentralTrustedTimeAnchorSigner, EDGE_TRUSTED_TIME_ANCHOR_LIFETIME_MS } from './edge-trusted-time-anchor.signer';
import {
  EDGE_TRUSTED_TIME_SIGNING_KEYS,
  MountedEdgeTrustedTimeSigningKeyProvider,
  UnavailableEdgeTrustedTimeSigningKeyProvider,
  edgeTrustedTimeSigningIsConfigured,
  type EdgeTrustedTimeSigningKeyProvider,
} from './edge-trusted-time-signing-key.provider';
import { P256KeyImporter } from '../shield/p256-key.importer';
import type { AppConfig } from '../../config/env.schema';

/**
 * ============================================================================
 * WP-29B / FW2-11 Crucible — CENTRAL'S TRUSTED-TIME ANCHOR SIGNER.
 *
 * This is the first private key Sentinel has ever held, and this suite exists
 * to prove three things about it: that it produces anchors the ordinary
 * verification path accepts, that it CANNOT produce anything else, and that
 * when it is unavailable central says so rather than degrading.
 *
 * Verification here goes through `P256KeyImporter` — the service's own,
 * existing verification boundary — deliberately. If the signer's output only
 * verified under a bespoke checker written alongside it, the suite would be
 * testing agreement between two new things rather than compatibility with the
 * one that already exists.
 * ============================================================================
 */

const NOW = new Date('2026-08-29T12:00:00.000Z');
const SIGNER_KEY_ID = 'central-tta-2026-01';
const P256_SPKI_HEADER_BYTES = 26;

const importer = new P256KeyImporter();

const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(P256_SPKI_HEADER_BYTES)).toString(
  'base64url',
);

let directory: string;
let keyPath: string;

function config(overrides: Record<string, unknown> = {}): AppConfig {
  return {
    EDGE_TRUSTED_TIME_SIGNER_KEY_ID: SIGNER_KEY_ID,
    EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: keyPath,
    ...overrides,
  } as unknown as AppConfig;
}

function signerWith(provider: EdgeTrustedTimeSigningKeyProvider): CentralTrustedTimeAnchorSigner {
  return new CentralTrustedTimeAnchorSigner(provider);
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    claim: { edge_boot_id: 'boot-4f2a', edge_monotonic_at_anchor: 1_000_000 },
    edge_id: 'edge-17',
    organisation_id: 'org-1',
    site_id: 'site-1',
    now: NOW,
    ...overrides,
  };
}

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'sentinel-tta-key-'));
  keyPath = join(directory, 'anchor-signer.pem');
  // Stands in for what a secret manager mounts. A PKCS#8 PEM at a path — never
  // a value in the environment.
  await writeFile(keyPath, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), 'utf8');
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

describe('the signer issues anchors the ordinary verification path accepts', () => {
  it('issues a signed anchor that verifies under the pinned public key', async () => {
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;

    const verified = importer.verifySignature({
      registeredPublicKey: publicKey,
      message: canonicalEdgeTrustedTimeAnchorStatement(result.anchor.statement),
      signature: result.anchor.signature,
      serverResolvedProfile: 'P256_ECDSA_SHA256',
      claimedProfile: 'P256_ECDSA_SHA256',
    });
    expect(verified).toBe(true);
  });

  it('produces a canonical low-S signature the frozen schema admits', async () => {
    // Node can emit a high-S signature, which `decodeCanonicalP256Signature`
    // refuses. Without `lowSCanonicaliseForSigning` in the provider, roughly
    // half of all anchors would be unparseable at Edge.
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(
        request({ claim: { edge_boot_id: `boot-${attempt}`, edge_monotonic_at_anchor: attempt } }),
      );
      expect(result.outcome).toBe('ISSUED');
      if (result.outcome === 'ISSUED') expect(SignedEdgeTrustedTimeAnchorSchema.safeParse(result.anchor).success).toBe(true);
    }
  });

  it('carries the two Edge-supplied facts through unaltered and into the signature', async () => {
    // Central does not "correct" them. A monotonic reading central adjusted
    // would be a subtrahend Edge never observed.
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    expect(result.anchor.statement.edge_boot_id).toBe('boot-4f2a');
    expect(result.anchor.statement.edge_monotonic_at_anchor).toBe(1_000_000);
    expect(canonicalEdgeTrustedTimeAnchorStatement(result.anchor.statement)).toContain('"edge_monotonic_at_anchor":1000000');
  });

  it('stamps the identity CENTRAL resolved, never anything from the claim', async () => {
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    expect(result.anchor.statement.edge_id).toBe('edge-17');
    expect(result.anchor.statement.organisation_id).toBe('org-1');
    expect(result.anchor.statement.site_id).toBe('site-1');
  });

  it('stamps signer_key_id from the RESOLVED key, so the field names what actually signed', async () => {
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome === 'ISSUED') expect(result.anchor.statement.signer_key_id).toBe(SIGNER_KEY_ID);
  });

  it('gives each anchor its own id', async () => {
    const signer = signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config()));
    const first = await signer.issueTrustedTimeAnchor(request());
    const second = await signer.issueTrustedTimeAnchor(request());
    expect(first.outcome).toBe('ISSUED');
    expect(second.outcome).toBe('ISSUED');
    if (first.outcome === 'ISSUED' && second.outcome === 'ISSUED') {
      expect(first.anchor.statement.anchor_id).not.toBe(second.anchor.statement.anchor_id);
    }
  });

  it('returns a fingerprint for audit rather than expecting the anchor to be logged', async () => {
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome === 'ISSUED') {
      expect(result.anchor_fingerprint).toBe(edgeTrustedTimeAnchorFingerprint(result.anchor.statement));
      expect(result.anchor_fingerprint).toMatch(/^[0-9a-f]{64}$/u);
    }
  });
});

describe('the six-hour ceiling is enforced BEFORE anything is signed', () => {
  it('issues at exactly the frozen lease ceiling', async () => {
    expect(EDGE_TRUSTED_TIME_ANCHOR_LIFETIME_MS).toBe(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    const lifetime = Date.parse(result.anchor.statement.server_valid_until) - Date.parse(result.anchor.statement.server_issued_at);
    expect(lifetime).toBe(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
  });

  it('never signs an over-long anchor, because the statement is parsed first', async () => {
    // The ceiling is not merely something Edge checks on receipt. A statement
    // that fails its own schema never reaches the signing call at all, so an
    // over-long anchor cannot exist with a valid signature anywhere.
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(
      request({ now: new Date('not a date') }),
    );
    expect(result).toEqual({ outcome: 'SIGNING_UNAVAILABLE', reason: 'ANCHOR_NOT_REPRESENTABLE' });
  });

  it('cannot express a field that would relax a rule at Edge', async () => {
    const result = await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config())).issueTrustedTimeAnchor(request());
    expect(result.outcome).toBe('ISSUED');
    if (result.outcome !== 'ISSUED') return;
    for (const field of EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS) {
      expect(Object.keys(result.anchor.statement)).not.toContain(field);
    }
  });
});

describe('signing unavailable is truthful, never a downgrade', () => {
  it('answers SIGNING_KEY_UNAVAILABLE with no key configured', async () => {
    const result = await signerWith(new UnavailableEdgeTrustedTimeSigningKeyProvider()).issueTrustedTimeAnchor(request());
    expect(result).toEqual({ outcome: 'SIGNING_UNAVAILABLE', reason: 'SIGNING_KEY_UNAVAILABLE' });
  });

  it('NEVER produces an unsigned or placeholder anchor on any refusal path', async () => {
    // The shape refuses to be able to express one: there is no third arm to the
    // union and no `signature: string | null`.
    const refusals = [
      await signerWith(new UnavailableEdgeTrustedTimeSigningKeyProvider()).issueTrustedTimeAnchor(request()),
      await signerWith(new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: undefined }))).issueTrustedTimeAnchor(
        request(),
      ),
      await signerWith(
        new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: join(directory, 'missing.pem') })),
      ).issueTrustedTimeAnchor(request()),
    ];
    for (const result of refusals) {
      expect(result.outcome).toBe('SIGNING_UNAVAILABLE');
      expect(result).not.toHaveProperty('anchor');
      expect(result).not.toHaveProperty('signature');
    }
  });

  it('refuses a signing key file that is not readable', async () => {
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(
      config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: join(directory, 'nope.pem') }),
    );
    await expect(provider.resolve()).resolves.toBeNull();
  });

  it('refuses material that is not a private key', async () => {
    const publicPath = join(directory, 'public.pem');
    await writeFile(publicPath, pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(), 'utf8');
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: publicPath }));
    await expect(provider.resolve()).resolves.toBeNull();
  });

  it('refuses a key on the wrong curve', async () => {
    // The version in the domain separator fixes the algorithm, so a P-384 key
    // is not a weaker key — it is a key for a statement type that does not exist.
    const other = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const path = join(directory, 'p384.pem');
    await writeFile(path, other.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), 'utf8');
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: path }));
    await expect(provider.resolve()).resolves.toBeNull();
  });

  it('refuses a key of the wrong algorithm entirely', async () => {
    const ed = generateKeyPairSync('ed25519');
    const path = join(directory, 'ed25519.pem');
    await writeFile(path, ed.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), 'utf8');
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: path }));
    await expect(provider.resolve()).resolves.toBeNull();
  });

  it('refuses unparseable material', async () => {
    const path = join(directory, 'garbage.pem');
    await writeFile(path, 'not a key at all', 'utf8');
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(config({ EDGE_TRUSTED_TIME_SIGNING_KEY_FILE: path }));
    await expect(provider.resolve()).resolves.toBeNull();
  });
});

describe('all-or-nothing configuration, and the safe default', () => {
  it('is unconfigured when the deployment has said nothing', () => {
    expect(edgeTrustedTimeSigningIsConfigured({} as AppConfig)).toBe(false);
  });

  it.each(EDGE_TRUSTED_TIME_SIGNING_KEYS)('counts %s alone as an ATTEMPT to configure', (key) => {
    expect(edgeTrustedTimeSigningIsConfigured({ [key]: 'x' } as unknown as AppConfig)).toBe(true);
  });

  it.each(EDGE_TRUSTED_TIME_SIGNING_KEYS)('refuses when only %s is set', async (key) => {
    // A key file with no signer_key_id produces anchors Edge cannot resolve
    // against its keyring — a silent failure six hours later rather than a loud
    // one at boot.
    const partial = { [key]: key === 'EDGE_TRUSTED_TIME_SIGNING_KEY_FILE' ? keyPath : SIGNER_KEY_ID } as unknown as AppConfig;
    await expect(new MountedEdgeTrustedTimeSigningKeyProvider(partial).resolve()).resolves.toBeNull();
  });
});

describe('the key is reachable for nothing else', () => {
  it('exposes only an anchor issuer, with no sign(bytes) entry point', () => {
    // The public surface is one method taking a typed request. Even inside this
    // module the provider's own sign method takes a branded type that only the
    // signer can mint.
    const methods = Object.getOwnPropertyNames(CentralTrustedTimeAnchorSigner.prototype).filter((name) => name !== 'constructor');
    expect(methods).toEqual(['issueTrustedTimeAnchor']);
  });

  it('hands back no key material on the resolved capability', async () => {
    const key = await new MountedEdgeTrustedTimeSigningKeyProvider(config()).resolve();
    expect(key).not.toBeNull();
    if (key === null) return;
    expect(Object.keys(key)).not.toContain('key');
    expect(Object.keys(key)).not.toContain('privateKey');
    expect(JSON.stringify(key)).not.toContain('PRIVATE KEY');
  });

  it('caches the resolved key rather than re-reading it per anchor', async () => {
    const provider = new MountedEdgeTrustedTimeSigningKeyProvider(config());
    expect(await provider.resolve()).toBe(await provider.resolve());
  });
});
