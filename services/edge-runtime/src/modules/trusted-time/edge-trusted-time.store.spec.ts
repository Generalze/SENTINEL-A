import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  EdgeIdentityContextSchema,
  EdgeTrustedTimeAnchorStatementSchema,
  SignedEdgeTrustedTimeAnchorSchema,
  type SignedEdgeTrustedTimeAnchor,
} from '@sentinel/contracts';
import {
  EDGE_TRUSTED_TIME_ANCHOR_FILENAME,
  FileSystemEdgeTrustedTimeAnchorStore,
  VolatileEdgeTrustedTimeAnchorStore,
} from './edge-trusted-time.store';
import { EdgeTrustedTimeAnchorVerifier } from './edge-trusted-time.verifier';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';
import { loadEdgeTrustedTimeKeyring } from './edge-trusted-time.keyring';
import { generateTestAnchorSigner, signTestAnchor } from './edge-trusted-time.test-support';
import type { EdgeConfigService } from '../../config/config.service';
import type { EdgeConfig } from '../../config/env.schema';

/**
 * WP-29B Crucible — persistence, and the restart it makes safe.
 *
 * The point of this suite is not that a file round-trips. It is that THE STORE
 * IS NOT A TRUST BOUNDARY: an attacker with write access to the anchor file can
 * do anything they like to it, and every outcome is a refusal.
 */

const ISSUED = '2026-08-29T12:00:00.000Z';
const MINUTE = 60_000;
const HOUR = 3_600_000;
const BOOT_ID = 'boot-4f2a';
const ANCHOR_MONOTONIC = 1_000_000;
const SIGNER_KEY_ID = 'central-tta-2026-01';

const signer = generateTestAnchorSigner();
const signatures = new P256AnchorSignatureVerifier();

const identity = EdgeIdentityContextSchema.parse({
  schema_version: 1,
  organisation_id: 'org-1',
  edge_id: 'edge-17',
  edge_key_id: 'edge-key-1',
  edge_key_version: 1,
  claimed_signature_profile: 'P256_ECDSA_SHA256',
  authorised_site_ids: ['site-1'],
});

const keyring = loadEdgeTrustedTimeKeyring(
  {
    EDGE_TRUSTED_TIME_VERIFICATION_KEYS: JSON.stringify([{ signer_key_id: SIGNER_KEY_ID, public_key: signer.publicKey, role: 'ACTIVE' }]),
    EDGE_TRUSTED_TIME_KEYRING_VERSION: 'keyring-1',
  } as unknown as EdgeConfig,
  (key) => signatures.isRuntimeValidPublicKey(key),
);
const verifier = new EdgeTrustedTimeAnchorVerifier(keyring, signatures);

function iso(deltaMs: number): string {
  return new Date(Date.parse(ISSUED) + deltaMs).toISOString();
}

function signedAnchor(overrides: Record<string, unknown> = {}): SignedEdgeTrustedTimeAnchor {
  const statement = EdgeTrustedTimeAnchorStatementSchema.parse({
    schema_version: 1,
    anchor_id: '9c4e1f80-1a2b-4c3d-8e5f-6a7b8c9d0e1f',
    edge_id: 'edge-17',
    organisation_id: 'org-1',
    site_id: 'site-1',
    edge_boot_id: BOOT_ID,
    edge_monotonic_at_anchor: ANCHOR_MONOTONIC,
    server_issued_at: ISSUED,
    server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS),
    signer_key_id: SIGNER_KEY_ID,
    ...overrides,
  });
  return SignedEdgeTrustedTimeAnchorSchema.parse({ statement, signature: signTestAnchor(signer.privateKey, statement) });
}

let directory: string;
let store: FileSystemEdgeTrustedTimeAnchorStore;

function configService(queuePath: string): EdgeConfigService {
  return { values: { EDGE_QUEUE_PATH: queuePath } } as unknown as EdgeConfigService;
}

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'sentinel-edge-anchor-'));
  store = new FileSystemEdgeTrustedTimeAnchorStore(configService(directory));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

describe('the volatile store stays the absence-of-trust behaviour', () => {
  it('holds nothing across a restart and does not complain', async () => {
    // Kept deliberately. It is not a placeholder: it is the correct wiring for
    // a deployment with no pinned keyring, and for every cold-start test.
    const volatileStore = new VolatileEdgeTrustedTimeAnchorStore();
    await expect(volatileStore.save(signedAnchor())).resolves.toBeUndefined();
    await expect(volatileStore.load()).resolves.toBeNull();
    await expect(volatileStore.clear()).resolves.toBeUndefined();
  });

  it('leaves a resumed Edge with no trusted time', async () => {
    const volatileStore = new VolatileEdgeTrustedTimeAnchorStore();
    const result = verifier.admit({
      candidate: await volatileStore.load(),
      identity,
      reading: { monotonic_ms: ANCHOR_MONOTONIC, boot_id: BOOT_ID },
    });
    expect(result).toEqual({ admitted: false, refusal: 'NO_ANCHOR' });
  });
});

describe('what is persisted is the signed original', () => {
  it('writes exactly the statement and the signature, and nothing derived', async () => {
    const anchor = signedAnchor();
    await store.save(anchor);
    const written = JSON.parse(await readFile(join(directory, EDGE_TRUSTED_TIME_ANCHOR_FILENAME), 'utf8')) as Record<string, unknown>;
    // No cached trusted_now, no remembered expiry, no verified flag — each would
    // be a value produced BY verification that is then trusted WITHOUT it.
    expect(Object.keys(written).sort()).toEqual(['signature', 'statement']);
    expect(written.signature).toBe(anchor.signature);
    expect(written.statement).toEqual(anchor.statement);
  });

  it('returns the candidate as UNVERIFIED bytes, so a caller cannot skip the chain', async () => {
    await store.save(signedAnchor());
    const candidate = await store.load();
    // Typed `unknown` on purpose. What comes off a disk is a candidate.
    expect(candidate).not.toBeNull();
    expect(typeof candidate).toBe('object');
  });

  it('overwrites the previous anchor on refresh', async () => {
    await store.save(signedAnchor());
    const refreshed = signedAnchor({ anchor_id: '11111111-2222-4333-8444-555555555555' });
    await store.save(refreshed);
    const candidate = (await store.load()) as { statement: { anchor_id: string } };
    expect(candidate.statement.anchor_id).toBe('11111111-2222-4333-8444-555555555555');
  });

  it('leaves no temporary file behind, because the write is rename-based', async () => {
    await store.save(signedAnchor());
    const { readdir } = await import('node:fs/promises');
    expect((await readdir(directory)).filter((name) => name.endsWith('.tmp'))).toHaveLength(0);
  });
});

describe('a restart within the same boot recovers', () => {
  it('carries trusted time forward without a round trip to central', async () => {
    // The whole benefit persistence buys. The process died; the machine did not.
    await store.save(signedAnchor());
    const reopened = new FileSystemEdgeTrustedTimeAnchorStore(configService(directory));
    const result = verifier.admit({
      candidate: await reopened.load(),
      identity,
      reading: { monotonic_ms: ANCHOR_MONOTONIC + 2 * HOUR, boot_id: BOOT_ID },
    });
    expect(result.admitted).toBe(true);
    if (result.admitted) expect(result.trusted_now).toBe(iso(2 * HOUR));
  });

  it('refuses the persisted anchor after a HOST REBOOT', async () => {
    // FW2-10 and the ruling's restart rule. The file is pristine, the signature
    // verifies, hours of lifetime remain — and the boot identity differs, so the
    // counter the anchor names no longer exists.
    await store.save(signedAnchor());
    const reopened = new FileSystemEdgeTrustedTimeAnchorStore(configService(directory));
    const result = verifier.admit({
      candidate: await reopened.load(),
      identity,
      reading: { monotonic_ms: 42, boot_id: 'boot-AFTER-REBOOT' },
    });
    expect(result).toEqual({ admitted: false, refusal: 'BOOT_IDENTITY_CHANGED' });
  });

  it('refuses a persisted anchor that has since expired', async () => {
    await store.save(signedAnchor());
    const result = verifier.admit({
      candidate: await store.load(),
      identity,
      reading: { monotonic_ms: ANCHOR_MONOTONIC + DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS, boot_id: BOOT_ID },
    });
    expect(result).toEqual({ admitted: false, refusal: 'ANCHOR_EXPIRED' });
  });
});

describe('the store is not a trust boundary', () => {
  const path = (): string => join(directory, EDGE_TRUSTED_TIME_ANCHOR_FILENAME);

  async function admitPersisted(bootId = BOOT_ID) {
    return verifier.admit({
      candidate: await store.load(),
      identity,
      reading: { monotonic_ms: ANCHOR_MONOTONIC + MINUTE, boot_id: bootId },
    });
  }

  it('refuses an absent file', async () => {
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'NO_ANCHOR' });
  });

  it('refuses a truncated file', async () => {
    await store.save(signedAnchor());
    const raw = await readFile(path(), 'utf8');
    await writeFile(path(), raw.slice(0, raw.length / 2));
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'NO_ANCHOR' });
  });

  it('refuses a file rewritten with an EDITED statement', async () => {
    // The attack the round-1 STOP was about: back-date the anchor and every
    // derived instant moves. The signature stops it.
    const anchor = signedAnchor();
    await writeFile(
      path(),
      JSON.stringify({ statement: { ...anchor.statement, server_issued_at: iso(-2 * HOUR) }, signature: anchor.signature }),
    );
    const result = await admitPersisted();
    expect(result.admitted).toBe(false);
    if (!result.admitted) expect(['SIGNATURE_NOT_VERIFIED', 'ANCHOR_MALFORMED']).toContain(result.refusal);
  });

  it('refuses a file rewritten with a LOWERED monotonic reading', async () => {
    // The subtler attack, and the reason the monotonic reading is inside the
    // signature: lowering it moves every derived instant FORWARD by the
    // difference, with central's wall time untouched.
    const anchor = signedAnchor();
    await writeFile(path(), JSON.stringify({ statement: { ...anchor.statement, edge_monotonic_at_anchor: 1 }, signature: anchor.signature }));
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it("refuses another Edge's genuinely signed anchor planted in this file", async () => {
    await writeFile(path(), JSON.stringify(signedAnchor({ edge_id: 'edge-OTHER' })));
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'ANCHOR_BINDING_MISMATCH' });
  });

  it('refuses a file replaced with arbitrary JSON', async () => {
    await writeFile(path(), JSON.stringify({ trusted_now: iso(0) }));
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });

  it('clears without error when there is nothing to clear', async () => {
    await expect(store.clear()).resolves.toBeUndefined();
    expect(await admitPersisted()).toEqual({ admitted: false, refusal: 'NO_ANCHOR' });
  });

  it('does not throw when the directory cannot be written', async () => {
    // Persistence is an optimisation over the volatile behaviour, never what
    // makes an anchor trustworthy. An Edge that fell over because its disk was
    // full would have turned a degraded state into an outage.
    const unwritable = new FileSystemEdgeTrustedTimeAnchorStore(configService(join(directory, 'x y')));
    await expect(unwritable.save(signedAnchor())).resolves.toBeUndefined();
    await expect(unwritable.load()).resolves.toBeNull();
  });
});
