import { describe, expect, it, vi } from 'vitest';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  EdgeIdentityContextSchema,
  EdgeTrustedTimeAnchorStatementSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  type EdgeIdentityContext,
  type EdgeTrustedTimeAnchorStatement,
} from '@sentinel/contracts';
import { EdgeTrustedTimeAnchorVerifier } from './edge-trusted-time.verifier';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';
import { loadEdgeTrustedTimeKeyring, unconfiguredEdgeTrustedTimeKeyring, type EdgeTrustedTimeKeyring } from './edge-trusted-time.keyring';
import { generateTestAnchorSigner, signTestAnchor } from './edge-trusted-time.test-support';
import type { EdgeConfig } from '../../config/env.schema';
import type { EdgeMonotonicReading } from './edge-trusted-time.anchor';

/**
 * ============================================================================
 * WP-29B / FW2-11 Crucible — THE ORDERED VERIFICATION CHAIN.
 *
 * Every case the ruling named is here, and each one is an attack rather than a
 * shape check: this suite signs real anchors with a real P-256 key and then
 * tries to make Edge believe a time central never asserted.
 *
 * There is no clock in this file. Every monotonic reading is a number a test
 * chose, which is what lets "a wall-clock jump does not alter trusted time" be
 * asserted rather than described.
 * ============================================================================
 */

const ISSUED = '2026-08-29T12:00:00.000Z';
const HOUR = 3_600_000;
const MINUTE = 60_000;
const BOOT_ID = 'boot-4f2a';
const ANCHOR_MONOTONIC = 1_000_000;
const SIGNER_KEY_ID = 'central-tta-2026-01';
const PREVIOUS_KEY_ID = 'central-tta-2025-07';

const signer = generateTestAnchorSigner();
const previousSigner = generateTestAnchorSigner();
const strangerSigner = generateTestAnchorSigner();

const verifierService = new P256AnchorSignatureVerifier();

function iso(deltaMs: number): string {
  return new Date(Date.parse(ISSUED) + deltaMs).toISOString();
}

function identity(overrides: Partial<EdgeIdentityContext> = {}): EdgeIdentityContext {
  return EdgeIdentityContextSchema.parse({
    schema_version: 1,
    organisation_id: 'org-1',
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    authorised_site_ids: ['site-1', 'site-2'],
    ...overrides,
  });
}

function statement(overrides: Record<string, unknown> = {}): EdgeTrustedTimeAnchorStatement {
  return EdgeTrustedTimeAnchorStatementSchema.parse({
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
}

/** A genuinely signed anchor. Every negative case starts from one of these. */
function signedAnchor(overrides: Record<string, unknown> = {}): { statement: EdgeTrustedTimeAnchorStatement; signature: string } {
  const value = statement(overrides);
  return { statement: value, signature: signTestAnchor(signer.privateKey, value) };
}

function keyringConfig(entries: unknown, version = 'keyring-1'): EdgeConfig {
  return {
    EDGE_TRUSTED_TIME_VERIFICATION_KEYS: typeof entries === 'string' ? entries : JSON.stringify(entries),
    EDGE_TRUSTED_TIME_KEYRING_VERSION: version,
  } as unknown as EdgeConfig;
}

function keyring(entries: unknown = [{ signer_key_id: SIGNER_KEY_ID, public_key: signer.publicKey, role: 'ACTIVE' }]): EdgeTrustedTimeKeyring {
  return loadEdgeTrustedTimeKeyring(keyringConfig(entries), (key) => verifierService.isRuntimeValidPublicKey(key));
}

function subject(ring: EdgeTrustedTimeKeyring = keyring()): EdgeTrustedTimeAnchorVerifier {
  return new EdgeTrustedTimeAnchorVerifier(ring, verifierService);
}

/** A reading `elapsedMs` after the anchor, in the same boot. */
function reading(elapsedMs: number, bootId: string = BOOT_ID): EdgeMonotonicReading {
  return { monotonic_ms: ANCHOR_MONOTONIC + elapsedMs, boot_id: bootId };
}

function admit(anchor: unknown, at: EdgeMonotonicReading = reading(MINUTE), ring?: EdgeTrustedTimeKeyring, who: EdgeIdentityContext = identity()) {
  return subject(ring).admit({ candidate: anchor, identity: who, reading: at });
}

// ---------------------------------------------------------------------------

describe('a valid anchor is accepted', () => {
  it('admits a genuinely signed, correctly bound, in-lifetime anchor', () => {
    const result = admit(signedAnchor(), reading(90 * MINUTE));
    expect(result.admitted).toBe(true);
    if (result.admitted) expect(result.trusted_now).toBe(iso(90 * MINUTE));
  });

  it('derives trusted time from the SIGNED monotonic reading, not a local one', () => {
    const result = admit(signedAnchor(), reading(0));
    expect(result.admitted).toBe(true);
    if (result.admitted) expect(result.trusted_now).toBe(ISSUED);
  });

  it('admits an anchor for any site this Edge is authorised for', () => {
    expect(admit(signedAnchor({ site_id: 'site-2' })).admitted).toBe(true);
  });

  it('admits an anchor signed by the PREVIOUS key during a rotation', () => {
    // Refusing PREVIOUS at verification time would break every in-flight anchor
    // at the instant of rotation — the outage rotation exists to avoid.
    const value = statement({ signer_key_id: PREVIOUS_KEY_ID });
    const anchor = { statement: value, signature: signTestAnchor(previousSigner.privateKey, value) };
    const ring = keyring([
      { signer_key_id: SIGNER_KEY_ID, public_key: signer.publicKey, role: 'ACTIVE' },
      { signer_key_id: PREVIOUS_KEY_ID, public_key: previousSigner.publicKey, role: 'PREVIOUS' },
    ]);
    expect(admit(anchor, reading(MINUTE), ring).admitted).toBe(true);
  });
});

describe('every field of the statement is bound, and changing any of them is refused', () => {
  /**
   * THE CORE PROPERTY. Each case takes a genuinely signed anchor and edits ONE
   * field afterwards — exactly what an attacker with write access to the
   * persisted file can do — and the signature must stop it.
   */
  const tampered: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    // Forward by a minute: still inside the six-hour ceiling, so the edit has
    // to be caught by the SIGNATURE rather than by the schema.
    ['server_issued_at', { server_issued_at: iso(MINUTE) }],
    ['server_valid_until', { server_valid_until: iso(2 * HOUR) }],
    ['anchor_id', { anchor_id: '00000000-0000-4000-8000-000000000000' }],
    ['edge_boot_id', { edge_boot_id: 'boot-FORGED' }],
    ['edge_monotonic_at_anchor', { edge_monotonic_at_anchor: 1 }],
  ];

  it.each(tampered)('refuses an anchor whose %s was edited after signing', (field, override) => {
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, ...override }, signature: genuine.signature };
    // Guard: the case must actually change something, or it proves nothing.
    expect(canonicalEdgeTrustedTimeAnchorStatement(edited.statement as EdgeTrustedTimeAnchorStatement)).not.toBe(
      canonicalEdgeTrustedTimeAnchorStatement(genuine.statement),
    );
    expect(admit(edited, reading(MINUTE))).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
    expect(field).toBeTruthy();
  });

  it('refuses an anchor re-pointed at the other PINNED key', () => {
    // `signer_key_id` is inside the signature too. Re-pointing a genuine anchor
    // at the previous key — a key this deployment really does hold — resolves
    // successfully and then fails to verify, rather than being waved through as
    // "well, that key is trusted".
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, signer_key_id: PREVIOUS_KEY_ID }, signature: genuine.signature };
    const ring = keyring([
      { signer_key_id: SIGNER_KEY_ID, public_key: signer.publicKey, role: 'ACTIVE' },
      { signer_key_id: PREVIOUS_KEY_ID, public_key: previousSigner.publicKey, role: 'PREVIOUS' },
    ]);
    expect(admit(edited, reading(MINUTE), ring)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses an edited edge_id — caught at the signature, before the binding check', () => {
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, edge_id: 'edge-OTHER' }, signature: genuine.signature };
    expect(admit(edited)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses an edited organisation_id', () => {
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, organisation_id: 'org-OTHER' }, signature: genuine.signature };
    expect(admit(edited)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses an edited site_id', () => {
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, site_id: 'site-OTHER' }, signature: genuine.signature };
    expect(admit(edited)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });
});

describe('a genuinely signed anchor issued to somebody else is still refused', () => {
  it('refuses an anchor bound to a different edge_id', () => {
    // Signed correctly, in lifetime, same boot — and not this Edge's. Replanting
    // an anchor between two deployments of one tenant is exactly what the
    // binding exists to stop.
    expect(admit(signedAnchor({ edge_id: 'edge-OTHER' }))).toEqual({ admitted: false, refusal: 'ANCHOR_BINDING_MISMATCH' });
  });

  it('refuses an anchor bound to a different organisation_id', () => {
    expect(admit(signedAnchor({ organisation_id: 'org-OTHER' }))).toEqual({ admitted: false, refusal: 'ANCHOR_BINDING_MISMATCH' });
  });

  it('refuses an anchor for a site this Edge is not authorised for', () => {
    expect(admit(signedAnchor({ site_id: 'site-99' }))).toEqual({ admitted: false, refusal: 'ANCHOR_BINDING_MISMATCH' });
  });
});

describe('boot identity and the monotonic binding', () => {
  it('refuses a persisted anchor after a host reboot, however pristine the file', () => {
    // FW2-10, and the ruling's restart rule. The signature is perfect, the
    // lifetime has hours left, and the anchor is invalid because the counter it
    // names no longer exists.
    expect(admit(signedAnchor(), reading(MINUTE, 'boot-NEW'))).toEqual({ admitted: false, refusal: 'BOOT_IDENTITY_CHANGED' });
  });

  it('refuses a reboot whose fresh counter is SMALLER, rather than deriving a negative interval', () => {
    const result = admit(signedAnchor(), { monotonic_ms: 12, boot_id: 'boot-NEW' });
    expect(result).toEqual({ admitted: false, refusal: 'BOOT_IDENTITY_CHANGED' });
  });

  it('refuses a monotonic reading behind the signed one within the same boot', () => {
    expect(admit(signedAnchor(), reading(-1))).toEqual({ admitted: false, refusal: 'MONOTONIC_WENT_BACKWARDS' });
  });

  it('recovers on a restart within the SAME boot', () => {
    // The whole benefit persistence buys: the process died, the machine did not,
    // and the anchor is carried forward without a round trip to central.
    const persisted = JSON.parse(JSON.stringify(signedAnchor())) as unknown;
    const result = admit(persisted, reading(3 * HOUR));
    expect(result.admitted).toBe(true);
    if (result.admitted) expect(result.trusted_now).toBe(iso(3 * HOUR));
  });
});

describe('the signer must be one this deployment pinned', () => {
  it('refuses an unknown signer_key_id without attempting any key', () => {
    // BY ID, never by trial. Trying every pinned key until one verified would
    // make `signer_key_id` decorative and would admit an anchor signed by a key
    // the statement did not name.
    const value = statement({ signer_key_id: 'central-tta-UNKNOWN' });
    const anchor = { statement: value, signature: signTestAnchor(signer.privateKey, value) };
    expect(admit(anchor)).toEqual({ admitted: false, refusal: 'SIGNER_KEY_UNKNOWN' });
  });

  it('refuses an anchor signed by a stranger holding the pinned key id', () => {
    const value = statement();
    const anchor = { statement: value, signature: signTestAnchor(strangerSigner.privateKey, value) };
    expect(admit(anchor)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses when the pinned public key is the wrong one for that id', () => {
    const ring = keyring([{ signer_key_id: SIGNER_KEY_ID, public_key: strangerSigner.publicKey, role: 'ACTIVE' }]);
    expect(admit(signedAnchor(), reading(MINUTE), ring)).toEqual({ admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses everything when no keyring is configured', () => {
    expect(admit(signedAnchor(), reading(MINUTE), unconfiguredEdgeTrustedTimeKeyring())).toEqual({
      admitted: false,
      refusal: 'KEYRING_UNAVAILABLE',
    });
  });

  it('distinguishes "we never heard of that key" from "that key did not sign this"', () => {
    // Two different operator problems: a keyring that was not rotated, versus a
    // file somebody edited. Collapsing them into one refusal would send whoever
    // is debugging to the wrong place.
    const unknown = statement({ signer_key_id: 'nope' });
    expect(admit({ statement: unknown, signature: signTestAnchor(signer.privateKey, unknown) })).toEqual({
      admitted: false,
      refusal: 'SIGNER_KEY_UNKNOWN',
    });
    const wrongSigner = statement();
    expect(admit({ statement: wrongSigner, signature: signTestAnchor(strangerSigner.privateKey, wrongSigner) })).toEqual({
      admitted: false,
      refusal: 'SIGNATURE_NOT_VERIFIED',
    });
  });
});

describe('corrupted, malformed and absent anchors', () => {
  it('refuses a corrupted signature', () => {
    const genuine = signedAnchor();
    const corrupted = Buffer.from(genuine.signature, 'base64url');
    corrupted[10] = (corrupted[10] as number) ^ 0xff;
    expect(admit({ ...genuine, signature: corrupted.toString('base64url') })).toEqual({
      admitted: false,
      refusal: 'SIGNATURE_NOT_VERIFIED',
    });
  });

  it.each([null, undefined])('refuses %s as no anchor at all', (candidate) => {
    expect(admit(candidate)).toEqual({ admitted: false, refusal: 'NO_ANCHOR' });
  });

  it.each([
    ['a truncated signature', { signature: 'AAAA' }],
    ['a padded signature', { signature: 'AAAA=' }],
    ['a non-base64url signature', { signature: 'not a signature!!' }],
  ])('refuses %s at the parse boundary', (_label, override) => {
    expect(admit({ ...signedAnchor(), ...override })).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });

  it.each([{}, [], 'a string', 42, { statement: {}, signature: 'x' }])('refuses the non-anchor %#', (candidate) => {
    expect(admit(candidate)).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });

  it('refuses a signed anchor carrying an extra field', () => {
    expect(admit({ ...signedAnchor(), trusted_now: iso(0) })).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });

  it('refuses a statement carrying a field that would relax a rule', () => {
    const genuine = signedAnchor();
    const edited = { statement: { ...genuine.statement, allow_wall_clock: true }, signature: genuine.signature };
    expect(admit(edited)).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });
});

describe('the six-hour ceiling cannot be signed past', () => {
  it('refuses an over-long anchor at the parse, BEFORE the signature is even checked', () => {
    // The ceiling is not merely something Edge checks — it is something that
    // can never acquire a meaningful signature, because a statement that fails
    // its own schema never reaches the verifier's signature step. A compromised
    // signing key therefore cannot mint a week-long anchor.
    const overLong = {
      ...statement(),
      server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + 1),
    };
    const anchor = { statement: overLong, signature: signTestAnchor(signer.privateKey, overLong as EdgeTrustedTimeAnchorStatement) };
    expect(admit(anchor)).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });

  it('accepts exactly the ceiling', () => {
    expect(admit(signedAnchor({ server_valid_until: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS) })).admitted).toBe(true);
  });

  it('refuses a BACK-DATED issued_at that stretches the window past the ceiling', () => {
    // The attacker's most natural edit: move `server_issued_at` earlier so the
    // derived instant lands wherever they want. Two independent rules refuse it
    // — the ceiling at the parse, and the signature immediately after — and the
    // parse wins, which means it never even reaches the crypto.
    const genuine = signedAnchor();
    const backdated = { statement: { ...genuine.statement, server_issued_at: iso(-4 * HOUR) }, signature: genuine.signature };
    expect(admit(backdated)).toEqual({ admitted: false, refusal: 'ANCHOR_MALFORMED' });
  });
});

describe('expiry, and the two clocks that cannot extend it', () => {
  it('admits one millisecond before server_valid_until', () => {
    expect(admit(signedAnchor(), reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS - 1)).admitted).toBe(true);
  });

  it('refuses at exactly server_valid_until, because the boundary is exclusive', () => {
    expect(admit(signedAnchor(), reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS))).toEqual({
      admitted: false,
      refusal: 'ANCHOR_EXPIRED',
    });
  });

  it('refuses an expired anchor', () => {
    expect(admit(signedAnchor(), reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + HOUR))).toEqual({
      admitted: false,
      refusal: 'ANCHOR_EXPIRED',
    });
  });

  it('honours a SHORTER central-issued lifetime at its own boundary', () => {
    const short = signedAnchor({ server_valid_until: iso(15 * MINUTE) });
    expect(admit(short, reading(15 * MINUTE - 1)).admitted).toBe(true);
    expect(admit(short, reading(15 * MINUTE))).toEqual({ admitted: false, refusal: 'ANCHOR_EXPIRED' });
  });

  it('A WALL-CLOCK JUMP DOES NOT ALTER TRUSTED TIME', () => {
    // Someone with physical access moves the appliance clock four hours back —
    // or four hours forward. The derived instant is identical, because the host
    // clock is not an input to any step in the chain.
    const anchor = signedAnchor();
    const before = admit(anchor, reading(2 * HOUR));

    const jumped = vi.spyOn(Date, 'now').mockReturnValue(Date.parse(ISSUED) - 4 * HOUR);
    const during = admit(anchor, reading(2 * HOUR));
    jumped.mockReturnValue(Date.parse(ISSUED) + 400 * HOUR);
    const after = admit(anchor, reading(2 * HOUR));
    jumped.mockRestore();

    expect(during).toEqual(before);
    expect(after).toEqual(before);
    if (before.admitted) expect(before.trusted_now).toBe(iso(2 * HOUR));
  });

  it('AN NTP ROLLBACK DOES NOT EXTEND THE ANCHOR', () => {
    // A disciplining daemon steps the clock backwards past the anchor's issue
    // instant. An implementation that judged expiry against the host clock
    // would decide the anchor was young again; this one does not consult it, so
    // an expired anchor stays expired.
    const anchor = signedAnchor();
    const rolledBack = vi.spyOn(Date, 'now').mockReturnValue(Date.parse(ISSUED) - 24 * HOUR);
    const result = admit(anchor, reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + MINUTE));
    rolledBack.mockRestore();
    expect(result).toEqual({ admitted: false, refusal: 'ANCHOR_EXPIRED' });
  });

  it('never reads the host clock on the admitting path either', () => {
    const nowSpy = vi.spyOn(Date, 'now');
    admit(signedAnchor(), reading(MINUTE));
    expect(nowSpy).not.toHaveBeenCalled();
    nowSpy.mockRestore();
  });
});

describe('there is no unsigned path to trusted time', () => {
  it('produces no admission from any refusal, whatever the reason', () => {
    const refusals = [
      admit(null),
      admit({ ...signedAnchor(), signature: 'AAAA' }),
      admit(signedAnchor({ edge_id: 'edge-OTHER' })),
      admit(signedAnchor(), reading(MINUTE, 'boot-NEW')),
      admit(signedAnchor(), reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS)),
      admit(signedAnchor(), reading(MINUTE), unconfiguredEdgeTrustedTimeKeyring()),
    ];
    for (const result of refusals) {
      expect(result.admitted).toBe(false);
      expect(result).not.toHaveProperty('trusted_now');
      expect(result).not.toHaveProperty('anchor');
    }
  });

  it('has no refusal that is silently treated as TIME_NOT_AUTHORITATIVE-but-usable', () => {
    const unreadable = admit({ ...signedAnchor(), statement: { ...statement(), server_issued_at: 'nope' } });
    expect(unreadable.admitted).toBe(false);
    // The strict schema catches it first, which is stronger than the fallback.
    expect([DEVICE_TIME_NOT_AUTHORITATIVE, 'ANCHOR_MALFORMED']).toContain(
      unreadable.admitted ? '' : unreadable.refusal,
    );
  });
});
