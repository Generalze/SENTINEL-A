import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  canonicalEdgeTrustedTimeAnchorStatement,
  encodeCanonicalP256Signature,
  type EdgeTrustedTimeAnchorStatement,
} from '@sentinel/contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { CentralEdgeTrustedTimeVerifier, isVerifiedEdgeTrustedTimeEvidence } from './central-edge-trusted-time.verifier';
import { CentralTrustedTimeKeyringProvider } from './central-trusted-time-verification.keyring';

/**
 * THE POINT OF THIS FILE.
 *
 * Before M3B §7 the offline path could tell whether an Edge's claimed time was
 * PLAUSIBLE. A compromised Edge that asserts a well-shaped recent timestamp
 * passes plausibility. Every test below is a way that would have worked, and
 * now does not.
 *
 * Each refusal is proven REACHABLE. A refusal code no test can produce is a
 * branch nobody has evidence about, and in a verifier that is the branch an
 * attacker gets to explore first.
 */

const SIGNER_KEY_ID = 'central-tta-2026-01';
const EDGE_ID = 'edge-17';
const ORG_ID = 'org-1';
const SITE_ID = 'site-1';
const BOOT_ID = 'boot-4f2a';

const ANCHOR_MONOTONIC = 1_000_000;
const ISSUED_AT = '2026-09-07T00:00:00.000Z';
const VALID_UNTIL = '2026-09-07T06:00:00.000Z';

let privateKey: KeyObject;
let canonicalPublicKey: string;

/** Base64url SEC1 uncompressed point, the form the registry and keyring use. */
function canonicalPoint(key: KeyObject): string {
  const raw = key.export({ format: 'jwk' });
  const x = Buffer.from(String(raw.x), 'base64url');
  const y = Buffer.from(String(raw.y), 'base64url');
  return Buffer.concat([Buffer.from([0x04]), x, y]).toString('base64url');
}

/**
 * Signs canonical statement bytes and returns the CANONICAL LOW-S wire form.
 *
 * `createSign` emits either S or n-S at random, and the contract brands only
 * low-S -- deliberately, so one mathematical signature has exactly one wire
 * form (C14-01). A test helper that skipped this would fail about half the
 * time for a reason that looks nothing like its cause, so the canonicalisation
 * that every real signer performs is performed here too.
 */
function sign(message: string): string {
  const signer = createSign('sha256');
  signer.update(Buffer.from(message, 'utf8'));
  signer.end();
  const raw = signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
  const rawS = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
  const s = rawS > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - rawS : rawS;
  return encodeCanonicalP256Signature(r, s);
}

function statement(overrides: Partial<EdgeTrustedTimeAnchorStatement> = {}): EdgeTrustedTimeAnchorStatement {
  return {
    schema_version: 1,
    anchor_id: '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
    edge_id: EDGE_ID,
    organisation_id: ORG_ID,
    site_id: SITE_ID,
    edge_boot_id: BOOT_ID,
    edge_monotonic_at_anchor: ANCHOR_MONOTONIC,
    server_issued_at: ISSUED_AT,
    server_valid_until: VALID_UNTIL,
    signer_key_id: SIGNER_KEY_ID,
    ...overrides,
  } as EdgeTrustedTimeAnchorStatement;
}

function signedAnchor(st: EdgeTrustedTimeAnchorStatement): Record<string, unknown> {
  return { statement: st, signature: sign(canonicalEdgeTrustedTimeAnchorStatement(st)) };
}

function evidence(overrides: Record<string, unknown> = {}, st = statement()): Record<string, unknown> {
  return {
    schema_version: 1,
    signed_anchor: signedAnchor(st),
    edge_boot_id: BOOT_ID,
    edge_monotonic_at_observation: ANCHOR_MONOTONIC + 30_000,
    ...overrides,
  };
}

/** The instant central will derive for the default evidence: issued + 30s. */
const DERIVED_ISO = new Date(Date.parse(ISSUED_AT) + 30_000).toISOString();

const context = {
  edgeId: EDGE_ID,
  organisationId: ORG_ID,
  siteId: SITE_ID,
} as never;

function verifierWith(keysJson: string | undefined): CentralEdgeTrustedTimeVerifier {
  const config = { values: { EDGE_TRUSTED_TIME_VERIFICATION_KEYS: keysJson } } as never;
  return new CentralEdgeTrustedTimeVerifier(new CentralTrustedTimeKeyringProvider(config), new P256KeyImporter());
}

function configuredVerifier(): CentralEdgeTrustedTimeVerifier {
  return verifierWith(
    JSON.stringify([{ signer_key_id: SIGNER_KEY_ID, public_key: canonicalPublicKey, role: 'ACTIVE' }]),
  );
}

beforeAll(() => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  privateKey = pair.privateKey;
  canonicalPublicKey = canonicalPoint(pair.publicKey);
});

describe('central verification of Edge trusted-time evidence', () => {
  it('accepts evidence whose anchor central actually signed, and derives the time itself', () => {
    const result = configuredVerifier().verify(context, evidence(), DERIVED_ISO);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The value recorded is CENTRAL'S computation. The Edge's claim was
    // required to equal it, but it is not the value that survives.
    expect(result.evidence.verifiedTrustedTime.toISOString()).toBe(DERIVED_ISO);
    expect(result.evidence.anchorId).toBe('3f2504e0-4f89-11d3-9a0c-0305e82c3301');
    expect(result.evidence.signerKeyId).toBe(SIGNER_KEY_ID);
    expect(result.evidence.edgeMonotonicPosition).toBe(ANCHOR_MONOTONIC + 30_000);
  });

  it('mints something only this module can construct', () => {
    const result = configuredVerifier().verify(context, evidence(), DERIVED_ISO);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(isVerifiedEdgeTrustedTimeEvidence(result.evidence)).toBe(true);
    // An object with the right FIELDS is not the right TYPE. This is what
    // stops a plain literal being passed to the admissibility path.
    expect(
      isVerifiedEdgeTrustedTimeEvidence({
        anchorId: 'x',
        anchorFingerprint: 'x',
        signerKeyId: SIGNER_KEY_ID,
        verifiedTrustedTime: new Date(),
        edgeMonotonicPosition: 1,
      }),
    ).toBe(false);
  });

  it('refuses when no evidence accompanied the receipt', () => {
    expect(configuredVerifier().verify(context, null, DERIVED_ISO)).toMatchObject({ refusal: 'EVIDENCE_ABSENT' });
  });

  it('refuses malformed evidence', () => {
    expect(configuredVerifier().verify(context, { nonsense: true }, DERIVED_ISO)).toMatchObject({
      refusal: 'EVIDENCE_MALFORMED',
    });
  });

  // A deployment that cannot verify must refuse, not wave the evidence
  // through. This is the branch that decides whether an unconfigured central
  // is fail-open or fail-closed.
  it('refuses when it has no keyring at all', () => {
    expect(verifierWith(undefined).verify(context, evidence(), DERIVED_ISO)).toMatchObject({
      refusal: 'KEYRING_UNAVAILABLE',
    });
  });

  // Resolution is BY ID. If this ever fell back to trying every key, a
  // compromised retired key would keep working for anything naming another id.
  it('refuses an anchor naming a signer it does not hold', () => {
    const other = statement({ signer_key_id: 'central-tta-2099-12' });
    expect(configuredVerifier().verify(context, evidence({}, other), DERIVED_ISO)).toMatchObject({
      refusal: 'SIGNER_KEY_UNKNOWN',
    });
  });

  // THE CENTRAL CLAIM OF §7. A well-formed anchor that central did not sign
  // is worth nothing, however plausible its contents.
  it('refuses an anchor central did not sign', () => {
    const forged = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const foreign = verifierWith(
      JSON.stringify([{ signer_key_id: SIGNER_KEY_ID, public_key: canonicalPoint(forged.publicKey), role: 'ACTIVE' }]),
    );
    expect(foreign.verify(context, evidence(), DERIVED_ISO)).toMatchObject({ refusal: 'ANCHOR_SIGNATURE_INVALID' });
  });

  it('refuses a genuine signature over a tampered statement', () => {
    // Signature computed over the ORIGINAL statement, then the statement
    // swapped. Canonical bytes are recomputed from the parsed statement, so
    // the substitution cannot survive.
    const original = statement();
    const tampered = { ...signedAnchor(original), statement: statement({ edge_monotonic_at_anchor: 1 }) };
    const result = configuredVerifier().verify(context, evidence({ signed_anchor: tampered }), DERIVED_ISO);
    expect(result).toMatchObject({ refusal: 'ANCHOR_SIGNATURE_INVALID' });
  });

  // A REAL central signature over a statement about somebody else. The
  // signature verifies; the anchor still says nothing about this caller.
  it.each([
    ['edge_id', { edge_id: 'edge-99' }, 'ANCHOR_EDGE_MISMATCH'],
    ['organisation_id', { organisation_id: 'org-2' }, 'ANCHOR_ORGANISATION_MISMATCH'],
    ['site_id', { site_id: 'site-2' }, 'ANCHOR_SITE_MISMATCH'],
  ])('refuses a validly signed anchor issued to a different %s', (_label, override, expected) => {
    const other = statement(override as Partial<EdgeTrustedTimeAnchorStatement>);
    expect(configuredVerifier().verify(context, evidence({}, other), DERIVED_ISO)).toMatchObject({
      refusal: expected,
    });
  });

  // Monotonic readings are comparable only within one boot. Measuring an
  // observation against another boot's anchor is arithmetic on unrelated
  // origins, and would produce a confident wrong answer rather than a failure.
  it('refuses an observation from a different boot than the anchor', () => {
    expect(configuredVerifier().verify(context, evidence({ edge_boot_id: 'boot-other' }), DERIVED_ISO)).toMatchObject({
      refusal: 'ANCHOR_BOOT_MISMATCH',
    });
  });

  it('refuses a monotonic counter that went backwards within a boot', () => {
    const result = configuredVerifier().verify(
      context,
      evidence({ edge_monotonic_at_observation: ANCHOR_MONOTONIC - 1 }),
      DERIVED_ISO,
    );
    expect(result).toMatchObject({ refusal: 'MONOTONIC_WENT_BACKWARDS' });
  });

  // The anchor's expiry bounds how far forward it can carry a derivation.
  // Without this an Edge could hold one anchor and keep counting for ever --
  // exactly the holdover the anchor design refuses.
  it('refuses a derivation that runs past the anchor expiry', () => {
    const sevenHours = 7 * 60 * 60 * 1000;
    const result = configuredVerifier().verify(
      context,
      evidence({ edge_monotonic_at_observation: ANCHOR_MONOTONIC + sevenHours }),
      new Date(Date.parse(ISSUED_AT) + sevenHours).toISOString(),
    );
    expect(result).toMatchObject({ refusal: 'DERIVED_TIME_AFTER_ANCHOR_EXPIRY' });
  });

  // The step that makes the frozen receipt's timestamp mean something: it is
  // no longer a value the Edge chose, it is one central recomputed and matched.
  it('refuses when the receipt time disagrees with what central derived', () => {
    const wrongByOneSecond = new Date(Date.parse(DERIVED_ISO) + 1000).toISOString();
    expect(configuredVerifier().verify(context, evidence(), wrongByOneSecond)).toMatchObject({
      refusal: 'RECEIPT_TIME_DISAGREES_WITH_DERIVATION',
    });
  });

  it('refuses when the receipt witnessed no trusted time at all', () => {
    expect(configuredVerifier().verify(context, evidence(), null)).toMatchObject({
      refusal: 'RECEIPT_TIME_DISAGREES_WITH_DERIVATION',
    });
  });

  // A keyring with two ACTIVE keys is an ambiguity, and this codebase refuses
  // ambiguities rather than picking one.
  it('refuses to load a keyring with two active keys', () => {
    const ambiguous = verifierWith(
      JSON.stringify([
        { signer_key_id: 'a', public_key: canonicalPublicKey, role: 'ACTIVE' },
        { signer_key_id: 'b', public_key: canonicalPublicKey, role: 'ACTIVE' },
      ]),
    );
    expect(ambiguous.verify(context, evidence(), DERIVED_ISO)).toMatchObject({ refusal: 'KEYRING_UNAVAILABLE' });
  });

  // A PREVIOUS key must keep verifying after a rotation. Anchors live up to
  // the six-hour ceiling, so a verifier that only knew the ACTIVE key would
  // start refusing every in-flight anchor the moment a key was rotated.
  it('still verifies an anchor signed by a rotated PREVIOUS key', () => {
    const active = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rotated = verifierWith(
      JSON.stringify([
        { signer_key_id: 'central-tta-2026-02', public_key: canonicalPoint(active.publicKey), role: 'ACTIVE' },
        { signer_key_id: SIGNER_KEY_ID, public_key: canonicalPublicKey, role: 'PREVIOUS' },
      ]),
    );
    expect(rotated.verify(context, evidence(), DERIVED_ISO).ok).toBe(true);
  });
});
