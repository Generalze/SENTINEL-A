import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  P256_SCALAR_BYTES,
  WHISPER_DEVICE_ACTION_V2_DOMAIN,
  WHISPER_DEVICE_ACTION_V2_PROFILE,
  WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS,
  WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN,
  WhisperDeviceActionSubmissionV2Schema,
  WhisperDeviceActionV2ClaimsSchema,
  canonicalWhisperDeviceActionV2Statement,
  deriveP256PublicKeyThumbprint,
  encodeCanonicalP256Signature,
  evaluateWhisperDeviceActionV2Admissibility,
  lowSCanonicaliseForSigning,
  whisperDeviceActionV2Fingerprint,
  whisperDeviceActionV2ReplayIdentity,
  whisperDeviceActionV2ReplayKey,
  whisperDeviceActionV2StatementInput,
  whisperDeviceActionV2Submission,
  type AuthenticatedDeviceContext,
  type WhisperDeviceActionV2RegistryFacts,
} from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';

/**
 * WP-27 — THE COMMITTED INTEROPERABILITY FIXTURE.
 *
 * `fixtures/whisper-device-action-v2.interop.json` is a frozen, byte-exact
 * example of the v2 statement: the server-resolved identity, the client claims,
 * the P-256 public key, one recorded signature, the canonical statement, its
 * SHA-256, and the replay identity it derives.
 *
 * WHY A FILE RATHER THAN A SHARED HELPER. The Android client cannot import this
 * repository's TypeScript, and a second implementation of a canonicaliser is
 * exactly how two sides of a signature scheme come to disagree about what was
 * signed — silently, and only for the inputs nobody thought to try. A committed
 * artefact is the only thing both sides can assert BYTE EQUALITY against. A
 * later Android test reads THIS FILE and must reproduce `canonical_statement`
 * character for character; if it cannot, the client is wrong, or this is, and
 * either way the disagreement surfaces as a failing test rather than as a
 * signature that mysteriously does not verify in the field.
 *
 * THE KEY IN THE FILE IS A TEST KEY, AND THE FILE SAYS SO IN ITS OWN TEXT. It
 * was generated once for this fixture, is registered to no device, and its
 * private half exists only so an implementation can reproduce a signature over
 * these exact bytes. That is asserted below, so the warning cannot be quietly
 * deleted.
 *
 * ECDSA IS RANDOMISED, so the recorded signature is EVIDENCE, not a target: a
 * conforming implementation produces a DIFFERENT signature over the same bytes,
 * and both verify. What must match byte for byte is the STATEMENT.
 */

const FIXTURE_PATH = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'whisper-device-action-v2.interop.json');

interface InteropFixture {
  readonly fixture_version: number;
  readonly fixture_id: string;
  readonly what_this_is: string;
  readonly key_material_warning: string;
  readonly profile: Record<string, string>;
  readonly domains: { readonly statement: string; readonly replay_identity: string };
  readonly key: {
    readonly private_key_pkcs8_der_base64: string;
    readonly public_key_canonical_base64url: string;
    readonly public_key_thumbprint_sha256_hex: string;
  };
  readonly server_resolved_signature_profile: string;
  readonly server_resolved_identity: Record<string, string>;
  readonly client_claims: Record<string, unknown>;
  readonly canonical_statement: string;
  readonly canonical_statement_sha256_hex: string;
  readonly replay_identity: Record<string, unknown>;
  readonly replay_key: string;
  readonly replay_identity_digest_sha256_hex: string;
  readonly expected: Record<string, unknown>;
}

const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as InteropFixture;

/** The DER SubjectPublicKeyInfo prefix for an uncompressed P-256 point. */
const P256_SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

function importPublicKey(canonical: string): ReturnType<typeof createPublicKey> {
  return createPublicKey({
    key: Buffer.concat([P256_SPKI_HEADER, Buffer.from(canonical, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
}

function verifySignature(canonicalPublicKey: string, message: string, signature: string): boolean {
  return cryptoVerify(
    'sha256',
    Buffer.from(message, 'utf8'),
    { key: importPublicKey(canonicalPublicKey), dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url'),
  );
}

const claims = WhisperDeviceActionV2ClaimsSchema.parse(fixture.client_claims);
const submission = whisperDeviceActionV2Submission(
  {
    context_id: fixture.server_resolved_identity.context_id as string,
    organisation_id: fixture.server_resolved_identity.organisation_id as string,
    site_id: fixture.server_resolved_identity.site_id as string,
    actor_user_id: fixture.server_resolved_identity.actor_user_id as string,
    device_id: fixture.server_resolved_identity.device_id as string,
  },
  claims,
);

describe('WP-27 the interoperability fixture is self-describing and stable', () => {
  it('names itself, says what it is for, and warns about its own key material', () => {
    expect(fixture.fixture_version).toBe(1);
    expect(fixture.fixture_id).toBe('sentinel.whisper.device-action.v2.interop.1');
    expect(fixture.what_this_is).toMatch(/byte for byte/u);
    expect(fixture.key_material_warning).toMatch(/TEST KEY/u);
    expect(fixture.key_material_warning).toMatch(/never production material/u);
  });

  it('records the profile and the two domain separators the runtime actually uses', () => {
    expect(fixture.profile).toEqual(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS);
    expect(fixture.domains.statement).toBe(WHISPER_DEVICE_ACTION_V2_DOMAIN);
    expect(fixture.domains.replay_identity).toBe(WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN);
    expect(fixture.server_resolved_signature_profile).toBe(WHISPER_DEVICE_ACTION_V2_PROFILE);
  });

  it('carries a key the contract accepts, whose thumbprint is DERIVED rather than believed', () => {
    expect(deriveP256PublicKeyThumbprint(fixture.key.public_key_canonical_base64url)).toBe(
      fixture.key.public_key_thumbprint_sha256_hex,
    );
    // The recorded public key really is the public half of the recorded private
    // key — otherwise the fixture would be two unrelated artefacts that happen
    // to sit in one file.
    const derived = createPublicKey(
      createPrivateKey({ key: Buffer.from(fixture.key.private_key_pkcs8_der_base64, 'base64'), format: 'der', type: 'pkcs8' }),
    );
    const spki = derived.export({ format: 'der', type: 'spki' });
    expect(Buffer.from(spki.subarray(26)).toString('base64url')).toBe(fixture.key.public_key_canonical_base64url);
  });

  it('the claims contain NO algorithm, profile, curve or hash field', () => {
    for (const key of Object.keys(fixture.client_claims)) {
      expect(/algorithm|profile|curve|hash/u.test(key), key).toBe(false);
    }
    expect(WhisperDeviceActionV2ClaimsSchema.safeParse({ ...fixture.client_claims, signature_algorithm: 'Ed25519' }).success).toBe(false);
  });
});

describe('WP-27 the fixture IS the canonical bytes', () => {
  it('rebuilds `canonical_statement` byte for byte from identity + claims + the SERVER profile', () => {
    const rebuilt = canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(WhisperDeviceActionSubmissionV2Schema.parse(submission), WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    expect(rebuilt).toBe(fixture.canonical_statement);
    // Stated twice on purpose: a length check catches an invisible difference
    // — a stray BOM, a different escape — that an equality diff renders oddly.
    expect(Buffer.byteLength(rebuilt, 'utf8')).toBe(Buffer.byteLength(fixture.canonical_statement, 'utf8'));
  });

  it('agrees on the SHA-256 of those bytes', () => {
    expect(createHash('sha256').update(fixture.canonical_statement, 'utf8').digest('hex')).toBe(fixture.canonical_statement_sha256_hex);
    expect(
      whisperDeviceActionV2Fingerprint(
        whisperDeviceActionV2StatementInput(WhisperDeviceActionSubmissionV2Schema.parse(submission), WHISPER_DEVICE_ACTION_V2_PROFILE),
      ),
    ).toBe(fixture.canonical_statement_sha256_hex);
  });

  it('the statement excludes the signature and includes the domain tag', () => {
    expect(fixture.canonical_statement).toContain(`"domain":"${WHISPER_DEVICE_ACTION_V2_DOMAIN}"`);
    expect(fixture.canonical_statement).not.toContain(fixture.client_claims.signature as string);
    expect(fixture.expected.signature_is_excluded_from_canonical_statement).toBe(true);
  });

  it('the recorded signature verifies against the recorded public key', () => {
    expect(verifySignature(fixture.key.public_key_canonical_base64url, fixture.canonical_statement, claims.signature)).toBe(true);
    expect(fixture.expected.signature_verifies_against_public_key).toBe(true);
  });

  it('a FRESH signature by the same key differs, still verifies, and moves nothing else', () => {
    const privateKey = createPrivateKey({
      key: Buffer.from(fixture.key.private_key_pkcs8_der_base64, 'base64'),
      format: 'der',
      type: 'pkcs8',
    });
    const raw = cryptoSign('sha256', Buffer.from(fixture.canonical_statement, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    const fresh = encodeCanonicalP256Signature(
      BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`),
      lowSCanonicaliseForSigning(BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`)),
    );
    expect(fresh).not.toBe(claims.signature);
    expect(verifySignature(fixture.key.public_key_canonical_base64url, fixture.canonical_statement, fresh)).toBe(true);

    const resigned = WhisperDeviceActionSubmissionV2Schema.parse({ ...submission, signature: fresh });
    expect(whisperDeviceActionV2ReplayKey(resigned)).toBe(fixture.replay_key);
    expect(
      whisperDeviceActionV2Fingerprint(whisperDeviceActionV2StatementInput(resigned, WHISPER_DEVICE_ACTION_V2_PROFILE)),
    ).toBe(fixture.canonical_statement_sha256_hex);
  });
});

describe('WP-27 the fixture IS the replay identity', () => {
  it('reproduces the identity, the canonical key and its digest', () => {
    expect(whisperDeviceActionV2ReplayIdentity(submission)).toEqual(fixture.replay_identity);
    expect(whisperDeviceActionV2ReplayKey(submission)).toBe(fixture.replay_key);
    expect(createHash('sha256').update(fixture.replay_key, 'utf8').digest('hex')).toBe(fixture.replay_identity_digest_sha256_hex);
  });

  it('excludes the signature, and says so in the file', () => {
    expect(fixture.replay_key).not.toContain(claims.signature);
    expect(Object.keys(fixture.replay_identity)).not.toContain('signature');
    expect(fixture.expected.signature_is_excluded_from_replay_identity).toBe(true);
  });
});

describe('WP-27 the fixture states the expected RESULT, and the gate produces it', () => {
  it('is admissible, with the effect the file names', () => {
    const parsed = WhisperDeviceActionSubmissionV2Schema.parse(submission);
    const context: AuthenticatedDeviceContext = {
      schema_version: 1,
      context_id: parsed.context_id,
      organisation_id: parsed.organisation_id,
      actor_user_id: parsed.actor_user_id,
      device_id: parsed.device_id,
      authorised_site_ids: [parsed.site_id],
      device_trust: 'TRUSTED',
      key_id: parsed.key_id,
      key_version: parsed.key_version,
      issued_at: '2026-03-01T11:59:00.000Z',
      expires_at: '2026-03-01T12:03:00.000Z',
    };
    const registered: WhisperDeviceActionV2RegistryFacts = {
      organisation_id: parsed.organisation_id,
      device_id: parsed.device_id,
      key_id: parsed.key_id,
      key_version: parsed.key_version,
      signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
      key_state: 'CURRENT',
      device_revoked: false,
      key_revoked: false,
      revocation_disposition: null,
      trust: 'TRUSTED',
    };
    const decision = evaluateWhisperDeviceActionV2Admissibility({
      context,
      submission: parsed,
      now: '2026-03-01T12:00:10.000Z',
      registered,
      verified: verifySignature(fixture.key.public_key_canonical_base64url, fixture.canonical_statement, parsed.signature),
      consumption: {
        source: 'SENTINEL_NONCE_STORE',
        outcome: 'FIRST_SEEN',
        replay_key: fixture.replay_key,
        statement_fingerprint: fixture.canonical_statement_sha256_hex,
        stored_outcome_ref: null,
      },
    });
    expect(decision.admissible).toBe(true);
    expect(decision.admissible ? decision.effect : null).toBe(fixture.expected.admissibility_effect);
    expect(fixture.expected.verification_outcome).toBe('VERIFIED_STATEMENT');
  });
});
