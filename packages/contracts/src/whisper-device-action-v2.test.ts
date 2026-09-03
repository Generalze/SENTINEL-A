import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPublicKey, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DEVICE_PURPOSE_PERMITTED_TRUST,
  P256_SCALAR_BYTES,
  encodeCanonicalP256Signature,
  lowSCanonicaliseForSigning,
  type AuthenticatedDeviceContext,
  type DeviceNonceConsumption,
} from './index.js';
import {
  WHISPER_DEVICE_ACTION_V2_DOMAIN,
  WHISPER_DEVICE_ACTION_V2_PROFILE,
  WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS,
  WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN,
  WhisperDeviceActionSubmissionV2Schema,
  WhisperDeviceActionV2ClaimsSchema,
  WhisperDeviceActionV2VerificationResultSchema,
  canonicalWhisperDeviceActionV2Statement,
  evaluateWhisperDeviceActionV2Admissibility,
  parseWhisperDeviceActionV2Claims,
  whisperDeviceActionSchemaVersionOf,
  whisperDeviceActionV2Fingerprint,
  whisperDeviceActionV2ReplayIdentity,
  whisperDeviceActionV2ReplayKey,
  whisperDeviceActionV2StatementInput,
  whisperDeviceActionV2Submission,
  type WhisperDeviceActionSubmissionV2,
  type WhisperDeviceActionV2AdmissibilityInput,
  type WhisperDeviceActionV2RegistryFacts,
} from './whisper-device-action-v2.js';

/**
 * WP-27 — the v2 device-action statement, judged as a contract.
 *
 * Everything here is pure. The one place real cryptography appears is the
 * ECDSA-randomisation regression, and it is real precisely because the property
 * being asserted — that two signatures over the SAME bytes differ, and that the
 * replay identity is unmoved by that difference — is not observable against a
 * stub.
 */

const P256_SPKI_HEADER_BYTES = 26;

interface TestKeyPair {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

function generateKeyPair(): TestKeyPair {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  return { publicKey: Buffer.from(spki.subarray(P256_SPKI_HEADER_BYTES)).toString('base64url'), privateKey: pair.privateKey };
}

/** Signs exactly as a conforming device does: P1363, low-S normalised on the signer. */
function sign(privateKey: KeyObject, message: string): string {
  const raw = cryptoSign('sha256', Buffer.from(message, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`);
  const s = BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`);
  return encodeCanonicalP256Signature(r, lowSCanonicaliseForSigning(s));
}

const P256_SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

function verify(publicKey: string, message: string, signature: string): boolean {
  const key = createPublicKey({
    key: Buffer.concat([P256_SPKI_HEADER, Buffer.from(publicKey, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  return cryptoVerify(
    'sha256',
    Buffer.from(message, 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url'),
  );
}

const keys = generateKeyPair();

const IDENTITY = {
  context_id: 'ctx-1',
  organisation_id: 'org-a',
  site_id: 'site-a1',
  actor_user_id: 'op-alpha',
  device_id: 'dev-1',
} as const;

const RAW_CLAIMS = {
  schema_version: 2 as const,
  key_id: 'key-1',
  key_version: 3,
  whisper_signal_id: 'sig-1',
  whisper_signal_version: 4,
  modality: 'DEVICE_ACTION' as const,
  device_action_id: 'triple-press',
  recognised_at: '2026-01-01T00:00:00.000Z',
  confidence: 0.91,
  anti_replay_nonce: 'nonce-0123456789abcdef',
};

/** A submission whose signature is a genuine one over its own canonical bytes. */
function buildSubmission(overrides: Partial<Record<string, unknown>> = {}): WhisperDeviceActionSubmissionV2 {
  const draft = { ...IDENTITY, ...RAW_CLAIMS, ...overrides };
  const statement = canonicalWhisperDeviceActionV2Statement({
    ...(draft as unknown as Omit<WhisperDeviceActionSubmissionV2, 'signature'>),
    signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
  });
  const parsed = WhisperDeviceActionSubmissionV2Schema.safeParse({ ...draft, signature: sign(keys.privateKey, statement) });
  if (!parsed.success) throw new Error(`fixture does not parse: ${parsed.error.message}`);
  return parsed.data;
}

const SUBMISSION = buildSubmission();

const CONTEXT: AuthenticatedDeviceContext = {
  schema_version: 1,
  context_id: IDENTITY.context_id,
  organisation_id: IDENTITY.organisation_id,
  actor_user_id: IDENTITY.actor_user_id,
  device_id: IDENTITY.device_id,
  authorised_site_ids: [IDENTITY.site_id],
  device_trust: 'TRUSTED',
  key_id: RAW_CLAIMS.key_id,
  key_version: RAW_CLAIMS.key_version,
  issued_at: '2026-01-01T00:00:00.000Z',
  expires_at: '2026-01-01T00:04:00.000Z',
};

const REGISTERED: WhisperDeviceActionV2RegistryFacts = {
  organisation_id: IDENTITY.organisation_id,
  device_id: IDENTITY.device_id,
  key_id: RAW_CLAIMS.key_id,
  key_version: RAW_CLAIMS.key_version,
  signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
  key_state: 'CURRENT',
  device_revoked: false,
  key_revoked: false,
  revocation_disposition: null,
  trust: 'TRUSTED',
};

const NOW = '2026-01-01T00:00:30.000Z';

function fingerprintOf(submission: WhisperDeviceActionSubmissionV2): string {
  return whisperDeviceActionV2Fingerprint(whisperDeviceActionV2StatementInput(submission, WHISPER_DEVICE_ACTION_V2_PROFILE));
}

function firstSeen(submission: WhisperDeviceActionSubmissionV2 = SUBMISSION): DeviceNonceConsumption {
  return {
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'FIRST_SEEN',
    replay_key: whisperDeviceActionV2ReplayKey(submission),
    statement_fingerprint: fingerprintOf(submission),
    stored_outcome_ref: null,
  };
}

function admissibility(overrides: Partial<WhisperDeviceActionV2AdmissibilityInput> = {}): WhisperDeviceActionV2AdmissibilityInput {
  const submission = overrides.submission ?? SUBMISSION;
  return {
    context: CONTEXT,
    submission,
    now: NOW,
    registered: REGISTERED,
    verified: true,
    consumption: firstSeen(submission),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

describe('WP-27 the profile is declared once, and it is P-256/ECDSA/SHA-256 over canonical P1363', () => {
  it('names EC, secp256r1, ECDSA, SHA-256 and IEEE-P1363 from a single export', () => {
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE).toBe('P256_ECDSA_SHA256');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.profile).toBe(WHISPER_DEVICE_ACTION_V2_PROFILE);
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.key_type).toBe('EC');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.curve).toBe('secp256r1');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.curve_openssl_name).toBe('prime256v1');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.signature_algorithm).toBe('ECDSA');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.digest_algorithm).toBe('SHA-256');
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.signature_encoding).toBe('IEEE-P1363');
  });

  it('records WHY P1363 rather than DER — malleability closed at the encoding', () => {
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.encoding_rationale).toMatch(/DER/u);
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.encoding_rationale).toMatch(/high-S/u);
    expect(WHISPER_DEVICE_ACTION_V2_PROFILE_SEMANTICS.signature_encoding_detail).toMatch(/low-S/u);
  });

  it('reads the frozen purpose table rather than restating W21-05', () => {
    expect(DEVICE_PURPOSE_PERMITTED_TRUST.WHISPER_DEVICE_ACTION).toEqual(['TRUSTED']);
  });
});

// ---------------------------------------------------------------------------
// The submission schema
// ---------------------------------------------------------------------------

describe('WP-27 the client never names the algorithm', () => {
  for (const field of ['signature_algorithm', 'signature_profile', 'curve', 'hash_algorithm']) {
    it(`refuses a submission carrying ${field}`, () => {
      const parsed = WhisperDeviceActionSubmissionV2Schema.safeParse({ ...SUBMISSION, [field]: 'anything' });
      expect(parsed.success, field).toBe(false);
    });

    it(`refuses a CLAIMS payload carrying ${field}`, () => {
      const { context_id, organisation_id, site_id, actor_user_id, device_id, ...claims } = SUBMISSION;
      void context_id;
      void organisation_id;
      void site_id;
      void actor_user_id;
      void device_id;
      expect(WhisperDeviceActionV2ClaimsSchema.safeParse({ ...claims, [field]: 'anything' }).success, field).toBe(false);
    });
  }

  it('has no algorithm-shaped key at all in a parsed submission', () => {
    for (const key of Object.keys(SUBMISSION)) {
      expect(/algorithm|profile|curve|hash/u.test(key), key).toBe(false);
    }
  });

  it('refuses a signature that is not the one canonical wire form', () => {
    // DER, high-S, padded, wrong length and non-canonical base64url all die at
    // the schema, not at some later caller who remembered to decode.
    for (const bad of ['', 'AAAA', `${SUBMISSION.signature}=`, `${SUBMISSION.signature}A`, 'MEUCIQD*not-base64url*']) {
      expect(WhisperDeviceActionSubmissionV2Schema.safeParse({ ...SUBMISSION, signature: bad }).success, bad).toBe(false);
    }
  });

  it('refuses a v1-shaped result, and v1 dispatch never reaches v2', () => {
    expect(whisperDeviceActionSchemaVersionOf({ schema_version: 1 })).toBe(1);
    expect(whisperDeviceActionSchemaVersionOf({ schema_version: 2 })).toBe(2);
    expect(whisperDeviceActionSchemaVersionOf({ schema_version: 3 })).toBeNull();
    expect(whisperDeviceActionSchemaVersionOf(null)).toBeNull();
    expect(parseWhisperDeviceActionV2Claims({ ...SUBMISSION, schema_version: 1 })).toEqual({
      ok: false,
      refusal: 'SUBMISSION_MALFORMED',
    });
  });
});

// ---------------------------------------------------------------------------
// The canonical statement
// ---------------------------------------------------------------------------

describe('WP-27 the canonical statement binds every field it claims to', () => {
  it('is domain-tagged, deterministic and sorted', () => {
    const input = whisperDeviceActionV2StatementInput(SUBMISSION, WHISPER_DEVICE_ACTION_V2_PROFILE);
    const statement = canonicalWhisperDeviceActionV2Statement(input);
    expect(statement).toContain(`"domain":"${WHISPER_DEVICE_ACTION_V2_DOMAIN}"`);
    expect(statement).toBe(canonicalWhisperDeviceActionV2Statement(input));
    const keys = [...statement.matchAll(/"([a-z_]+)":/gu)].map((match) => match[1]);
    expect(keys).toEqual([...keys].sort());
  });

  it('never contains the signature — the output is not part of its own preimage', () => {
    const statement = canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(SUBMISSION, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    expect(statement).not.toContain(SUBMISSION.signature);
    expect(statement).not.toContain('"signature"');
  });

  it('MUTATING ANY BOUND FIELD, INDIVIDUALLY, CHANGES THE FINGERPRINT', () => {
    const base = fingerprintOf(SUBMISSION);
    const mutations: Array<[string, Partial<Record<string, unknown>>]> = [
      ['context_id', { context_id: 'ctx-2' }],
      ['organisation_id', { organisation_id: 'org-b' }],
      ['site_id', { site_id: 'site-a2' }],
      ['actor_user_id', { actor_user_id: 'op-bravo' }],
      ['device_id', { device_id: 'dev-2' }],
      ['key_id', { key_id: 'key-2' }],
      ['key_version', { key_version: 4 }],
      ['whisper_signal_id', { whisper_signal_id: 'sig-2' }],
      ['whisper_signal_version', { whisper_signal_version: 5 }],
      ['device_action_id', { device_action_id: 'double-press' }],
      ['recognised_at', { recognised_at: '2026-01-01T00:00:00.001Z' }],
      ['confidence', { confidence: 0.92 }],
      ['anti_replay_nonce', { anti_replay_nonce: 'nonce-fedcba9876543210' }],
    ];
    const seen = new Set([base]);
    for (const [name, override] of mutations) {
      const mutated = fingerprintOf({ ...SUBMISSION, ...override } as WhisperDeviceActionSubmissionV2);
      expect(mutated, name).not.toBe(base);
      expect(seen.has(mutated), `${name} collided with another mutation`).toBe(false);
      seen.add(mutated);
    }
    // Every mutation is distinct from every other, so no two bound fields share
    // a position in the preimage.
    expect(seen.size).toBe(mutations.length + 1);
  });

  it('the SERVER-resolved profile is bound, so a statement means "signed under the profile the platform chose"', () => {
    const statement = canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(SUBMISSION, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    expect(statement).toContain(`"signature_profile":"${WHISPER_DEVICE_ACTION_V2_PROFILE}"`);
  });

  it('the v1 and v2 domains differ, so one preimage can never be the other', () => {
    expect(WHISPER_DEVICE_ACTION_V2_DOMAIN).toBe('sentinel.whisper.device-action.v2');
    expect(WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN).toBe('sentinel.whisper.replay-identity.v2');
    expect(WHISPER_DEVICE_ACTION_V2_DOMAIN).not.toBe('sentinel.whisper.device-action.v1');
  });

  it('the assembler reproduces a submission from server identity plus client claims', () => {
    const { context_id, organisation_id, site_id, actor_user_id, device_id, ...claims } = SUBMISSION;
    const rebuilt = whisperDeviceActionV2Submission(
      { context_id, organisation_id, site_id, actor_user_id, device_id },
      WhisperDeviceActionV2ClaimsSchema.parse(claims),
    );
    expect(rebuilt).toEqual(SUBMISSION);
  });
});

// ---------------------------------------------------------------------------
// The replay identity — the ECDSA ruling
// ---------------------------------------------------------------------------

describe('WP-27 the replay identity is the ACTION, and the signature is not part of it', () => {
  it('carries no signature field at all', () => {
    const identity = whisperDeviceActionV2ReplayIdentity(SUBMISSION);
    expect(Object.keys(identity).sort()).toEqual([
      'actor_user_id',
      'anti_replay_nonce',
      'device_id',
      'key_version',
      'organisation_id',
      'site_id',
      'whisper_signal_id',
      'whisper_signal_version',
    ]);
    expect(JSON.stringify(identity)).not.toContain(SUBMISSION.signature);
    expect(whisperDeviceActionV2ReplayKey(SUBMISSION)).not.toContain(SUBMISSION.signature);
  });

  it('TWO DIFFERENT VALID SIGNATURES OVER THE SAME BYTES YIELD ONE IDENTITY', () => {
    const statement = canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(SUBMISSION, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );
    const first = sign(keys.privateKey, statement);
    const second = sign(keys.privateKey, statement);

    // ECDSA is randomised. If this ever stopped holding, the ruling below would
    // be untestable rather than false — so it is asserted rather than assumed.
    expect(second).not.toBe(first);
    expect(verify(keys.publicKey, statement, first)).toBe(true);
    expect(verify(keys.publicKey, statement, second)).toBe(true);

    const a = WhisperDeviceActionSubmissionV2Schema.parse({ ...SUBMISSION, signature: first });
    const b = WhisperDeviceActionSubmissionV2Schema.parse({ ...SUBMISSION, signature: second });

    expect(whisperDeviceActionV2ReplayKey(b)).toBe(whisperDeviceActionV2ReplayKey(a));
    expect(whisperDeviceActionV2ReplayIdentity(b)).toEqual(whisperDeviceActionV2ReplayIdentity(a));
    // ...and the fingerprint too, because the signature is not in the preimage.
    expect(fingerprintOf(b)).toBe(fingerprintOf(a));
  });

  it('is domain-tagged canonical JSON, never a delimiter join', () => {
    const key = whisperDeviceActionV2ReplayKey(SUBMISSION);
    expect(key).toContain(`"domain":"${WHISPER_DEVICE_ACTION_V2_REPLAY_IDENTITY_DOMAIN}"`);
    // C11-01: two tuples that a delimiter join would collide on stay distinct.
    const left = whisperDeviceActionV2ReplayKey({ ...SUBMISSION, organisation_id: 'a:b', site_id: 'c' });
    const right = whisperDeviceActionV2ReplayKey({ ...SUBMISSION, organisation_id: 'a', site_id: 'b:c' });
    expect(left).not.toBe(right);
  });

  it('changes with every semantic field, and NOT with recognised_at, confidence or context', () => {
    const base = whisperDeviceActionV2ReplayKey(SUBMISSION);
    for (const override of [
      { organisation_id: 'org-b' },
      { site_id: 'site-a2' },
      { actor_user_id: 'op-bravo' },
      { device_id: 'dev-2' },
      { key_version: 4 },
      { whisper_signal_id: 'sig-2' },
      { whisper_signal_version: 5 },
      { anti_replay_nonce: 'nonce-fedcba9876543210' },
    ]) {
      expect(whisperDeviceActionV2ReplayKey({ ...SUBMISSION, ...override }), JSON.stringify(override)).not.toBe(base);
    }
    // A new context must not open a fresh slot for an action already spent, and
    // a millisecond edit must not either.
    for (const override of [{ context_id: 'ctx-2' }, { recognised_at: '2026-01-01T00:00:00.001Z' }, { confidence: 0.5 }]) {
      expect(whisperDeviceActionV2ReplayKey({ ...SUBMISSION, ...override }), JSON.stringify(override)).toBe(base);
    }
  });
});

// ---------------------------------------------------------------------------
// Admissibility
// ---------------------------------------------------------------------------

describe('WP-27 the admissibility gate', () => {
  it('admits a valid, fresh, bound, unspent statement', () => {
    const decision = evaluateWhisperDeviceActionV2Admissibility(admissibility());
    expect(decision).toEqual({
      admissible: true,
      effect: 'PROCEED',
      fingerprint: fingerprintOf(SUBMISSION),
      replay_key: whisperDeviceActionV2ReplayKey(SUBMISSION),
    });
  });

  it('refuses every individual disagreement with the SERVER-established context', () => {
    const cases: Array<[Partial<WhisperDeviceActionSubmissionV2>, string]> = [
      [{ organisation_id: 'org-b' }, 'CONTEXT_ORGANISATION_MISMATCH'],
      [{ actor_user_id: 'op-bravo' }, 'CONTEXT_ACTOR_MISMATCH'],
      [{ device_id: 'dev-2' }, 'CONTEXT_DEVICE_MISMATCH'],
      [{ context_id: 'ctx-2' }, 'CONTEXT_IDENTITY_MISMATCH'],
      [{ site_id: 'site-a2' }, 'CONTEXT_SITE_NOT_AUTHORISED'],
      [{ key_id: 'key-2' }, 'CONTEXT_KEY_MISMATCH'],
      [{ key_version: 9 }, 'CONTEXT_KEY_MISMATCH'],
    ];
    for (const [override, refusal] of cases) {
      const submission = { ...SUBMISSION, ...override } as WhisperDeviceActionSubmissionV2;
      const decision = evaluateWhisperDeviceActionV2Admissibility(admissibility({ submission }));
      expect(decision, refusal).toEqual({ admissible: false, refusal });
    }
  });

  it('refuses on registry disagreement, rotation and unsupported profile', () => {
    const cases: Array<[Partial<WhisperDeviceActionV2RegistryFacts>, string]> = [
      [{ organisation_id: 'org-b' }, 'REGISTRY_IDENTITY_MISMATCH'],
      [{ device_id: 'dev-2' }, 'REGISTRY_IDENTITY_MISMATCH'],
      [{ key_id: 'key-2' }, 'CONTEXT_KEY_MISMATCH'],
      [{ key_version: 4 }, 'KEY_VERSION_ROTATED'],
      [{ device_revoked: true }, 'DEVICE_REVOKED'],
      [{ key_revoked: true }, 'KEY_REVOKED'],
      [{ key_state: 'ROTATED' }, 'KEY_STATE_NOT_OPERATIONAL'],
      [{ key_state: 'REVOKED' }, 'KEY_STATE_NOT_OPERATIONAL'],
      [{ key_state: 'COMPROMISED' }, 'KEY_STATE_NOT_OPERATIONAL'],
      [{ trust: 'DEGRADED' }, 'DEVICE_TRUST_NOT_PERMITTED'],
      [{ trust: 'SUSPICIOUS' }, 'DEVICE_TRUST_NOT_PERMITTED'],
      [{ trust: 'QUARANTINED' }, 'DEVICE_TRUST_NOT_PERMITTED'],
      [{ trust: 'OFFLINE' }, 'DEVICE_TRUST_NOT_PERMITTED'],
      [{ trust: 'COMPROMISED' }, 'DEVICE_TRUST_NOT_PERMITTED'],
    ];
    for (const [override, refusal] of cases) {
      const decision = evaluateWhisperDeviceActionV2Admissibility(
        admissibility({ registered: { ...REGISTERED, ...override } }),
      );
      expect(decision, JSON.stringify(override)).toEqual({ admissible: false, refusal });
    }
  });

  it('refuses a registry profile that is not the one v2 supports, with NO fallback', () => {
    const decision = evaluateWhisperDeviceActionV2Admissibility(
      admissibility({
        registered: { ...REGISTERED, signature_profile: 'Ed25519' as unknown as WhisperDeviceActionV2RegistryFacts['signature_profile'] },
      }),
    );
    expect(decision).toEqual({ admissible: false, refusal: 'SIGNATURE_PROFILE_NOT_SUPPORTED' });
  });

  it('judges freshness against the SERVER clock in both directions', () => {
    expect(evaluateWhisperDeviceActionV2Admissibility(admissibility({ now: '2026-01-01T00:03:00.000Z' }))).toEqual({
      admissible: false,
      refusal: 'RECOGNITION_STALE',
    });
    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({
          submission: { ...SUBMISSION, recognised_at: '2026-01-01T00:00:20.000Z' } as WhisperDeviceActionSubmissionV2,
          now: '2026-01-01T00:00:00.000Z',
        }),
      ).admissible,
    ).toBe(false);
  });

  it('refuses a closed or unborn context window, and an unreadable clock', () => {
    expect(evaluateWhisperDeviceActionV2Admissibility(admissibility({ now: '2026-01-01T00:05:00.000Z' }))).toEqual({
      admissible: false,
      refusal: 'CONTEXT_EXPIRED',
    });
    expect(evaluateWhisperDeviceActionV2Admissibility(admissibility({ now: '2025-12-31T23:59:00.000Z' }))).toEqual({
      admissible: false,
      refusal: 'CONTEXT_NOT_YET_VALID',
    });
    expect(evaluateWhisperDeviceActionV2Admissibility(admissibility({ now: 'not-a-time' }))).toEqual({
      admissible: false,
      refusal: 'TIME_NOT_AUTHORITATIVE',
    });
  });

  it('POSSESSION IS CHECKED LAST, so a perfect statement without the key refuses SIGNATURE_INVALID', () => {
    expect(evaluateWhisperDeviceActionV2Admissibility(admissibility({ verified: false }))).toEqual({
      admissible: false,
      refusal: 'SIGNATURE_INVALID',
    });
  });

  it('REFUSES an exact re-presentation rather than converging on it', () => {
    // The asymmetry with `evaluateDeviceRequestProof` is the ruling: the
    // lost-response retry is a TRANSPORT concern and is answered one layer up,
    // so an exact duplicate reaching this gate is a spent action being
    // presented again under fresh transport.
    const spent = evaluateWhisperDeviceActionV2Admissibility(
      admissibility({
        consumption: {
          source: 'SENTINEL_NONCE_STORE',
          outcome: 'EXACT_DUPLICATE',
          replay_key: whisperDeviceActionV2ReplayKey(SUBMISSION),
          statement_fingerprint: fingerprintOf(SUBMISSION),
          stored_outcome_ref: 'outcome-ref-1',
        },
      }),
    );
    expect(spent).toEqual({ admissible: false, refusal: 'REPLAY_IDENTITY_ALREADY_SPENT' });

    // ...and possession is still checked FIRST, so a caller without the key
    // learns nothing about which identities are already spent.
    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({
          verified: false,
          consumption: {
            source: 'SENTINEL_NONCE_STORE',
            outcome: 'EXACT_DUPLICATE',
            replay_key: whisperDeviceActionV2ReplayKey(SUBMISSION),
            statement_fingerprint: fingerprintOf(SUBMISSION),
            stored_outcome_ref: 'outcome-ref-1',
          },
        }),
      ),
    ).toEqual({ admissible: false, refusal: 'SIGNATURE_INVALID' });

    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({
          consumption: {
            source: 'SENTINEL_NONCE_STORE',
            outcome: 'REUSED_WITH_CHANGED_SEMANTICS',
            replay_key: whisperDeviceActionV2ReplayKey(SUBMISSION),
            statement_fingerprint: fingerprintOf(SUBMISSION),
            stored_outcome_ref: null,
          },
        }),
      ),
    ).toEqual({ admissible: false, refusal: 'REPLAY_IDENTITY_REUSED' });
  });

  it('fails closed on a consumption fact about another statement, or of an impossible shape', () => {
    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({ consumption: { ...firstSeen(), replay_key: 'somebody-elses-key' } }),
      ),
    ).toEqual({ admissible: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' });

    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({
          consumption: {
            source: 'SENTINEL_NONCE_STORE',
            outcome: 'EXACT_DUPLICATE',
            replay_key: whisperDeviceActionV2ReplayKey(SUBMISSION),
            statement_fingerprint: fingerprintOf(SUBMISSION),
            stored_outcome_ref: '',
          } as unknown as DeviceNonceConsumption,
        }),
      ),
    ).toEqual({ admissible: false, refusal: 'NONCE_CONSUMPTION_INCONSISTENT' });
  });

  it('a signature over a DIFFERENT statement never becomes admissible by re-presentation', () => {
    // The statement was altered after signing: the fingerprint moves, so the
    // consumption fact no longer binds, and the signature no longer verifies.
    const altered = { ...SUBMISSION, device_action_id: 'double-press' } as WhisperDeviceActionSubmissionV2;
    expect(fingerprintOf(altered)).not.toBe(fingerprintOf(SUBMISSION));
    expect(
      evaluateWhisperDeviceActionV2Admissibility(
        admissibility({ submission: altered, consumption: firstSeen(altered), verified: false }),
      ),
    ).toEqual({ admissible: false, refusal: 'SIGNATURE_INVALID' });
  });
});

// ---------------------------------------------------------------------------
// The verification result
// ---------------------------------------------------------------------------

describe('WP-27 the verification result is a value, never a naked boolean', () => {
  const base = {
    schema_version: 2 as const,
    source: 'SENTINEL_SERVER_VERIFICATION' as const,
    outcome: 'VERIFIED_STATEMENT' as const,
    refusal: null,
    context_id: IDENTITY.context_id,
    organisation_id: IDENTITY.organisation_id,
    site_id: IDENTITY.site_id,
    actor_user_id: IDENTITY.actor_user_id,
    device_id: IDENTITY.device_id,
    key_id: RAW_CLAIMS.key_id,
    key_version: RAW_CLAIMS.key_version,
    signature_profile: WHISPER_DEVICE_ACTION_V2_PROFILE,
    device_trust: 'TRUSTED' as const,
    key_state: 'CURRENT' as const,
    revocation_disposition: null,
    whisper_signal_id: RAW_CLAIMS.whisper_signal_id,
    whisper_signal_version: RAW_CLAIMS.whisper_signal_version,
    device_action_id: RAW_CLAIMS.device_action_id,
    statement_fingerprint: fingerprintOf(SUBMISSION),
    replay_identity_digest: fingerprintOf(SUBMISSION),
    stored_outcome_ref: 'outcome-ref-1',
    verified_at: NOW,
  };

  it('carries WHAT it is about, so a verdict cannot be borrowed', () => {
    const parsed = WhisperDeviceActionV2VerificationResultSchema.parse(base);
    expect(parsed.source).toBe('SENTINEL_SERVER_VERIFICATION');
    expect(parsed.context_id).toBe(IDENTITY.context_id);
    expect(parsed.key_version).toBe(RAW_CLAIMS.key_version);
  });

  it('never carries a signature, a key or a nonce', () => {
    expect(Object.keys(base)).not.toContain('signature');
    expect(Object.keys(base)).not.toContain('public_key');
    expect(Object.keys(base)).not.toContain('anti_replay_nonce');
    expect(WhisperDeviceActionV2VerificationResultSchema.safeParse({ ...base, signature: SUBMISSION.signature }).success).toBe(false);
    expect(WhisperDeviceActionV2VerificationResultSchema.safeParse({ ...base, anti_replay_nonce: 'x' }).success).toBe(false);
  });

  it('refuses an incoherent verdict in either direction', () => {
    expect(WhisperDeviceActionV2VerificationResultSchema.safeParse({ ...base, outcome: 'REFUSED', refusal: null }).success).toBe(false);
    expect(
      WhisperDeviceActionV2VerificationResultSchema.safeParse({ ...base, outcome: 'VERIFIED_STATEMENT', refusal: 'SIGNATURE_INVALID' })
        .success,
    ).toBe(false);
    expect(
      WhisperDeviceActionV2VerificationResultSchema.safeParse({
        ...base,
        outcome: 'CONVERGED_ON_VERIFIED_STATEMENT',
        stored_outcome_ref: null,
      }).success,
    ).toBe(false);
    expect(WhisperDeviceActionV2VerificationResultSchema.safeParse({ ...base, outcome: 'REFUSED', refusal: 'SIGNATURE_INVALID' }).success).toBe(
      true,
    );
  });
});
