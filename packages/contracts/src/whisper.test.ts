import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ALLOWED_WHISPER_SIGNAL_STATUS_TRANSITIONS,
  DeviceActionWhisperResultSchema,
  MAX_WHISPER_RECOGNITION_AGE_MS,
  MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS,
  PROPOSED_WHISPER_ROLE_ACTIONS,
  WHISPER_ACTIONS,
  WHISPER_INVOCATION_TRUST_STATES,
  WHISPER_RESPONSE_PROTOCOLS,
  WHISPER_SEMANTIC_CONFIGURATION_FIELDS,
  WHISPER_REPLAY_IDENTITY_DOMAIN,
  WHISPER_SIGNATURE_ALGORITHM,
  WHISPER_SIGNED_STATEMENT_DOMAIN,
  WhisperActivationApprovalSchema,
  WhisperAuditPayloadSchema,
  WhisperSignalSchema,
  WhisperSignalStatusSchema,
  canTransitionWhisperSignalStatus,
  canonicalWhisperSignedStatement,
  classifyWhisperConfigurationEdit,
  classifyWhisperRecognitionFreshness,
  deviceActionWhisperReplayIdentity,
  deviceActionWhisperReplayKey,
  deviceTrustPermitsWhisperInvocation,
  evaluateWhisperContextRequirements,
  evaluateWhisperRuntimeEligibility,
  isAllowlistedWhisperResponseProtocol,
  isTerminalWhisperSignalStatus,
  isWhisperConfigurationEditable,
  whisperActivationApproverIsDistinct,
  whisperConfigurationFingerprint,
  whisperRecognitionFingerprint,
  type AuthenticatedWhisperDeviceContext,
  type WhisperRuntimeEligibilityInput,
  type WhisperSemanticConfiguration,
  type WhisperSignalStatus,
} from './whisper';

const at = '2026-08-16T10:00:00Z';

describe('WhisperSignalStatusSchema and lifecycle', () => {
  it('accepts every documented lifecycle status', () => {
    for (const status of ['DRAFT', 'SIMULATION', 'FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL', 'ACTIVE', 'ROTATED', 'RETIRED']) {
      expect(WhisperSignalStatusSchema.parse(status)).toBe(status);
    }
  });

  it('rejects an invalid lifecycle status', () => {
    expect(() => WhisperSignalStatusSchema.parse('TESTED')).toThrow();
  });

  it('enforces ordered lifecycle examples and terminal boundary states', () => {
    expect(canTransitionWhisperSignalStatus('DRAFT', 'SIMULATION')).toBe(true);
    expect(canTransitionWhisperSignalStatus('FIELD_DRILL', 'APPROVAL')).toBe(true);
    expect(canTransitionWhisperSignalStatus('ACTIVE', 'ROTATED')).toBe(true);
    expect(canTransitionWhisperSignalStatus('DRAFT', 'ACTIVE')).toBe(false);
    expect(canTransitionWhisperSignalStatus('RETIRED', 'ACTIVE')).toBe(false);
  });
});

describe('WhisperSignalSchema', () => {
  const signal = {
    schema_version: 1 as const, whisper_signal_id: 'whisper-1', organisation_id: 'org-1', site_id: 'site-1', name: 'Assistance device action',
    signal_version: 1, status: 'ACTIVE' as const, modality: 'DEVICE_ACTION' as const, device_action_id: 'button-double-press', authorised_user_ids: ['user-1'],
    context_requirements: { on_duty: true }, minimum_confidence: 0.9, response_protocol_id: 'SILENT_INCIDENT_RESPONSE' as const, created_at: at, updated_at: at,
    created_by_user_id: 'admin-1', trace_id: 'trace-1',
  };

  it('accepts a versioned device-action signal that only references a protocol', () => {
    expect(WhisperSignalSchema.parse(signal).response_protocol_id).toBe('SILENT_INCIDENT_RESPONSE');
  });

  it('rejects invalid tenant scope, unsupported modality, and active signal without protocol reference', () => {
    expect(() => WhisperSignalSchema.parse({ ...signal, organisation_id: '' })).toThrow();
    expect(() => WhisperSignalSchema.parse({ ...signal, modality: 'VOICE' })).toThrow();
    expect(() => WhisperSignalSchema.parse({ ...signal, response_protocol_id: null })).toThrow();
  });

  it('accepts the minimum confidence boundary', () => {
    expect(WhisperSignalSchema.parse({ ...signal, minimum_confidence: 0 }).minimum_confidence).toBe(0);
  });

  it('rejects duplicate authorised users', () => {
    expect(() => WhisperSignalSchema.parse({ ...signal, authorised_user_ids: ['user-1', 'user-1'] })).toThrow(/authorised_user_ids/);
  });
});

describe('DeviceActionWhisperResultSchema', () => {
  const result = {
    schema_version: 1 as const, whisper_result_id: 'result-1', whisper_signal_id: 'whisper-1', whisper_signal_version: 1, organisation_id: 'org-1', site_id: 'site-1',
    actor_user_id: 'user-1', device_id: 'device-1', device_action_id: 'button-double-press', recognised_at: at, confidence: 0.95, device_trust: 'TRUSTED' as const, context: { on_duty: true },
    freshness_ms: 0, anti_replay_nonce: '0123456789abcdef', signature_algorithm: 'Ed25519', signature: '0123456789abcdef', trace_id: 'trace-1',
  };

  it('accepts a signed, tenant-scoped device-action result at freshness boundary', () => {
    expect(DeviceActionWhisperResultSchema.parse(result).freshness_ms).toBe(0);
  });

  it('accepts canonical device trust states and rejects local competing labels', () => {
    expect(DeviceActionWhisperResultSchema.parse({ ...result, device_trust: 'OFFLINE' }).device_trust).toBe('OFFLINE');
    expect(() => DeviceActionWhisperResultSchema.parse({ ...result, device_trust: 'UNTRUSTED' })).toThrow();
  });

  it('rejects invalid site scope and a nonce too short for anti-replay', () => {
    expect(() => DeviceActionWhisperResultSchema.parse({ ...result, site_id: '' })).toThrow();
    expect(() => DeviceActionWhisperResultSchema.parse({ ...result, anti_replay_nonce: 'short' })).toThrow();
  });

  it('derives a tenant-scoped replay key from device, signal version, and nonce', () => {
    expect(deviceActionWhisperReplayKey(result)).toBe(deviceActionWhisperReplayKey({ ...result }));
    expect(deviceActionWhisperReplayKey(result)).not.toBe(deviceActionWhisperReplayKey({ ...result, organisation_id: 'org-2' }));
    expect(deviceActionWhisperReplayKey(result)).not.toBe(deviceActionWhisperReplayKey({ ...result, site_id: 'site-2' }));
    expect(deviceActionWhisperReplayKey(result)).not.toBe(deviceActionWhisperReplayKey({ ...result, anti_replay_nonce: 'fedcba9876543210' }));
  });
});

/** WP-21A Contract + Authority Lock (directive W21-01 .. W21-14). */

const SIGNAL_CONFIG: WhisperSemanticConfiguration = {
  modality: 'DEVICE_ACTION' as const,
  device_action_id: 'button-double-press',
  authorised_user_ids: ['user-1', 'user-2'],
  context_requirements: { on_duty: true },
  minimum_confidence: 0.9,
  response_protocol_id: 'SILENT_INCIDENT_RESPONSE' as const,
};

const SIGNAL_SCOPE = { organisation_id: 'org-1', site_id: 'site-1' as string | null };

const DEVICE_CONTEXT: AuthenticatedWhisperDeviceContext = {
  organisationId: 'org-1',
  actorUserId: 'user-1',
  deviceId: 'device-1',
  authorisedSiteIds: ['site-1'],
  deviceTrust: 'TRUSTED',
  verificationKeyId: 'key-1',
};

const SIGNED_IDENTITY = {
  organisation_id: 'org-1',
  site_id: 'site-1',
  actor_user_id: 'user-1',
  device_id: 'device-1',
  whisper_signal_version: 3,
  device_action_id: 'button-double-press',
  confidence: 0.95,
};

function eligibilityInput(overrides: Partial<WhisperRuntimeEligibilityInput> = {}): WhisperRuntimeEligibilityInput {
  return {
    signal: { ...SIGNAL_SCOPE, status: 'ACTIVE', signal_version: 3, ...SIGNAL_CONFIG },
    context: DEVICE_CONTEXT,
    result: SIGNED_IDENTITY,
    actorHoldsCurrentAuthority: true,
    serverFacts: { on_duty: true },
    freshness: 'FRESH',
    ...overrides,
  };
}

const STATEMENT_INPUT = {
  schema_version: 1 as const,
  organisation_id: 'org-1',
  site_id: 'site-1',
  actor_user_id: 'user-1',
  device_id: 'device-1',
  whisper_signal_id: 'whisper-1',
  whisper_signal_version: 3,
  device_action_id: 'button-double-press',
  recognised_at: '2026-08-19T10:00:00.000Z',
  confidence: 0.95,
  anti_replay_nonce: '0123456789abcdef',
};

describe('W21-01/W21-10 modality and protocol separation', () => {
  it('admits only DEVICE_ACTION — no phrase, voice, gesture, camera or biometric modality parses', () => {
    const base = {
      schema_version: 1 as const, whisper_signal_id: 'whisper-1', organisation_id: 'org-1', site_id: 'site-1', name: 'Assistance',
      signal_version: 1, status: 'DRAFT' as const, ...SIGNAL_CONFIG, created_at: at, updated_at: at, created_by_user_id: 'admin-1', trace_id: 'trace-1',
    };
    expect(WhisperSignalSchema.parse(base).modality).toBe('DEVICE_ACTION');
    for (const modality of ['VOICE', 'PHRASE', 'GESTURE', 'CAMERA', 'BIOMETRIC', 'WEARABLE']) {
      expect(() => WhisperSignalSchema.parse({ ...base, modality })).toThrow();
    }
  });

  it('a signal may only reference an allowlisted protocol — it can never carry an executable command', () => {
    expect(WHISPER_RESPONSE_PROTOCOLS).toEqual(['SILENT_INCIDENT_RESPONSE']);
    expect(isAllowlistedWhisperResponseProtocol('SILENT_INCIDENT_RESPONSE')).toBe(true);
    // A Constitution action name, a route and an invented protocol are all refused.
    for (const forged of ['SILENT_DISPATCH_ACTION', '/api/v1/incidents', 'protocol-1', 'ESCALATE_SEV1']) {
      expect(isAllowlistedWhisperResponseProtocol(forged)).toBe(false);
      expect(() =>
        WhisperSignalSchema.parse({
          schema_version: 1, whisper_signal_id: 'whisper-1', organisation_id: 'org-1', site_id: 'site-1', name: 'Assistance',
          signal_version: 1, status: 'ACTIVE', ...SIGNAL_CONFIG, response_protocol_id: forged,
          created_at: at, updated_at: at, created_by_user_id: 'admin-1', trace_id: 'trace-1',
        }),
      ).toThrow();
    }
  });
});

describe('W21-02 configuration freeze and version identity', () => {
  it('configuration is editable only in DRAFT', () => {
    expect(isWhisperConfigurationEditable('DRAFT')).toBe(true);
    for (const status of ['SIMULATION', 'FALSE_POSITIVE_TEST', 'ANTI_SPOOF_TEST', 'FIELD_DRILL', 'APPROVAL', 'ACTIVE', 'ROTATED', 'RETIRED'] as const) {
      expect(isWhisperConfigurationEditable(status)).toBe(false);
    }
  });

  it('past DRAFT a semantic change requires a new version, while a no-op edit is merely unchanged', () => {
    expect(classifyWhisperConfigurationEdit('DRAFT', SIGNAL_CONFIG, { ...SIGNAL_CONFIG, minimum_confidence: 0.5 })).toBe('EDITABLE');
    expect(classifyWhisperConfigurationEdit('ACTIVE', SIGNAL_CONFIG, { ...SIGNAL_CONFIG })).toBe('UNCHANGED');
    // Every one of the six semantic fields forces a new version.
    const changes: Array<Partial<WhisperSemanticConfiguration>> = [
      { device_action_id: 'button-triple-press' },
      { authorised_user_ids: ['user-1'] },
      { context_requirements: { on_duty: true, indoors: true } },
      { minimum_confidence: 0.95 },
      { response_protocol_id: null },
    ];
    for (const change of changes) {
      expect(classifyWhisperConfigurationEdit('ACTIVE', SIGNAL_CONFIG, { ...SIGNAL_CONFIG, ...change })).toBe('REQUIRES_NEW_VERSION');
    }
    expect(WHISPER_SEMANTIC_CONFIGURATION_FIELDS).toHaveLength(6);
  });

  it('the fingerprint treats the allowlist as a set and object key order as insignificant', () => {
    expect(whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, authorised_user_ids: ['user-2', 'user-1'] })).toBe(whisperConfigurationFingerprint(SIGNAL_CONFIG));
    const reordered = { ...SIGNAL_CONFIG, context_requirements: { on_duty: true, zone: 'north' } };
    const sameFactsOtherOrder = { ...SIGNAL_CONFIG, context_requirements: { zone: 'north', on_duty: true } };
    expect(whisperConfigurationFingerprint(reordered)).toBe(whisperConfigurationFingerprint(sameFactsOtherOrder));
  });
});

describe('W21-03 the lifecycle admits no shortcut and no resurrection', () => {
  it('every transition outside the canonical chain is refused', () => {
    const statuses = Object.keys(ALLOWED_WHISPER_SIGNAL_STATUS_TRANSITIONS) as WhisperSignalStatus[];
    const canonical = new Set([
      'DRAFT>SIMULATION', 'SIMULATION>FALSE_POSITIVE_TEST', 'FALSE_POSITIVE_TEST>ANTI_SPOOF_TEST',
      'ANTI_SPOOF_TEST>FIELD_DRILL', 'FIELD_DRILL>APPROVAL', 'APPROVAL>ACTIVE', 'ACTIVE>ROTATED', 'ACTIVE>RETIRED',
    ]);
    for (const from of statuses) {
      for (const to of statuses) {
        expect(canTransitionWhisperSignalStatus(from, to)).toBe(canonical.has(`${from}>${to}`));
      }
    }
  });

  it('there is no administrative DRAFT to ACTIVE shortcut and no reactivation of a spent version', () => {
    expect(canTransitionWhisperSignalStatus('DRAFT', 'ACTIVE')).toBe(false);
    expect(canTransitionWhisperSignalStatus('DRAFT', 'APPROVAL')).toBe(false);
    expect(canTransitionWhisperSignalStatus('SIMULATION', 'ACTIVE')).toBe(false);
    for (const terminal of ['ROTATED', 'RETIRED'] as const) {
      expect(isTerminalWhisperSignalStatus(terminal)).toBe(true);
      expect(canTransitionWhisperSignalStatus(terminal, 'ACTIVE')).toBe(false);
      expect(canTransitionWhisperSignalStatus(terminal, 'DRAFT')).toBe(false);
    }
  });
});

describe('W21-06/C11-01 the canonical signed statement', () => {
  it('is domain-tagged canonical JSON over the eleven signed fields', () => {
    const statement = canonicalWhisperSignedStatement(STATEMENT_INPUT);
    expect(JSON.parse(statement)).toEqual({
      domain: WHISPER_SIGNED_STATEMENT_DOMAIN,
      schema_version: 1,
      organisation_id: 'org-1',
      site_id: 'site-1',
      actor_user_id: 'user-1',
      device_id: 'device-1',
      whisper_signal_id: 'whisper-1',
      whisper_signal_version: 3,
      device_action_id: 'button-double-press',
      recognised_at: '2026-08-19T10:00:00.000Z',
      confidence: 0.95,
      anti_replay_nonce: '0123456789abcdef',
    });
    expect(whisperRecognitionFingerprint(STATEMENT_INPUT)).toBe(createHash('sha256').update(statement, 'utf8').digest('hex'));
    expect(whisperRecognitionFingerprint(STATEMENT_INPUT)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('C11-01: a field value containing the old delimiter cannot forge another identity', () => {
    // The delimiter-joined form collided here: org "a\nb" + site "c" and
    // org "a" + site "b\nc" produced identical bytes, so one signature
    // verified for two different tenants.
    const split = { ...STATEMENT_INPUT, organisation_id: 'a\nb', site_id: 'c' };
    const shifted = { ...STATEMENT_INPUT, organisation_id: 'a', site_id: 'b\nc' };
    expect(canonicalWhisperSignedStatement(split)).not.toBe(canonicalWhisperSignedStatement(shifted));
    expect(whisperRecognitionFingerprint(split)).not.toBe(whisperRecognitionFingerprint(shifted));
    // The same attack through a quote or a brace is equally refused.
    const quoted = { ...STATEMENT_INPUT, organisation_id: 'a","site_id":"z' };
    expect(whisperRecognitionFingerprint(quoted)).not.toBe(whisperRecognitionFingerprint(STATEMENT_INPUT));
  });

  it('the observed device_action_id is part of the statement, so a signature cannot be re-presented for another action', () => {
    expect(whisperRecognitionFingerprint({ ...STATEMENT_INPUT, device_action_id: 'button-triple-press' })).not.toBe(
      whisperRecognitionFingerprint(STATEMENT_INPUT),
    );
  });

  it('C11-04: confidence is signed, so it cannot be raised in flight to cross the threshold', () => {
    const raised = { ...STATEMENT_INPUT, confidence: 0.99 };
    expect(whisperRecognitionFingerprint(raised)).not.toBe(whisperRecognitionFingerprint(STATEMENT_INPUT));
    // A recognition below the bar is refused, and lifting the figure changes
    // the signed statement — so the altered claim no longer verifies.
    const belowBar = { ...SIGNED_IDENTITY, confidence: 0.5 };
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: belowBar }))).toEqual({
      eligible: false,
      conflictCode: 'CONFIDENCE_BELOW_THRESHOLD',
    });
    expect(whisperRecognitionFingerprint({ ...STATEMENT_INPUT, confidence: 0.5 })).not.toBe(whisperRecognitionFingerprint(STATEMENT_INPUT));
  });

  it('every identity field changes the statement', () => {
    const variants = [
      { organisation_id: 'org-2' }, { site_id: 'site-2' }, { actor_user_id: 'user-2' }, { device_id: 'device-2' },
      { whisper_signal_id: 'whisper-2' }, { whisper_signal_version: 4 }, { recognised_at: '2026-08-19T10:00:01.000Z' },
      { anti_replay_nonce: 'fedcba9876543210' }, { confidence: 0.96 },
    ];
    for (const variant of variants) {
      expect(canonicalWhisperSignedStatement({ ...STATEMENT_INPUT, ...variant })).not.toBe(canonicalWhisperSignedStatement(STATEMENT_INPUT));
    }
  });

  it('C11-04: only the server-selected Ed25519 algorithm is admitted', () => {
    expect(WHISPER_SIGNATURE_ALGORITHM).toBe('Ed25519');
    const base = {
      schema_version: 1 as const, whisper_result_id: 'result-2', whisper_signal_id: 'whisper-1', whisper_signal_version: 3,
      organisation_id: 'org-1', site_id: 'site-1', actor_user_id: 'user-1', device_id: 'device-1', device_action_id: 'button-double-press',
      recognised_at: at, confidence: 0.95, device_trust: 'TRUSTED' as const, context: { on_duty: true }, freshness_ms: 0,
      anti_replay_nonce: '0123456789abcdef', signature_algorithm: 'Ed25519', signature: '0123456789abcdef', trace_id: 'trace-1',
    };
    expect(DeviceActionWhisperResultSchema.parse(base).signature_algorithm).toBe('Ed25519');
    // A client must never be able to name the verifier — least of all a
    // downgrade the platform could be talked into accepting.
    for (const algorithm of ['none', 'HS256', 'RS256', 'MD5', 'Ed448']) {
      expect(() => DeviceActionWhisperResultSchema.parse({ ...base, signature_algorithm: algorithm })).toThrow();
    }
  });
});

describe('W21-09/C11-01 the replay identity is actor-bound and unambiguous', () => {
  it('exposes the real composite identity that persistence must key on', () => {
    expect(deviceActionWhisperReplayIdentity(STATEMENT_INPUT)).toEqual({
      organisation_id: 'org-1', site_id: 'site-1', actor_user_id: 'user-1', device_id: 'device-1',
      whisper_signal_id: 'whisper-1', whisper_signal_version: 3, anti_replay_nonce: '0123456789abcdef',
    });
    expect(JSON.parse(deviceActionWhisperReplayKey(STATEMENT_INPUT)).domain).toBe(WHISPER_REPLAY_IDENTITY_DOMAIN);
  });

  it('distinguishes actors sharing one device, and every other scope dimension', () => {
    const key = deviceActionWhisperReplayKey(STATEMENT_INPUT);
    const variants = [
      { actor_user_id: 'user-2' }, { organisation_id: 'org-2' }, { site_id: 'site-2' }, { device_id: 'device-2' },
      { whisper_signal_id: 'whisper-2' }, { whisper_signal_version: 4 }, { anti_replay_nonce: 'fedcba9876543210' },
    ];
    for (const variant of variants) {
      expect(deviceActionWhisperReplayKey({ ...STATEMENT_INPUT, ...variant })).not.toBe(key);
    }
  });

  it('C11-01: a colon inside a value cannot make one tenant consume another tenant replay slot', () => {
    const split = { ...STATEMENT_INPUT, organisation_id: 'a:b', site_id: 'c' };
    const shifted = { ...STATEMENT_INPUT, organisation_id: 'a', site_id: 'b:c' };
    expect(deviceActionWhisperReplayKey(split)).not.toBe(deviceActionWhisperReplayKey(shifted));
  });

  it('a reused identity carrying different immutable semantics is a different request', () => {
    const drifted = { ...STATEMENT_INPUT, device_action_id: 'button-triple-press' };
    expect(deviceActionWhisperReplayKey(drifted)).toBe(deviceActionWhisperReplayKey(STATEMENT_INPUT));
    expect(whisperRecognitionFingerprint(drifted)).not.toBe(whisperRecognitionFingerprint(STATEMENT_INPUT));
  });
});

describe('W21-08 freshness is judged against authoritative receipt time', () => {
  it('names its bounds and classifies the boundaries exactly', () => {
    expect(MAX_WHISPER_RECOGNITION_AGE_MS).toBe(120_000);
    expect(MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS).toBe(5_000);
    const recognised = new Date('2026-08-19T10:00:00.000Z');
    const at = (offsetMs: number) => new Date(recognised.getTime() + offsetMs);
    expect(classifyWhisperRecognitionFreshness(recognised, at(0))).toBe('FRESH');
    expect(classifyWhisperRecognitionFreshness(recognised, at(MAX_WHISPER_RECOGNITION_AGE_MS))).toBe('FRESH');
    expect(classifyWhisperRecognitionFreshness(recognised, at(MAX_WHISPER_RECOGNITION_AGE_MS + 1))).toBe('STALE');
    expect(classifyWhisperRecognitionFreshness(recognised, at(-MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS))).toBe('FRESH');
    expect(classifyWhisperRecognitionFreshness(recognised, at(-MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS - 1))).toBe('FUTURE_SKEW');
  });

  it('a device under-reporting its own freshness cannot extend the window', () => {
    // freshness_ms is not an input to the decision at all — the signature is
    // the only client value that matters, and this is judged on server clocks.
    const recognised = new Date('2026-08-19T10:00:00.000Z');
    const received = new Date('2026-08-19T10:05:00.000Z');
    expect(classifyWhisperRecognitionFreshness(recognised, received)).toBe('STALE');
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ freshness: 'STALE' }))).toEqual({ eligible: false, conflictCode: 'RECOGNITION_STALE' });
  });
});

describe('W21-07 client confidence and context cannot authorize', () => {
  it('context is satisfied only by server-established facts, and an unknown fact fails closed', () => {
    expect(evaluateWhisperContextRequirements({ on_duty: true }, { on_duty: true })).toEqual({ satisfied: true });
    expect(evaluateWhisperContextRequirements({ on_duty: true }, { on_duty: false })).toEqual({ satisfied: false, unsatisfiedKeys: ['on_duty'] });
    // No authoritative Field state at all: unknown is not permission.
    expect(evaluateWhisperContextRequirements({ on_duty: true }, {})).toEqual({ satisfied: false, unsatisfiedKeys: ['on_duty'] });
    expect(evaluateWhisperContextRequirements({ on_duty: true }, { on_duty: null })).toEqual({ satisfied: false, unsatisfiedKeys: ['on_duty'] });
  });

  it('a device asserting its own context does not satisfy the requirement', () => {
    // The submitted result's `context` is telemetry; only serverFacts count.
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ serverFacts: {} }))).toEqual({ eligible: false, conflictCode: 'CONTEXT_NOT_SATISFIED' });
  });

  it('signed confidence can only reduce what is permitted', () => {
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, confidence: 0.9 } })).eligible).toBe(true);
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, confidence: 0.89 } }))).toEqual({
      eligible: false,
      conflictCode: 'CONFIDENCE_BELOW_THRESHOLD',
    });
  });

  it('live device trust is the platform judgement, and only TRUSTED may invoke', () => {
    expect(WHISPER_INVOCATION_TRUST_STATES).toEqual(['TRUSTED']);
    expect(deviceTrustPermitsWhisperInvocation('TRUSTED')).toBe(true);
    for (const trust of ['DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'] as const) {
      expect(deviceTrustPermitsWhisperInvocation(trust)).toBe(false);
      expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ context: { ...DEVICE_CONTEXT, deviceTrust: trust } }))).toEqual({
        eligible: false,
        conflictCode: 'DEVICE_TRUST_INSUFFICIENT',
      });
    }
  });
});

describe('W21-04 configuration eligibility is not runtime authority', () => {
  it('a named user who has since lost their current authority cannot invoke', () => {
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput()).eligible).toBe(true);
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ actorHoldsCurrentAuthority: false }))).toEqual({
      eligible: false,
      conflictCode: 'ACTOR_NOT_ELIGIBLE',
    });
  });

  it('an unnamed user cannot invoke even while currently authorised elsewhere', () => {
    // Identity is consistent — the signed result and the trusted context name
    // the same person — so the ONLY thing refusing this is the allowlist.
    const context = { ...DEVICE_CONTEXT, actorUserId: 'user-9' };
    const result = { ...SIGNED_IDENTITY, actor_user_id: 'user-9' };
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ context, result }))).toEqual({ eligible: false, conflictCode: 'ACTOR_NOT_ELIGIBLE' });
    // And an identity that does NOT agree is refused earlier still, by C11-02.
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ context }))).toEqual({ eligible: false, conflictCode: 'DEVICE_CONTEXT_MISMATCH' });
  });

  it('only the exact ACTIVE version resolves, and the resolved protocol comes from the stored signal', () => {
    for (const status of ['DRAFT', 'SIMULATION', 'APPROVAL', 'ROTATED', 'RETIRED'] as const) {
      expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: { ...SIGNAL_SCOPE, status, signal_version: 3, ...SIGNAL_CONFIG } }))).toEqual({
        eligible: false,
        conflictCode: 'SIGNAL_NOT_ACTIVE',
      });
    }
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, whisper_signal_version: 2 } }))).toEqual({
      eligible: false,
      conflictCode: 'SIGNAL_VERSION_MISMATCH',
    });
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, device_action_id: 'button-triple-press' } }))).toEqual({
      eligible: false,
      conflictCode: 'DEVICE_ACTION_MISMATCH',
    });
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput())).toEqual({ eligible: true, responseProtocolId: 'SILENT_INCIDENT_RESPONSE' });
  });

  it('a site outside the authenticated device scope is refused before anything reveals the signal', () => {
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, site_id: 'site-2' } }))).toEqual({
      eligible: false,
      conflictCode: 'SITE_SCOPE_MISMATCH',
    });
  });
});

describe('W21-12/W21-13 authority vocabulary and activation approval', () => {
  it('proposes four separate capabilities with commander-only management and operative-only invocation', () => {
    expect(WHISPER_ACTIONS).toEqual(['whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve', 'whisper.device-action.invoke']);
    expect(PROPOSED_WHISPER_ROLE_ACTIONS['site.commander']).toEqual(['whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve']);
    expect(PROPOSED_WHISPER_ROLE_ACTIONS['field.operative']).toEqual(['whisper.device-action.invoke']);
    // Platform administration is not authority over a silent duress channel.
    for (const role of ['dispatcher', 'operator', 'investigator', 'evidence.custodian', 'admin']) {
      expect(PROPOSED_WHISPER_ROLE_ACTIONS[role]).toEqual([]);
    }
    // No role may both manage and invoke.
    for (const actions of Object.values(PROPOSED_WHISPER_ROLE_ACTIONS)) {
      expect(actions.includes('whisper.signal.manage') && actions.includes('whisper.device-action.invoke')).toBe(false);
    }
  });

  it('activation requires a person distinct from the version creator', () => {
    expect(whisperActivationApproverIsDistinct('creator-1', 'approver-1')).toBe(true);
    expect(whisperActivationApproverIsDistinct('creator-1', 'creator-1')).toBe(false);
    const approval = {
      schema_version: 1 as const, whisper_signal_id: 'whisper-1', signal_version: 3,
      configuration_fingerprint: whisperConfigurationFingerprint(SIGNAL_CONFIG),
      approved_by_user_id: 'commander-2', created_by_user_id: 'commander-1', approved_at: at, trace_id: 'trace-1',
    };
    expect(WhisperActivationApprovalSchema.parse(approval).approved_by_user_id).toBe('commander-2');
    expect(() => WhisperActivationApprovalSchema.parse({ ...approval, approved_by_user_id: 'commander-1' })).toThrow(/distinct/);
  });

  it('W21-13: an activation approval cannot masquerade as an operational response approval', () => {
    const approval = {
      schema_version: 1 as const, whisper_signal_id: 'whisper-1', signal_version: 3,
      configuration_fingerprint: whisperConfigurationFingerprint(SIGNAL_CONFIG),
      approved_by_user_id: 'commander-2', created_by_user_id: 'commander-1', approved_at: at, trace_id: 'trace-1',
    };
    // The shape carries no incident, task or dispatch reference — structurally,
    // it cannot be replayed as approval of a SILENT response.
    for (const forged of [{ incident_id: 'incident-1' }, { task_id: 'task-1' }, { silent_dispatch_approved: true }]) {
      expect(() => WhisperActivationApprovalSchema.parse({ ...approval, ...forged })).toThrow();
    }
    // And it is bound to the exact tested configuration.
    expect(approval.configuration_fingerprint).toBe(whisperConfigurationFingerprint(SIGNAL_CONFIG));
    expect(approval.configuration_fingerprint).not.toBe(whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, minimum_confidence: 0.5 }));
  });
});

describe('W21-14 audit records identity and disposition, never the secret', () => {
  const payload = {
    whisper_signal_id: 'whisper-1', signal_version: 3, configuration_fingerprint: whisperConfigurationFingerprint(SIGNAL_CONFIG),
    actor_user_id: 'user-1', device_id: 'device-1', from_status: 'APPROVAL' as const, to_status: 'ACTIVE' as const,
    outcome: 'ACCEPTED' as const, conflict_code: null, recognition_fingerprint: whisperRecognitionFingerprint(STATEMENT_INPUT),
    response_protocol_id: 'SILENT_INCIDENT_RESPONSE' as const, incident_id: 'incident-1', trace_id: 'trace-1',
  };

  it('accepts the allowlisted disposition fields', () => {
    expect(WhisperAuditPayloadSchema.parse(payload).to_status).toBe('ACTIVE');
  });

  it('refuses every field that would disclose the discreet action, the keys or the roster', () => {
    for (const leak of [
      { device_action_definition: 'double-press the volume rocker' },
      { signature: '0123456789abcdef' },
      { public_key: 'MCowBQYDK2VwAyEA' },
      { authorised_user_ids: ['user-1', 'user-2'] },
      { context_requirements: { on_duty: true } },
      { anti_replay_nonce: '0123456789abcdef' },
    ]) {
      expect(() => WhisperAuditPayloadSchema.parse({ ...payload, ...leak })).toThrow();
    }
  });
});

describe('C11-02 the signed identity and the resolved signal are bound to the trusted scope', () => {
  it('a signed result naming another organisation, actor or device is refused before anything is revealed', () => {
    for (const forged of [{ organisation_id: 'org-2' }, { actor_user_id: 'user-2' }, { device_id: 'device-2' }]) {
      expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ result: { ...SIGNED_IDENTITY, ...forged } }))).toEqual({
        eligible: false,
        conflictCode: 'DEVICE_CONTEXT_MISMATCH',
      });
    }
  });

  it('a signal from another organisation cannot be fired even by a perfectly authenticated device', () => {
    const foreignSignal = { organisation_id: 'org-2', site_id: 'site-1' as string | null, status: 'ACTIVE' as const, signal_version: 3, ...SIGNAL_CONFIG };
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: foreignSignal }))).toEqual({ eligible: false, conflictCode: 'SIGNAL_SCOPE_MISMATCH' });
  });

  it('a site-scoped signal cannot be fired at a different site of the same organisation', () => {
    const otherSite = { organisation_id: 'org-1', site_id: 'site-9' as string | null, status: 'ACTIVE' as const, signal_version: 3, ...SIGNAL_CONFIG };
    const context = { ...DEVICE_CONTEXT, authorisedSiteIds: ['site-1', 'site-9'] };
    // The device is entitled to both sites, so only the signal's own scope refuses it.
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: otherSite, context }))).toEqual({
      eligible: false,
      conflictCode: 'SIGNAL_SCOPE_MISMATCH',
    });
  });

  it('an organisation-wide signal (null site) fires only at a site the device is entitled to', () => {
    const orgWide = { organisation_id: 'org-1', site_id: null, status: 'ACTIVE' as const, signal_version: 3, ...SIGNAL_CONFIG };
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: orgWide }))).toEqual({ eligible: true, responseProtocolId: 'SILENT_INCIDENT_RESPONSE' });
    // Organisation-wide is NOT a bypass of the device's own site entitlement.
    expect(
      evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: orgWide, result: { ...SIGNED_IDENTITY, site_id: 'site-2' } })),
    ).toEqual({ eligible: false, conflictCode: 'SITE_SCOPE_MISMATCH' });
  });
});

describe('C11-03 context values must be losslessly canonical', () => {
  it('rejects values JSON cannot represent, at any nesting depth', () => {
    const signal = {
      schema_version: 1 as const, whisper_signal_id: 'whisper-1', organisation_id: 'org-1', site_id: 'site-1', name: 'Assistance',
      signal_version: 1, status: 'DRAFT' as const, ...SIGNAL_CONFIG, created_at: at, updated_at: at, created_by_user_id: 'admin-1', trace_id: 'trace-1',
    };
    for (const requirements of [
      { on_duty: undefined },
      { on_duty: Number.NaN },
      { on_duty: Number.POSITIVE_INFINITY },
      { nested: { deep: Number.NaN } },
      { nested: [1, Number.NEGATIVE_INFINITY] },
    ]) {
      expect(() => WhisperSignalSchema.parse({ ...signal, context_requirements: requirements })).toThrow();
    }
    // Ordinary JSON shapes remain admissible, including nested ones.
    expect(
      WhisperSignalSchema.parse({ ...signal, context_requirements: { on_duty: true, zone: { name: 'north', level: 2 }, tags: ['a', 'b'] } }).status,
    ).toBe('DRAFT');
  });

  it('the fingerprint refuses unrepresentable input rather than silently normalising it', () => {
    expect(() => whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, context_requirements: { on_duty: Number.NaN } as never })).toThrow(/canonically/);
    expect(() => whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, context_requirements: { on_duty: undefined } as never })).toThrow(/canonically/);
  });

  it('values that JSON.stringify would have collapsed stay distinguishable', () => {
    // Both of these once serialised to {"a":null}: a dropped member and an
    // explicit null are materially different requirements, and an activation
    // approval attests to the exact one that was tested.
    const explicitNull = whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, context_requirements: { a: null } });
    const empty = whisperConfigurationFingerprint({ ...SIGNAL_CONFIG, context_requirements: {} });
    expect(explicitNull).not.toBe(empty);
    expect(explicitNull).toMatch(/^[0-9a-f]{64}$/);
  });

  it('a server fact that cannot be represented canonically does not satisfy a requirement', () => {
    expect(evaluateWhisperContextRequirements({ on_duty: true }, { on_duty: Number.NaN })).toEqual({ satisfied: false, unsatisfiedKeys: ['on_duty'] });
  });
});

describe('C11-01 fingerprints are pinned to their exact hex shape', () => {
  it('refuses a digest that is the right length but not lowercase hex', () => {
    const approval = {
      schema_version: 1 as const, whisper_signal_id: 'whisper-1', signal_version: 3,
      configuration_fingerprint: whisperConfigurationFingerprint(SIGNAL_CONFIG),
      approved_by_user_id: 'commander-2', created_by_user_id: 'commander-1', approved_at: at, trace_id: 'trace-1',
    };
    expect(WhisperActivationApprovalSchema.parse(approval).configuration_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    for (const bad of ['A'.repeat(64), 'g'.repeat(64), '0'.repeat(63), '0'.repeat(65)]) {
      expect(() => WhisperActivationApprovalSchema.parse({ ...approval, configuration_fingerprint: bad })).toThrow();
    }
  });
});
