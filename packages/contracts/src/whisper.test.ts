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
  WHISPER_SIGNED_STATEMENT_DOMAIN,
  WhisperActivationApprovalSchema,
  WhisperAuditPayloadSchema,
  WhisperSignalSchema,
  WhisperSignalStatusSchema,
  canTransitionWhisperSignalStatus,
  canonicalWhisperSignedStatement,
  classifyWhisperConfigurationEdit,
  classifyWhisperRecognitionFreshness,
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
  context_requirements: { on_duty: true } as Record<string, unknown>,
  minimum_confidence: 0.9,
  response_protocol_id: 'SILENT_INCIDENT_RESPONSE' as const,
};

const DEVICE_CONTEXT: AuthenticatedWhisperDeviceContext = {
  organisationId: 'org-1',
  actorUserId: 'user-1',
  deviceId: 'device-1',
  authorisedSiteIds: ['site-1'],
  deviceTrust: 'TRUSTED',
  verificationKeyId: 'key-1',
};

function eligibilityInput(overrides: Partial<WhisperRuntimeEligibilityInput> = {}): WhisperRuntimeEligibilityInput {
  return {
    signal: { status: 'ACTIVE', signal_version: 3, ...SIGNAL_CONFIG },
    context: DEVICE_CONTEXT,
    claimedSignalVersion: 3,
    claimedSiteId: 'site-1',
    claimedDeviceActionId: 'button-double-press',
    reportedConfidence: 0.95,
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

describe('W21-06 the canonical signed statement', () => {
  it('binds exactly the ten documented identity fields, domain-separated', () => {
    expect(canonicalWhisperSignedStatement(STATEMENT_INPUT)).toBe(
      [
        WHISPER_SIGNED_STATEMENT_DOMAIN, '1', 'org-1', 'site-1', 'user-1', 'device-1', 'whisper-1', '3', 'button-double-press',
        '2026-08-19T10:00:00.000Z', '0123456789abcdef',
      ].join('\n'),
    );
    expect(whisperRecognitionFingerprint(STATEMENT_INPUT)).toBe(
      createHash('sha256').update(canonicalWhisperSignedStatement(STATEMENT_INPUT), 'utf8').digest('hex'),
    );
  });

  it('the observed device_action_id is part of the statement, so a signature cannot be re-presented for another action', () => {
    expect(whisperRecognitionFingerprint({ ...STATEMENT_INPUT, device_action_id: 'button-triple-press' })).not.toBe(
      whisperRecognitionFingerprint(STATEMENT_INPUT),
    );
  });

  it('every identity field changes the statement', () => {
    const variants = [
      { organisation_id: 'org-2' }, { site_id: 'site-2' }, { actor_user_id: 'user-2' }, { device_id: 'device-2' },
      { whisper_signal_id: 'whisper-2' }, { whisper_signal_version: 4 }, { recognised_at: '2026-08-19T10:00:01.000Z' },
      { anti_replay_nonce: 'fedcba9876543210' },
    ];
    for (const variant of variants) {
      expect(canonicalWhisperSignedStatement({ ...STATEMENT_INPUT, ...variant })).not.toBe(canonicalWhisperSignedStatement(STATEMENT_INPUT));
    }
  });
});

describe('W21-09 the replay identity is actor-bound', () => {
  it('distinguishes actors sharing one device, and every other scope dimension', () => {
    const base = { ...STATEMENT_INPUT };
    const key = deviceActionWhisperReplayKey(base);
    expect(deviceActionWhisperReplayKey({ ...base, actor_user_id: 'user-2' })).not.toBe(key);
    expect(deviceActionWhisperReplayKey({ ...base, organisation_id: 'org-2' })).not.toBe(key);
    expect(deviceActionWhisperReplayKey({ ...base, site_id: 'site-2' })).not.toBe(key);
    expect(deviceActionWhisperReplayKey({ ...base, device_id: 'device-2' })).not.toBe(key);
    expect(deviceActionWhisperReplayKey({ ...base, whisper_signal_version: 4 })).not.toBe(key);
    expect(deviceActionWhisperReplayKey({ ...base, anti_replay_nonce: 'fedcba9876543210' })).not.toBe(key);
  });

  it('a reused identity carrying different immutable semantics is a different request', () => {
    // Same replay identity (nonce and scope unchanged), different signed
    // statement: the runtime must treat this as a conflict, never converge it.
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

  it('reported confidence can only reduce what is permitted', () => {
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ reportedConfidence: 0.9 })).eligible).toBe(true);
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ reportedConfidence: 0.89 }))).toEqual({
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
    const context = { ...DEVICE_CONTEXT, actorUserId: 'user-9' };
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ context }))).toEqual({ eligible: false, conflictCode: 'ACTOR_NOT_ELIGIBLE' });
  });

  it('only the exact ACTIVE version resolves, and the resolved protocol comes from the stored signal', () => {
    for (const status of ['DRAFT', 'SIMULATION', 'APPROVAL', 'ROTATED', 'RETIRED'] as const) {
      expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ signal: { status, signal_version: 3, ...SIGNAL_CONFIG } }))).toEqual({
        eligible: false,
        conflictCode: 'SIGNAL_NOT_ACTIVE',
      });
    }
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ claimedSignalVersion: 2 }))).toEqual({ eligible: false, conflictCode: 'SIGNAL_VERSION_MISMATCH' });
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ claimedDeviceActionId: 'button-triple-press' }))).toEqual({
      eligible: false,
      conflictCode: 'DEVICE_ACTION_MISMATCH',
    });
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput())).toEqual({ eligible: true, responseProtocolId: 'SILENT_INCIDENT_RESPONSE' });
  });

  it('a site outside the authenticated device scope is refused before anything reveals the signal', () => {
    expect(evaluateWhisperRuntimeEligibility(eligibilityInput({ claimedSiteId: 'site-2' }))).toEqual({ eligible: false, conflictCode: 'SITE_SCOPE_MISMATCH' });
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
