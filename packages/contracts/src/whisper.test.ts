import { describe, expect, it } from 'vitest';
import {
  DeviceActionWhisperResultSchema,
  WhisperSignalSchema,
  WhisperSignalStatusSchema,
  canTransitionWhisperSignalStatus,
  deviceActionWhisperReplayKey,
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
    context_requirements: { on_duty: true }, minimum_confidence: 0.9, response_protocol_id: 'protocol-1', created_at: at, updated_at: at,
    created_by_user_id: 'admin-1', trace_id: 'trace-1',
  };

  it('accepts a versioned device-action signal that only references a protocol', () => {
    expect(WhisperSignalSchema.parse(signal).response_protocol_id).toBe('protocol-1');
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
    actor_user_id: 'user-1', device_id: 'device-1', recognised_at: at, confidence: 0.95, device_trust: 'TRUSTED' as const, context: { on_duty: true },
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
