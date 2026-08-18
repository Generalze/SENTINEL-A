import { describe, expect, it } from 'vitest';
import {
  CheckpointVerificationSchema,
  FieldAssignmentSchema,
  FieldAssignmentStatusSchema,
  FieldOperativeStateUpdateSchema,
  FieldStateSchema,
  FieldOfflineOperationSchema,
  IncidentFieldMessageSchema,
  MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES,
  PatrolCheckpointSchema,
  PatrolRouteSchema,
  canTransitionFieldAssignmentStatus,
  isNewerOfflineOperation,
  offlineOperationReplayKey,
} from './field';

const at = '2026-08-16T10:00:00Z';

const assignment = {
  schema_version: 1 as const,
  assignment_id: 'assignment-1',
  organisation_id: 'org-1',
  site_id: 'site-1',
  incident_id: 'incident-1',
  assignee_user_id: 'user-1',
  assignment_type: 'INCIDENT_RESPONSE',
  priority: 'SEV2' as const,
  status: 'ACCEPTED' as const,
  delivery_state: 'ACKNOWLEDGED' as const,
  need_to_know_summary: 'Proceed to the north gate.',
  created_at: at,
  updated_at: at,
  expires_at: null,
  accepted_at: at,
  completed_at: null,
  created_by_user_id: 'dispatcher-1',
  updated_by_user_id: 'dispatcher-1',
  accepted_by_user_id: 'user-1',
  trace_id: 'trace-1',
};

describe('FieldStateSchema / FieldAssignmentStatusSchema', () => {
  it('accepts every documented field state and assignment state', () => {
    for (const state of ['AVAILABLE', 'PATROL', 'OBSERVING', 'RESPONDING', 'ON_SCENE', 'NEED_SUPPORT', 'COMPROMISED', 'OFF_DUTY']) {
      expect(FieldStateSchema.parse(state)).toBe(state);
    }
    for (const status of ['REQUESTED', 'ACCEPTED', 'DECLINED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'EXPIRED']) {
      expect(FieldAssignmentStatusSchema.parse(status)).toBe(status);
    }
  });

  it('rejects invalid field and assignment states', () => {
    expect(() => FieldStateSchema.parse('ONLINE')).toThrow();
    expect(() => FieldAssignmentStatusSchema.parse('PENDING')).toThrow();
  });

  it('allows only defined assignment lifecycle transitions', () => {
    expect(canTransitionFieldAssignmentStatus('REQUESTED', 'ACCEPTED')).toBe(true);
    expect(canTransitionFieldAssignmentStatus('ACCEPTED', 'IN_PROGRESS')).toBe(true);
    expect(canTransitionFieldAssignmentStatus('COMPLETED', 'IN_PROGRESS')).toBe(false);
    expect(canTransitionFieldAssignmentStatus('REQUESTED', 'COMPLETED')).toBe(false);
  });
});

describe('FieldAssignmentSchema', () => {
  it('accepts a tenant-scoped assignment using shared delivery semantics', () => {
    expect(FieldAssignmentSchema.parse(assignment).delivery_state).toBe('ACKNOWLEDGED');
  });

  it('rejects an invalid tenant or site scope', () => {
    expect(() => FieldAssignmentSchema.parse({ ...assignment, organisation_id: '' })).toThrow();
    expect(() => FieldAssignmentSchema.parse({ ...assignment, site_id: '' })).toThrow();
  });

  it('rejects accepted states without the required acceptance actor and time', () => {
    expect(() => FieldAssignmentSchema.parse({ ...assignment, accepted_at: null })).toThrow();
  });

  it('rejects acceptance by a different user or before creation', () => {
    expect(() => FieldAssignmentSchema.parse({ ...assignment, accepted_by_user_id: 'user-2' })).toThrow(/accepted_by_user_id/);
    expect(() => FieldAssignmentSchema.parse({ ...assignment, accepted_at: '2026-08-16T09:59:59Z' })).toThrow(/accepted_at/);
  });

  it('rejects completed assignments without consistent completion time', () => {
    expect(() => FieldAssignmentSchema.parse({ ...assignment, status: 'COMPLETED', completed_at: null })).toThrow(/completed_at/);
    expect(() =>
      FieldAssignmentSchema.parse({ ...assignment, status: 'COMPLETED', accepted_at: at, completed_at: '2026-08-16T09:59:59Z' })
    ).toThrow(/completed_at/);
  });

  it('accepts the timestamp boundary updated_at === created_at', () => {
    expect(FieldAssignmentSchema.parse(assignment).updated_at).toBe(at);
  });
});

describe('FieldOperativeStateUpdateSchema', () => {
  const update = {
    schema_version: 1 as const, organisation_id: 'org-1', site_id: 'site-1', actor_user_id: 'user-1', device_id: 'device-1',
    state: 'RESPONDING' as const, location: { latitude: 6.5, longitude: 3.3 }, source_at: at, freshness_ms: 0, trace_id: 'trace-1',
  };

  it('accepts an audited state update with boundary freshness', () => {
    expect(FieldOperativeStateUpdateSchema.parse(update).freshness_ms).toBe(0);
  });

  it('rejects invalid site scope and negative freshness', () => {
    expect(() => FieldOperativeStateUpdateSchema.parse({ ...update, site_id: '' })).toThrow();
    expect(() => FieldOperativeStateUpdateSchema.parse({ ...update, freshness_ms: -1 })).toThrow();
  });
});

describe('PatrolRouteSchema / PatrolCheckpointSchema / CheckpointVerificationSchema', () => {
  const route = {
    schema_version: 1 as const, patrol_route_id: 'route-1', organisation_id: 'org-1', site_id: 'site-1', name: 'Perimeter', route_version: 1,
    checkpoint_ids: ['checkpoint-1'], created_at: at, updated_at: at, created_by_user_id: 'supervisor-1', trace_id: 'trace-1',
  };
  // WP-19/C9-04: a checkpoint now belongs to an exact route version and carries
  // that version's timing standard.
  const checkpoint = {
    schema_version: 1 as const, patrol_checkpoint_id: 'checkpoint-1', patrol_route_id: 'route-1', route_version: 1,
    organisation_id: 'org-1', site_id: 'site-1', sequence_number: 1, name: 'North gate', zone_id: null, location: null,
    window_open_offset_ms: 0, late_after_offset_ms: 300_000, missed_after_offset_ms: 900_000, trace_id: 'trace-1',
  };
  // WP-19/C9-01: a verification is bound to the run and run-checkpoint it
  // belongs to, otherwise two executions of one route are indistinguishable.
  const verification = {
    schema_version: 1 as const, checkpoint_verification_id: 'verification-1', organisation_id: 'org-1', site_id: 'site-1',
    patrol_run_id: 'run-1', patrol_run_checkpoint_id: 'run-checkpoint-1', patrol_route_id: 'route-1', route_version: 1,
    patrol_checkpoint_id: 'checkpoint-1', operative_user_id: 'user-1', device_id: 'device-1', verification_method: 'NFC', verification_context: {},
    source_at: at, recorded_at: at, idempotency_key: 'verification-op-1', trace_id: 'trace-1',
  };

  it('accepts valid route, ordered checkpoint, and verification records', () => {
    expect(PatrolRouteSchema.parse(route).checkpoint_ids).toEqual(['checkpoint-1']);
    expect(PatrolCheckpointSchema.parse(checkpoint).sequence_number).toBe(1);
    expect(CheckpointVerificationSchema.parse(verification).idempotency_key).toBe('verification-op-1');
  });

  it('rejects duplicate route checkpoints, zero sequence, and cross-scope blanks', () => {
    expect(() => PatrolRouteSchema.parse({ ...route, checkpoint_ids: ['checkpoint-1', 'checkpoint-1'] })).toThrow();
    expect(() => PatrolCheckpointSchema.parse({ ...checkpoint, sequence_number: 0 })).toThrow();
    expect(() => CheckpointVerificationSchema.parse({ ...verification, organisation_id: '' })).toThrow();
  });

  // WP-19/C9-01: the old rule here required recorded_at >= source_at. It is
  // removed deliberately — source_at is device telemetry and recorded_at is the
  // server's authority, so a device clock running fast must not be able to veto
  // a valid receipt.
  it('accepts a verification whose device clock runs ahead of the server receipt', () => {
    expect(CheckpointVerificationSchema.parse({ ...verification, source_at: '2026-08-16T10:30:00Z' })).toMatchObject({ recorded_at: at });
  });
});

describe('IncidentFieldMessageSchema', () => {
  const message = {
    schema_version: 1 as const, incident_field_message_id: 'message-1', organisation_id: 'org-1', site_id: 'site-1', incident_id: 'incident-1',
    sender_user_id: 'user-1', recipient_user_ids: ['user-2'], body: 'Hold position.', media_refs: [], delivery_state: 'REQUESTED' as const,
    retention_class: 'INCIDENT_OPERATIONAL', sent_at: at, expires_at: null, trace_id: 'trace-1',
  };

  it('accepts an incident-scoped message with the shared delivery state', () => {
    expect(IncidentFieldMessageSchema.parse(message).delivery_state).toBe('REQUESTED');
  });

  it('rejects invalid site scope and messages with no content', () => {
    expect(() => IncidentFieldMessageSchema.parse({ ...message, site_id: '' })).toThrow();
    expect(() => IncidentFieldMessageSchema.parse({ ...message, body: null, media_refs: [] })).toThrow();
  });

  it('rejects an over-large body payload at the byte boundary', () => {
    expect(() => IncidentFieldMessageSchema.parse({ ...message, body: 'x'.repeat(MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES + 1) })).toThrow();
  });
});

describe('FieldOfflineOperationSchema', () => {
  const operation = {
    schema_version: 1 as const, offline_operation_id: 'offline-1', organisation_id: 'org-1', site_id: 'site-1', device_id: 'device-1',
    device_sequence: 0, idempotency_key: 'operation-key-1', operation_kind: 'FIELD_STATE_UPDATE', payload: { state: 'PATROL' }, created_at: at, trace_id: 'trace-1',
  };

  it('accepts sequence zero as the first monotonic device operation', () => {
    expect(FieldOfflineOperationSchema.parse(operation).device_sequence).toBe(0);
  });

  it('rejects negative device sequence and invalid tenant scope', () => {
    expect(() => FieldOfflineOperationSchema.parse({ ...operation, device_sequence: -1 })).toThrow();
    expect(() => FieldOfflineOperationSchema.parse({ ...operation, organisation_id: '' })).toThrow();
  });

  it('makes duplicate and old replay detectable by device plus sequence', () => {
    const next = { ...operation, device_sequence: 1 };
    const duplicate = { ...operation };
    expect(offlineOperationReplayKey(operation)).toBe(offlineOperationReplayKey(duplicate));
    expect(offlineOperationReplayKey(operation)).not.toBe(offlineOperationReplayKey({ ...duplicate, organisation_id: 'org-2' }));
    expect(offlineOperationReplayKey(operation)).not.toBe(offlineOperationReplayKey({ ...duplicate, site_id: 'site-2' }));
    expect(isNewerOfflineOperation(operation, duplicate)).toBe(false);
    expect(isNewerOfflineOperation(next, operation)).toBe(false);
    expect(isNewerOfflineOperation(operation, next)).toBe(true);
  });
});
