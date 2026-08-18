import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicaliseOfflineSemanticRequest,
  classifyOfflineSequence,
  deriveOfflineDownstreamIdempotencyKey,
  FieldOfflineOperationSchema,
  FieldOfflineOperationV2Schema,
  fingerprintOfflineSemanticRequest,
  isNewerOfflineOperation,
  MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES,
  MAX_OFFLINE_DEVICE_SEQUENCE,
  nextExpectedOfflineSequence,
  OFFLINE_SEQUENCE_START,
  offlineReceiptAdvancesCursor,
  OfflineOperationResultSchema,
  OfflineReplayConflictCodeSchema,
  OfflineReplayConflictSchema,
  type FieldOfflineOperationV2,
  type OfflineReplayNamespace,
} from './index.js';

/** WP-20 Checkpoint A Crucible (directive section 14). */

const NAMESPACE: OfflineReplayNamespace = {
  organisation_id: 'org-1',
  site_id: 'site-1',
  user_id: 'user-1',
  device_id: 'device-1',
};

const OP_ID = 'a3bb1a10-2c3d-4e5f-8a9b-0c1d2e3f4a5b';
const ASSIGNMENT_ID = 'b4cc2b21-3d4e-4f60-9aab-1d2e3f4a5b6c';
const INCIDENT_ID = 'c5dd3c32-4e5f-4071-abbc-2e3f4a5b6c7d';
const MESSAGE_ID = 'd6ee4d43-5f60-4182-bccd-3f4a5b6c7d8e';

function acceptOperation(overrides: Record<string, unknown> = {}): FieldOfflineOperationV2 {
  return FieldOfflineOperationV2Schema.parse({
    schema_version: 2,
    offline_operation_id: OP_ID,
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
    device_sequence: 0,
    idempotency_key: 'client-key-1',
    operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
    payload: { assignment_id: ASSIGNMENT_ID, expected_status: 'REQUESTED' },
    created_at: '2026-08-18T10:00:00.000Z',
    trace_id: 'trace-1',
    ...overrides,
  });
}

function sendOperation(payloadOverrides: Record<string, unknown> = {}, envelopeOverrides: Record<string, unknown> = {}): FieldOfflineOperationV2 {
  return FieldOfflineOperationV2Schema.parse({
    schema_version: 2,
    offline_operation_id: OP_ID,
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
    device_sequence: 3,
    idempotency_key: 'client-key-3',
    operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
    payload: {
      incident_id: INCIDENT_ID,
      recipient_user_ids: ['user-2', 'user-3'],
      body: 'North gate is clear.',
      media_refs: ['media-a', 'media-b'],
      retention_class: 'OPERATIONAL_30D',
      expires_at: null,
      ...payloadOverrides,
    },
    created_at: '2026-08-18T10:05:00.000Z',
    trace_id: 'trace-3',
    ...envelopeOverrides,
  });
}

describe('WP-20/C10-03 sequence classification is contiguous', () => {
  it('a fresh namespace accepts exactly sequence 0', () => {
    expect(classifyOfflineSequence({ last_finalized_sequence: null, incoming_sequence: 0, receipt: { exists: false } })).toBe('FRESH');
    expect(OFFLINE_SEQUENCE_START).toBe(0);
    expect(nextExpectedOfflineSequence(null)).toBe(0);
  });

  it('N+1 is fresh; anything beyond is a gap that must never leapfrog N', () => {
    expect(classifyOfflineSequence({ last_finalized_sequence: 4, incoming_sequence: 5, receipt: { exists: false } })).toBe('FRESH');
    expect(classifyOfflineSequence({ last_finalized_sequence: 4, incoming_sequence: 6, receipt: { exists: false } })).toBe('SEQUENCE_GAP');
    // A fresh namespace with a nonzero start is equally a gap.
    expect(classifyOfflineSequence({ last_finalized_sequence: null, incoming_sequence: 1, receipt: { exists: false } })).toBe('SEQUENCE_GAP');
    expect(nextExpectedOfflineSequence(4)).toBe(5);
  });

  it('an old sequence with a receipt replays or conflicts by fingerprint; without a receipt it is stale', () => {
    expect(classifyOfflineSequence({ last_finalized_sequence: 4, incoming_sequence: 2, receipt: { exists: true, same_semantic_request: true } })).toBe('REPLAY');
    expect(classifyOfflineSequence({ last_finalized_sequence: 4, incoming_sequence: 2, receipt: { exists: true, same_semantic_request: false } })).toBe('SEQUENCE_REUSED');
    expect(classifyOfflineSequence({ last_finalized_sequence: 4, incoming_sequence: 2, receipt: { exists: false } })).toBe('SEQUENCE_STALE');
  });

  /**
   * B10-03. The namespace is finite, so the contract must say so out loud
   * rather than compute MAX + 1 and hand back a position that is no longer a
   * safe integer. There is no reset: a device that has consumed every position
   * needs a new authenticated identity, not a rewound cursor.
   */
  it('B10-03: a finalized MAX exhausts the namespace and there is no next sequence', () => {
    expect(nextExpectedOfflineSequence(MAX_OFFLINE_DEVICE_SEQUENCE)).toBeNull();
    expect(nextExpectedOfflineSequence(MAX_OFFLINE_DEVICE_SEQUENCE - 1)).toBe(MAX_OFFLINE_DEVICE_SEQUENCE);
  });

  it('B10-03: an exhausted namespace is judged purely by its receipt — never FRESH, never a GAP', () => {
    const exhausted = { last_finalized_sequence: MAX_OFFLINE_DEVICE_SEQUENCE, incoming_sequence: MAX_OFFLINE_DEVICE_SEQUENCE };
    // The finalized MAX position can still be read back.
    expect(classifyOfflineSequence({ ...exhausted, receipt: { exists: true, same_semantic_request: true } })).toBe('REPLAY');
    // A CHANGED request may never hide behind the identity MAX established.
    expect(classifyOfflineSequence({ ...exhausted, receipt: { exists: true, same_semantic_request: false } })).toBe('SEQUENCE_REUSED');
    // A consumed position with no receipt is stale, exactly as anywhere else.
    expect(classifyOfflineSequence({ ...exhausted, receipt: { exists: false } })).toBe('SEQUENCE_STALE');
  });

  it('B10-03: a result may report a null next_expected_sequence when the namespace is exhausted', () => {
    const result = OfflineOperationResultSchema.parse({
      schema_version: 2,
      offline_operation_id: OP_ID,
      device_sequence: MAX_OFFLINE_DEVICE_SEQUENCE,
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      outcome: 'APPLIED',
      replayed: false,
      finalized_at: '2026-08-18T10:06:00.000Z',
      next_expected_sequence: null,
      result_ref: OP_ID,
      result_snapshot: { assignment_id: OP_ID, status: 'ACCEPTED' },
      trace_id: 'trace-max',
    });
    expect(result.next_expected_sequence).toBeNull();
  });
});

describe('WP-20/C10-04 the semantic request is request-bound', () => {
  it('a fresh trace_id does not change the semantic request', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation({ trace_id: 'trace-1' }));
    const b = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation({ trace_id: 'trace-retry-99' }));
    expect(a).toBe(b);
  });

  it('object key order does not change the semantic request', () => {
    const ordered = acceptOperation();
    const reordered = FieldOfflineOperationV2Schema.parse({
      trace_id: 'trace-1',
      created_at: '2026-08-18T10:00:00.000Z',
      payload: { expected_status: 'REQUESTED', assignment_id: ASSIGNMENT_ID },
      operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
      idempotency_key: 'client-key-1',
      device_sequence: 0,
      device_id: 'device-1',
      site_id: 'site-1',
      organisation_id: 'org-1',
      offline_operation_id: OP_ID,
      schema_version: 2,
    });
    expect(fingerprintOfflineSemanticRequest(NAMESPACE, ordered)).toBe(fingerprintOfflineSemanticRequest(NAMESPACE, reordered));
  });

  it('ordered arrays remain ordered: reordering media_refs is a different request', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, sendOperation({ media_refs: ['media-a', 'media-b'] }));
    const b = fingerprintOfflineSemanticRequest(NAMESPACE, sendOperation({ media_refs: ['media-b', 'media-a'] }));
    expect(a).not.toBe(b);
  });

  it('recipient_user_ids is a set: its normalisation is deterministic', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, sendOperation({ recipient_user_ids: ['user-3', 'user-2'] }));
    const b = fingerprintOfflineSemanticRequest(NAMESPACE, sendOperation({ recipient_user_ids: ['user-2', 'user-3'] }));
    expect(a).toBe(b);
  });

  it('the same sequence with a changed payload fingerprints differently', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation());
    const b = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation({ payload: { assignment_id: ASSIGNMENT_ID, expected_status: 'ACCEPTED' } }));
    expect(a).not.toBe(b);
  });

  it('created_at is semantic client telemetry: changing it changes the request, and no result field carries it as server time', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation());
    const b = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation({ created_at: '2026-08-18T10:00:01.000Z' }));
    expect(a).not.toBe(b);
    // The canonical request includes created_at; the RESULT contract's only
    // timestamp is the server's finalized_at — created_at never crosses over.
    expect(canonicaliseOfflineSemanticRequest(NAMESPACE, acceptOperation())).toContain('created_at');
    expect(Object.keys(OfflineOperationResultSchema.shape)).not.toContain('created_at');
    expect(Object.keys(OfflineOperationResultSchema.shape)).toContain('finalized_at');
  });

  it('the namespace binds the fingerprint: another device is another request', () => {
    const a = fingerprintOfflineSemanticRequest(NAMESPACE, acceptOperation());
    const b = fingerprintOfflineSemanticRequest({ ...NAMESPACE, device_id: 'device-2' }, acceptOperation());
    expect(a).not.toBe(b);
  });
});

describe('WP-20/C10-09 downstream idempotency key derivation', () => {
  it('matches the exact documented encoding', () => {
    const expected = `offline:${createHash('sha256')
      .update(['org-1', 'site-1', 'user-1', 'device-1', OP_ID, 'FIELD_ASSIGNMENT_ACCEPT'].join('\n'), 'utf8')
      .digest('hex')}`;
    expect(deriveOfflineDownstreamIdempotencyKey(NAMESPACE, OP_ID, 'FIELD_ASSIGNMENT_ACCEPT')).toBe(expected);
  });

  it('differs per namespace, operation id and kind', () => {
    const base = deriveOfflineDownstreamIdempotencyKey(NAMESPACE, OP_ID, 'FIELD_ASSIGNMENT_ACCEPT');
    expect(deriveOfflineDownstreamIdempotencyKey({ ...NAMESPACE, device_id: 'device-2' }, OP_ID, 'FIELD_ASSIGNMENT_ACCEPT')).not.toBe(base);
    expect(deriveOfflineDownstreamIdempotencyKey(NAMESPACE, MESSAGE_ID, 'FIELD_ASSIGNMENT_ACCEPT')).not.toBe(base);
    expect(deriveOfflineDownstreamIdempotencyKey(NAMESPACE, OP_ID, 'FIELD_ASSIGNMENT_COMPLETE')).not.toBe(base);
  });
});

describe('WP-20/C10-05 the allowlist is closed', () => {
  it('all six admitted kinds parse', () => {
    for (const kind of ['FIELD_ASSIGNMENT_ACCEPT', 'FIELD_ASSIGNMENT_DECLINE', 'FIELD_ASSIGNMENT_START', 'FIELD_ASSIGNMENT_COMPLETE'] as const) {
      expect(acceptOperation({ operation_kind: kind }).operation_kind).toBe(kind);
    }
    expect(sendOperation().operation_kind).toBe('INCIDENT_FIELD_MESSAGE_SEND');
    const acknowledge = acceptOperation({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', payload: { message_id: MESSAGE_ID } });
    expect(acknowledge.operation_kind).toBe('INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE');
  });

  it('every explicitly excluded kind fails to parse', () => {
    for (const forbidden of [
      'FIELD_STATE_UPDATE',
      'PATROL_RUN_START',
      'PATROL_CHECKPOINT_VERIFY',
      'PATROL_ROUTE_CREATE',
      'PATROL_ROUTE_PUBLISH',
      'PATROL_RUN_SCHEDULE',
      'PATROL_RUN_CANCEL',
      'PATROL_RUN_ABANDON_COMMAND',
      'FIELD_ASSIGNMENT_CREATE',
      'FIELD_ASSIGNMENT_CANCEL',
      'INCIDENT_FIELD_MESSAGE_OVERSIGHT_READ',
      'INCIDENT_CREATE',
      'INCIDENT_CLOSE',
      'WHISPER_SIGNAL',
      'EVIDENCE_UPLOAD',
      'CONSTITUTION_APPROVE',
    ]) {
      expect(() => acceptOperation({ operation_kind: forbidden })).toThrow();
    }
  });

  it('an unknown kind and a wrong payload for a known kind are both refused', () => {
    expect(() => acceptOperation({ operation_kind: 'SOMETHING_NEW' })).toThrow();
    expect(() => acceptOperation({ payload: { message_id: MESSAGE_ID } })).toThrow();
    expect(() => sendOperation({}, { payload: { assignment_id: ASSIGNMENT_ID, expected_status: 'REQUESTED' } })).toThrow();
  });
});

describe('WP-20/C10-05 message bounds stay at least as strict as WP-18', () => {
  it('enforces recipient, body, media and mutual-presence rules', () => {
    expect(() => sendOperation({ recipient_user_ids: Array.from({ length: 129 }, (_, index) => `user-${index}`) })).toThrow();
    expect(() => sendOperation({ recipient_user_ids: ['user-2', 'user-2'] })).toThrow();
    expect(() => sendOperation({ body: 'x'.repeat(MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES + 1) })).toThrow();
    expect(() => sendOperation({ media_refs: Array.from({ length: 65 }, (_, index) => `media-${index}`) })).toThrow();
    expect(() => sendOperation({ body: null, media_refs: [] })).toThrow();
    // The boundary case remains admissible.
    expect(sendOperation({ body: null, media_refs: ['media-a'] }).payload).toMatchObject({ body: null });
  });

  it('rejects a negative, fractional or unsafe device_sequence', () => {
    expect(() => acceptOperation({ device_sequence: -1 })).toThrow();
    expect(() => acceptOperation({ device_sequence: 1.5 })).toThrow();
    expect(() => acceptOperation({ device_sequence: Number.MAX_SAFE_INTEGER + 2 })).toThrow();
  });
});

describe('WP-20/C10-08 + C10-11 outcome contracts', () => {
  it('APPLIED and REJECTED advance the cursor; UNKNOWN never does', () => {
    expect(offlineReceiptAdvancesCursor('APPLIED')).toBe(true);
    expect(offlineReceiptAdvancesCursor('REJECTED')).toBe(true);
    expect(offlineReceiptAdvancesCursor('UNKNOWN')).toBe(false);
    expect(offlineReceiptAdvancesCursor('RECEIVED')).toBe(false);
    expect(offlineReceiptAdvancesCursor('APPLYING')).toBe(false);
  });

  it('results and conflicts parse with safe metadata only, and OPERATION_ID_REUSED is conflict-capable', () => {
    const result = OfflineOperationResultSchema.parse({
      schema_version: 2,
      offline_operation_id: OP_ID,
      device_sequence: 3,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_SEND',
      outcome: 'REJECTED',
      replayed: true,
      finalized_at: '2026-08-18T10:06:00.000Z',
      next_expected_sequence: 4,
      result_ref: null,
      result_snapshot: { conflict: 'DOMAIN_REJECTED' },
      trace_id: 'trace-3',
    });
    expect(result.replayed).toBe(true);

    const conflict = OfflineReplayConflictSchema.parse({
      schema_version: 2,
      conflict_code: 'OPERATION_ID_REUSED',
      offline_operation_id: OP_ID,
      device_sequence: 7,
      expected_sequence: 4,
      received_sequence: 7,
      trace_id: 'trace-7',
    });
    expect(conflict.conflict_code).toBe('OPERATION_ID_REUSED');
    expect(OfflineReplayConflictCodeSchema.options).toHaveLength(10);
    expect(() => OfflineReplayConflictSchema.parse({ ...conflict, message_body: 'leak' })).toThrow();
    expect(() =>
      OfflineOperationResultSchema.parse({ ...result, result_snapshot: { blob: 'x'.repeat(17_000) } }),
    ).toThrow();
  });
});

describe('WP-20/C10-01 legacy V1 stays parseable, unchanged and superseded', () => {
  it('schema_version 1 still parses exactly as before', () => {
    const legacy = FieldOfflineOperationSchema.parse({
      schema_version: 1,
      offline_operation_id: 'legacy-1',
      organisation_id: 'org-1',
      site_id: 'site-1',
      device_id: 'device-1',
      device_sequence: 9,
      idempotency_key: 'legacy-key',
      operation_kind: 'anything.goes.in.v1',
      payload: { free: 'form' },
      created_at: '2026-08-18T09:00:00.000Z',
      trace_id: 'trace-legacy',
    });
    expect(legacy.operation_kind).toBe('anything.goes.in.v1');
    // And V1's "newer" remains merely greater-than — the documented reason it
    // is not an executable replay contract.
    expect(isNewerOfflineOperation({ device_id: 'device-1', device_sequence: 3 }, { device_id: 'device-1', device_sequence: 9 })).toBe(true);
  });

  it('V2 refuses schema_version 1 and V1-style free-form kinds', () => {
    expect(() => acceptOperation({ schema_version: 1 })).toThrow();
  });
});
