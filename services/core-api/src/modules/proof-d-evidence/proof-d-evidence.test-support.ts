import { PROOF_D_STRUCTURAL_CONSTRAINTS } from './proof-d-evidence.constants';
import type { ProofDHarnessAttestation, ProofDObservation, ProofDScope } from './proof-d-evidence.types';

/**
 * WP-31 — fixtures for the collector's unit tests.
 *
 * A hand-built observation rather than a database fixture, deliberately. The
 * guarantees under test are SHAPING guarantees — that a device clock never
 * comes out labelled as a server observation, that a missing source is visibly
 * missing, that no forbidden field can reach the bundle — and every one of them
 * has to hold on every run, including runs where nobody has a Postgres to hand.
 * A privacy guard whose test needs infrastructure is a privacy guard that gets
 * skipped.
 */

export const FIXTURE_SCOPE: ProofDScope = {
  organisation_id: 'org-crucible',
  site_id: 'site-north',
  device_id: '11111111-1111-4111-8111-111111111111',
  actor_user_id: 'user-operative',
};

const SEVERED_AT = '2026-09-05T09:00:00.000Z';
const RESTORED_AT = '2026-09-05T10:00:00.000Z';

export function fixtureObservation(overrides: Partial<ProofDObservation> = {}): ProofDObservation {
  return {
    read_at: '2026-09-05T10:30:00.000Z',
    window: { from: '2026-09-05T08:00:00.000Z', to: '2026-09-05T11:00:00.000Z' },
    scope: FIXTURE_SCOPE,
    present_sources: [
      'authenticated_device_contexts',
      'device_gateway_operation_events',
      'device_policy_leases',
      'edges',
      'field_offline_device_cursors',
      'field_offline_operation_receipts',
    ],
    unrecognised_sources: [],
    structural_constraints: PROOF_D_STRUCTURAL_CONSTRAINTS.map((entry) => ({
      index_name: entry.index_name,
      table_name: entry.table_name,
      present: true,
    })),
    receipts: [
      {
        // Composed offline, retried once on reconnect, converged on one effect.
        offline_operation_id: 'aaaaaaaa-0000-4000-8000-000000000001',
        device_sequence: 0,
        operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
        request_fingerprint: 'f'.repeat(64),
        downstream_idempotency_key: 'offline:aaa1',
        status: 'APPLIED',
        outcome: 'APPLIED',
        conflict_code: null,
        attempt_count: 2,
        client_created_at: '2026-09-05T09:12:00.000Z',
        first_received_at: '2026-09-05T10:00:05.000Z',
        processing_claimed_at: '2026-09-05T10:00:05.500Z',
        finalized_at: '2026-09-05T10:00:06.000Z',
        first_trace_id: 'trace-offline-1',
        policy_lease_id: 'lease-1',
        result_ref: '22222222-2222-4222-8222-222222222222',
      },
      {
        // Admitted, then refused by the domain. A durable, replayable rejection.
        offline_operation_id: 'aaaaaaaa-0000-4000-8000-000000000002',
        device_sequence: 1,
        operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
        request_fingerprint: 'e'.repeat(64),
        downstream_idempotency_key: 'offline:aaa2',
        status: 'REJECTED',
        outcome: 'REJECTED',
        conflict_code: 'DOMAIN_REJECTED',
        attempt_count: 1,
        client_created_at: '2026-09-05T09:30:00.000Z',
        first_received_at: '2026-09-05T10:00:07.000Z',
        processing_claimed_at: '2026-09-05T10:00:07.200Z',
        finalized_at: '2026-09-05T10:00:07.800Z',
        first_trace_id: 'trace-offline-2',
        policy_lease_id: 'lease-1',
        result_ref: null,
      },
      {
        // Still in flight. UNKNOWN never advances the cursor (C10-08).
        offline_operation_id: 'aaaaaaaa-0000-4000-8000-000000000003',
        device_sequence: 2,
        operation_kind: 'FIELD_ASSIGNMENT_COMPLETE',
        request_fingerprint: 'd'.repeat(64),
        downstream_idempotency_key: 'offline:aaa3',
        status: 'UNKNOWN',
        outcome: null,
        conflict_code: null,
        attempt_count: 1,
        client_created_at: '2026-09-05T09:45:00.000Z',
        first_received_at: '2026-09-05T10:00:09.000Z',
        processing_claimed_at: '2026-09-05T10:00:09.100Z',
        finalized_at: null,
        first_trace_id: 'trace-offline-3',
        policy_lease_id: null,
        result_ref: null,
      },
    ],
    cursor: { last_finalized_sequence: 1, updated_at: '2026-09-05T10:00:07.800Z' },
    gateway_events: [
      {
        event_type: 'OPERATION_COMMITTED',
        outcome: 'COMMITTED',
        refusal_reason: null,
        operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
        authenticated_device_context_id: '33333333-3333-4333-8333-333333333333',
        occurred_at: '2026-09-05T10:00:06.000Z',
        trace_id: 'trace-gateway-1',
      },
      {
        event_type: 'OPERATION_CONVERGED',
        outcome: 'CONVERGED',
        refusal_reason: null,
        operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
        authenticated_device_context_id: '33333333-3333-4333-8333-333333333333',
        occurred_at: '2026-09-05T10:00:06.500Z',
        trace_id: 'trace-gateway-2',
      },
      {
        event_type: 'OPERATION_REFUSED',
        outcome: 'REFUSED',
        refusal_reason: 'OFFLINE_SEQUENCE_REUSED',
        operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
        authenticated_device_context_id: '33333333-3333-4333-8333-333333333333',
        occurred_at: '2026-09-05T10:00:08.000Z',
        trace_id: 'trace-gateway-3',
      },
    ],
    device_contexts: [
      {
        authenticated_device_context_id: '33333333-3333-4333-8333-333333333333',
        establishment_id: '44444444-4444-4444-8444-444444444444',
        key_id: 'key-alpha',
        key_version: 3,
        issued_at: '2026-09-05T10:00:01.000Z',
        expires_at: '2026-09-05T10:05:01.000Z',
        closed_at: null,
        close_reason: null,
        issuance_trace_id: 'trace-context-1',
      },
    ],
    policy_leases: [
      {
        policy_lease_id: 'lease-1',
        authority_basis_id: 'grant-field-act',
        scope: ['FIELD_ASSIGNMENT_ACCEPT', 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'],
        issued_at: '2026-09-05T08:30:00.000Z',
        // Expires mid-outage: the durable shadow of a device-local refusal.
        expires_at: '2026-09-05T09:40:00.000Z',
        revoked_at: null,
      },
    ],
    trust_transitions: [],
    device_security_events: [
      { event_type: 'POSSESSION_VERIFIED', occurred_at: '2026-09-05T10:00:00.500Z', trace_id: 'trace-sec-1' },
    ],
    edges: [
      {
        edge_id: '55555555-5555-4555-8555-555555555555',
        enrolment_state: 'ACTIVE',
        edge_trust: 'TRUSTED',
        activated_at: '2026-09-01T00:00:00.000Z',
        withdrawn_at: null,
      },
    ],
    edge_security_events: [],
    field_audit: [
      { kind: 'OFFLINE_OPERATION_RECEIVED', at: '2026-09-05T10:00:05.000Z' },
      { kind: 'OFFLINE_OPERATION_FINALIZED', at: '2026-09-05T10:00:06.000Z' },
      { kind: 'OFFLINE_OPERATION_RECEIVED', at: '2026-09-05T10:00:07.000Z' },
    ],
    outbox_backlogs: [
      { table_name: 'field_outbox', unpublished_count: 0, oldest_unpublished_created_at: null },
      { table_name: 'incident_field_message_outbox', unpublished_count: 0, oldest_unpublished_created_at: null },
      { table_name: 'incident_update_outbox', unpublished_count: 0, oldest_unpublished_created_at: null },
      { table_name: 'events', unpublished_count: 0, oldest_unpublished_created_at: null },
    ],
    assignments: [
      {
        assignment_id: '22222222-2222-4222-8222-222222222222',
        status: 'ACCEPTED',
        delivery_state: 'DELIVERED',
        updated_at: '2026-09-05T10:00:06.000Z',
      },
    ],
    assignment_action_counts: [
      { idempotency_key: 'offline:aaa1', row_count: 1 },
      { idempotency_key: 'offline:aaa2', row_count: 0 },
      { idempotency_key: 'offline:aaa3', row_count: 0 },
    ],
    state_update_counts: [
      { idempotency_key: 'offline:aaa1', row_count: 0 },
      { idempotency_key: 'offline:aaa2', row_count: 0 },
      { idempotency_key: 'offline:aaa3', row_count: 0 },
    ],
    message_action_counts: [
      { idempotency_key: 'offline:aaa1', row_count: 0 },
      { idempotency_key: 'offline:aaa2', row_count: 1 },
      { idempotency_key: 'offline:aaa3', row_count: 0 },
    ],
    operative_current_state: {
      state: 'ON_TASK',
      source_at: '2026-09-05T09:55:00.000Z',
      received_at: '2026-09-05T10:00:04.000Z',
      updated_at: '2026-09-05T10:00:04.000Z',
    },
    operative_state_history_count: 2,
    ...overrides,
  };
}

export function fixtureAttestation(overrides: Partial<ProofDHarnessAttestation> = {}): ProofDHarnessAttestation {
  return {
    attestation_schema_version: 1,
    run_id: 'proof-d-dry-run-001',
    attested_by: 'WP-30 outage harness v0 (operator: duty engineer)',
    attested_at: '2026-09-05T10:29:00.000Z',
    environment: 'SIMULATED',
    scope: FIXTURE_SCOPE,
    wan: {
      severed_at: SEVERED_AT,
      restored_at: RESTORED_AT,
      severance_method: 'SIMULATED',
      note: 'Egress to central blocked at the harness network namespace.',
    },
    edge: {
      edge_id: '55555555-5555-4555-8555-555555555555',
      remained_operational: true,
      note: 'Edge continued to serve authorised local functions throughout.',
    },
    field_client: {
      degraded_state_recognised_at: '2026-09-05T09:00:20.000Z',
      queued_offline_operation_ids: [
        'aaaaaaaa-0000-4000-8000-000000000001',
        'aaaaaaaa-0000-4000-8000-000000000002',
        'aaaaaaaa-0000-4000-8000-000000000003',
      ],
      local_refusals: [
        {
          offline_operation_id: 'aaaaaaaa-0000-4000-8000-000000000004',
          reason: 'POLICY_LEASE_EXPIRED',
          at: '2026-09-05T09:41:00.000Z',
          note: 'The cached policy lease expired mid-outage and the client refused to queue further work under it.',
        },
      ],
      note: 'Client recognised degradation twenty seconds after the cut.',
    },
    reconnect: { at: '2026-09-05T10:00:01.000Z', note: 'Link restored; device re-established a context immediately.' },
    notes: ['Dry run of the collector against a simulated severance. Not an acceptance run.'],
    ...overrides,
  };
}
