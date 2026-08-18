import { describe, expect, it } from 'vitest';
import {
  ALLOWED_PATROL_RUN_TRANSITIONS,
  canTransitionPatrolRunStatus,
  isCheckpointMissed,
  PatrolRunCheckpointSchema,
  PatrolRunSchema,
  resolveCheckpointState,
  type PatrolRunCheckpoint,
} from './field.js';

const RUN_ID = 'run-1';
const T0 = '2026-08-18T10:00:00.000Z';

function expectation(overrides: Partial<PatrolRunCheckpoint> = {}): PatrolRunCheckpoint {
  return {
    schema_version: 1,
    patrol_run_checkpoint_id: 'rc-1',
    patrol_run_id: RUN_ID,
    patrol_checkpoint_id: 'cp-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    sequence_number: 1,
    expected_at: T0,
    late_after: '2026-08-18T10:05:00.000Z',
    missed_after: '2026-08-18T10:15:00.000Z',
    state: 'PENDING',
    resolved_at: null,
    checkpoint_verification_id: null,
    trace_id: 'trace-1',
    ...overrides,
  } as PatrolRunCheckpoint;
}

function run(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    patrol_run_id: RUN_ID,
    organisation_id: 'org-1',
    site_id: 'site-1',
    patrol_route_id: 'route-1',
    route_version: 3,
    assigned_operative_user_id: 'user-1',
    incident_id: null,
    status: 'SCHEDULED',
    scheduled_start_at: T0,
    started_at: null,
    completed_at: null,
    created_by_user_id: 'commander-1',
    trace_id: 'trace-1',
    ...overrides,
  };
}

describe('WP-19 patrol run contract', () => {
  it('accepts a scheduled run and rejects unknown fields', () => {
    expect(PatrolRunSchema.parse(run())).toMatchObject({ status: 'SCHEDULED', route_version: 3 });
    expect(() => PatrolRunSchema.parse({ ...(run() as object), surprise: true })).toThrow();
  });

  it('requires server-owned timestamps to match the lifecycle', () => {
    // A run cannot claim to be running or finished without a start.
    expect(() => PatrolRunSchema.parse(run({ status: 'IN_PROGRESS' }))).toThrow();
    expect(() => PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: T0 }))).toThrow();
    // ...nor claim a start before it has begun.
    expect(() => PatrolRunSchema.parse(run({ status: 'SCHEDULED', started_at: T0 }))).toThrow();
    // Completion cannot precede the start.
    expect(() =>
      PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: '2026-08-18T11:00:00.000Z', completed_at: T0 })),
    ).toThrow();

    expect(
      PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: T0, completed_at: '2026-08-18T11:00:00.000Z' })),
    ).toMatchObject({ status: 'COMPLETED' });
  });

  it('allows only forward lifecycle transitions and treats terminal states as terminal', () => {
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'IN_PROGRESS')).toBe(true);
    expect(canTransitionPatrolRunStatus('IN_PROGRESS', 'COMPLETED')).toBe(true);
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'COMPLETED')).toBe(false);
    expect(canTransitionPatrolRunStatus('COMPLETED', 'IN_PROGRESS')).toBe(false);
    for (const terminal of ['COMPLETED', 'ABANDONED', 'EXPIRED'] as const) {
      expect(ALLOWED_PATROL_RUN_TRANSITIONS[terminal]).toEqual([]);
    }
  });
});

describe('WP-19 checkpoint expectation contract', () => {
  it('requires a coherent timing window', () => {
    expect(PatrolRunCheckpointSchema.parse(expectation())).toMatchObject({ state: 'PENDING' });
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ late_after: '2026-08-18T09:59:00.000Z' }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ missed_after: '2026-08-18T10:01:00.000Z' }))).toThrow();
  });

  it('ties resolution evidence to resolved states', () => {
    // VERIFIED/LATE must say when, and by which verification.
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ state: 'VERIFIED' }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ state: 'LATE', resolved_at: T0 }))).toThrow();
    // PENDING must not carry a resolution, and MISSED must not cite a verification.
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ resolved_at: T0 }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(expectation({ state: 'MISSED', checkpoint_verification_id: 'v-1' }))).toThrow();

    expect(
      PatrolRunCheckpointSchema.parse(expectation({ state: 'VERIFIED', resolved_at: T0, checkpoint_verification_id: 'v-1' })),
    ).toMatchObject({ state: 'VERIFIED' });
    expect(PatrolRunCheckpointSchema.parse(expectation({ state: 'MISSED' }))).toMatchObject({ state: 'MISSED' });
  });
});

describe('WP-19 authoritative timing decision', () => {
  const window = expectation();

  it('classifies by server receipt time against the run own materialised window', () => {
    expect(resolveCheckpointState(new Date('2026-08-18T10:00:00.000Z'), window)).toBe('VERIFIED');
    // Boundaries are inclusive on the permissive side.
    expect(resolveCheckpointState(new Date('2026-08-18T10:05:00.000Z'), window)).toBe('VERIFIED');
    expect(resolveCheckpointState(new Date('2026-08-18T10:05:00.001Z'), window)).toBe('LATE');
    expect(resolveCheckpointState(new Date('2026-08-18T10:15:00.000Z'), window)).toBe('LATE');
    // Past the deadline it is no longer resolvable by verification at all.
    expect(resolveCheckpointState(new Date('2026-08-18T10:15:00.001Z'), window)).toBeNull();
  });

  it('marks missed only from the deadline and only while still pending', () => {
    const before = new Date('2026-08-18T10:14:59.999Z');
    const after = new Date('2026-08-18T10:15:00.001Z');
    expect(isCheckpointMissed(before, window)).toBe(false);
    expect(isCheckpointMissed(after, window)).toBe(true);

    // An already-resolved checkpoint can never become missed retroactively.
    for (const state of ['VERIFIED', 'LATE', 'MISSED'] as const) {
      expect(isCheckpointMissed(after, { state, missed_after: window.missed_after })).toBe(false);
    }
  });

  it('does not let one checkpoint decide another', () => {
    // The rule takes only this checkpoint's own window and state, so a later
    // checkpoint being verified cannot imply an earlier one was missed.
    const earlier = expectation({ sequence_number: 1, missed_after: '2026-08-18T10:30:00.000Z' });
    const now = new Date('2026-08-18T10:20:00.000Z');
    expect(isCheckpointMissed(now, earlier)).toBe(false);
    expect(resolveCheckpointState(now, earlier)).toBe('LATE');
  });
});
