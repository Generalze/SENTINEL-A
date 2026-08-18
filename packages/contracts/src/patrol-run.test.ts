import { describe, expect, it } from 'vitest';
import {
  ALLOWED_PATROL_RUN_TRANSITIONS,
  canCompletePatrolRun,
  canTransitionPatrolRunStatus,
  canVerifySequence,
  CheckpointVerificationSchema,
  isCheckpointMissed,
  materialiseCheckpointWindow,
  PatrolCheckpointSchema,
  PatrolRunCheckpointSchema,
  PatrolRunSchema,
  resolveAbandonedCheckpointState,
  resolveCheckpointTiming,
  type PatrolRunCheckpoint,
} from './field.js';

const T = (iso: string): string => iso;
const START = '2026-08-18T10:00:00.000Z';
const OPENS = '2026-08-18T10:02:00.000Z';
const LATE = '2026-08-18T10:05:00.000Z';
const MISSED = '2026-08-18T10:15:00.000Z';

function window_(overrides: Partial<PatrolRunCheckpoint> = {}): PatrolRunCheckpoint {
  return {
    schema_version: 1,
    patrol_run_checkpoint_id: 'rc-1',
    patrol_run_id: 'run-1',
    patrol_checkpoint_id: 'cp-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    sequence_number: 1,
    window_opens_at: OPENS,
    late_after: LATE,
    missed_after: MISSED,
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
    patrol_run_id: 'run-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    patrol_route_id: 'route-1',
    route_version: 3,
    assigned_operative_user_id: 'user-1',
    incident_id: null,
    status: 'SCHEDULED',
    scheduled_start_at: START,
    started_at: null,
    ended_at: null,
    created_by_user_id: 'commander-1',
    trace_id: 'trace-1',
    ...overrides,
  };
}

function checkpointPolicy(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    patrol_checkpoint_id: 'cp-1',
    patrol_route_id: 'route-1',
    route_version: 3,
    organisation_id: 'org-1',
    site_id: 'site-1',
    sequence_number: 1,
    name: 'North gate',
    zone_id: null,
    location: null,
    window_open_offset_ms: 120_000,
    late_after_offset_ms: 300_000,
    missed_after_offset_ms: 900_000,
    trace_id: 'trace-1',
    ...overrides,
  };
}

describe('WP-19/C9-04 route-version timing policy', () => {
  it('carries the standard on the versioned checkpoint definition', () => {
    expect(PatrolCheckpointSchema.parse(checkpointPolicy())).toMatchObject({ route_version: 3, late_after_offset_ms: 300_000 });
  });

  it('rejects an incoherent offset ordering', () => {
    expect(() => PatrolCheckpointSchema.parse(checkpointPolicy({ late_after_offset_ms: 60_000 }))).toThrow();
    expect(() => PatrolCheckpointSchema.parse(checkpointPolicy({ missed_after_offset_ms: 100_000 }))).toThrow();
  });

  it('materialises absolute instants from the run actual start, not the planned one', () => {
    const materialised = materialiseCheckpointWindow(new Date(START), {
      window_open_offset_ms: 120_000,
      late_after_offset_ms: 300_000,
      missed_after_offset_ms: 900_000,
    });
    expect(materialised).toEqual({ window_opens_at: OPENS, late_after: LATE, missed_after: MISSED });

    // A patrol that starts an hour late gets a correspondingly shifted window.
    const lateStart = materialiseCheckpointWindow(new Date('2026-08-18T11:00:00.000Z'), {
      window_open_offset_ms: 120_000,
      late_after_offset_ms: 300_000,
      missed_after_offset_ms: 900_000,
    });
    expect(lateStart.late_after).toBe('2026-08-18T11:05:00.000Z');
  });
});

describe('WP-19/C9-01 verification is bound to its execution', () => {
  const verification = {
    schema_version: 1,
    checkpoint_verification_id: 'v-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    patrol_run_id: 'run-1',
    patrol_run_checkpoint_id: 'rc-1',
    patrol_route_id: 'route-1',
    patrol_checkpoint_id: 'cp-1',
    operative_user_id: 'user-1',
    device_id: 'device-1',
    verification_method: 'manual',
    verification_context: {},
    source_at: T('2026-08-18T10:03:00.000Z'),
    recorded_at: T('2026-08-18T10:03:01.000Z'),
    idempotency_key: 'idem-1',
    trace_id: 'trace-1',
  };

  it('requires the run and run-checkpoint identity', () => {
    expect(CheckpointVerificationSchema.parse(verification)).toMatchObject({ patrol_run_id: 'run-1', patrol_run_checkpoint_id: 'rc-1' });
    for (const bindingField of ['patrol_run_id', 'patrol_run_checkpoint_id'] as const) {
      const unbound: Record<string, unknown> = { ...verification };
      delete unbound[bindingField];
      expect(() => CheckpointVerificationSchema.parse(unbound)).toThrow();
    }
  });

  it('does not let a skewed device clock veto a valid server receipt', () => {
    // source_at far in the future of recorded_at is telemetry, not a violation.
    expect(
      CheckpointVerificationSchema.parse({ ...verification, source_at: T('2026-08-18T10:08:00.000Z') }),
    ).toMatchObject({ recorded_at: '2026-08-18T10:03:01.000Z' });
  });
});

describe('WP-19/C9-02 timing outcomes', () => {
  const w = window_();

  it('treats an early arrival as TOO_EARLY rather than compliance', () => {
    // Without this a patrol could be "completed" the moment it started.
    expect(resolveCheckpointTiming(new Date(START), w)).toBe('TOO_EARLY');
    expect(resolveCheckpointTiming(new Date('2026-08-18T10:01:59.999Z'), w)).toBe('TOO_EARLY');
  });

  it('classifies the window boundaries inclusively on the permissive side', () => {
    expect(resolveCheckpointTiming(new Date(OPENS), w)).toBe('VERIFIED');
    expect(resolveCheckpointTiming(new Date(LATE), w)).toBe('VERIFIED');
    expect(resolveCheckpointTiming(new Date('2026-08-18T10:05:00.001Z'), w)).toBe('LATE');
    expect(resolveCheckpointTiming(new Date(MISSED), w)).toBe('LATE');
    expect(resolveCheckpointTiming(new Date('2026-08-18T10:15:00.001Z'), w)).toBe('EXPIRED');
  });
});

describe('WP-19/C9-02 checkpoint state coherence', () => {
  it('requires resolution evidence exactly when the state is resolved', () => {
    expect(PatrolRunCheckpointSchema.parse(window_())).toMatchObject({ state: 'PENDING' });

    // Resolved states must say when and by which verification.
    expect(() => PatrolRunCheckpointSchema.parse(window_({ state: 'VERIFIED' }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(window_({ state: 'LATE', resolved_at: LATE }))).toThrow();

    // Unresolved states must carry neither — including the previously-allowed
    // combinations of a MISSED resolution time or a PENDING verification id.
    expect(() => PatrolRunCheckpointSchema.parse(window_({ state: 'MISSED', resolved_at: MISSED }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(window_({ checkpoint_verification_id: 'v-1' }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(window_({ state: 'CANCELLED', checkpoint_verification_id: 'v-1' }))).toThrow();
  });

  it('refuses a state that contradicts its own resolution time', () => {
    // The row would otherwise assert two different histories at once.
    expect(() =>
      PatrolRunCheckpointSchema.parse(window_({ state: 'VERIFIED', resolved_at: '2026-08-18T10:10:00.000Z', checkpoint_verification_id: 'v-1' })),
    ).toThrow();
    expect(() =>
      PatrolRunCheckpointSchema.parse(window_({ state: 'LATE', resolved_at: OPENS, checkpoint_verification_id: 'v-1' })),
    ).toThrow();

    expect(
      PatrolRunCheckpointSchema.parse(window_({ state: 'VERIFIED', resolved_at: OPENS, checkpoint_verification_id: 'v-1' })),
    ).toMatchObject({ state: 'VERIFIED' });
    expect(
      PatrolRunCheckpointSchema.parse(window_({ state: 'LATE', resolved_at: '2026-08-18T10:10:00.000Z', checkpoint_verification_id: 'v-1' })),
    ).toMatchObject({ state: 'LATE' });
  });

  it('rejects an incoherent materialised window', () => {
    expect(() => PatrolRunCheckpointSchema.parse(window_({ late_after: '2026-08-18T10:01:00.000Z' }))).toThrow();
    expect(() => PatrolRunCheckpointSchema.parse(window_({ missed_after: '2026-08-18T10:03:00.000Z' }))).toThrow();
  });
});

describe('WP-19/C9-03 run lifecycle', () => {
  it('permits only the defined terminations and has no unspecified EXPIRED state', () => {
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'IN_PROGRESS')).toBe(true);
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'CANCELLED')).toBe(true);
    expect(canTransitionPatrolRunStatus('IN_PROGRESS', 'COMPLETED')).toBe(true);
    expect(canTransitionPatrolRunStatus('IN_PROGRESS', 'ABANDONED')).toBe(true);
    // A run cannot be cancelled once walking, nor abandoned before it starts.
    expect(canTransitionPatrolRunStatus('IN_PROGRESS', 'CANCELLED')).toBe(false);
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'ABANDONED')).toBe(false);
    expect(canTransitionPatrolRunStatus('SCHEDULED', 'COMPLETED')).toBe(false);
    for (const terminal of ['COMPLETED', 'ABANDONED', 'CANCELLED'] as const) {
      expect(ALLOWED_PATROL_RUN_TRANSITIONS[terminal]).toEqual([]);
    }
    expect(Object.keys(ALLOWED_PATROL_RUN_TRANSITIONS)).not.toContain('EXPIRED');
  });

  it('ties started_at and ended_at to the states that actually have them', () => {
    expect(() => PatrolRunSchema.parse(run({ status: 'IN_PROGRESS' }))).toThrow();
    expect(() => PatrolRunSchema.parse(run({ status: 'SCHEDULED', started_at: START }))).toThrow();
    expect(() => PatrolRunSchema.parse(run({ status: 'IN_PROGRESS', started_at: START, ended_at: MISSED }))).toThrow();
    expect(() => PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: START }))).toThrow();
    expect(() => PatrolRunSchema.parse(run({ status: 'CANCELLED' }))).toThrow();
    expect(() =>
      PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: '2026-08-18T11:00:00.000Z', ended_at: START })),
    ).toThrow();

    expect(PatrolRunSchema.parse(run({ status: 'IN_PROGRESS', started_at: START }))).toMatchObject({ status: 'IN_PROGRESS' });
    expect(PatrolRunSchema.parse(run({ status: 'COMPLETED', started_at: START, ended_at: MISSED }))).toMatchObject({ status: 'COMPLETED' });
    // Cancelled before starting: an end, but never a start.
    expect(PatrolRunSchema.parse(run({ status: 'CANCELLED', ended_at: START }))).toMatchObject({ status: 'CANCELLED' });
  });

  it('completes only when nothing is still outstanding', () => {
    expect(canCompletePatrolRun(['VERIFIED', 'LATE', 'MISSED'])).toBe(true);
    expect(canCompletePatrolRun(['VERIFIED', 'PENDING'])).toBe(false);
    expect(canCompletePatrolRun([])).toBe(true);
  });

  it('abandonment cannot launder an already-overdue checkpoint', () => {
    const now = new Date('2026-08-18T10:20:00.000Z');
    // Past its deadline -> MISSED, not quietly withdrawn.
    expect(resolveAbandonedCheckpointState(now, { state: 'PENDING', missed_after: MISSED })).toBe('MISSED');
    // Still in the future -> the expectation is withdrawn.
    expect(resolveAbandonedCheckpointState(now, { state: 'PENDING', missed_after: '2026-08-18T11:00:00.000Z' })).toBe('CANCELLED');
    // Already resolved -> untouched.
    expect(resolveAbandonedCheckpointState(now, { state: 'VERIFIED', missed_after: MISSED })).toBeNull();
  });
});

describe('WP-19 missed determination and ordering', () => {
  it('marks missed only from the deadline and only while pending', () => {
    expect(isCheckpointMissed(new Date('2026-08-18T10:14:59.999Z'), window_())).toBe(false);
    expect(isCheckpointMissed(new Date('2026-08-18T10:15:00.001Z'), window_())).toBe(true);
    for (const state of ['VERIFIED', 'LATE', 'MISSED', 'CANCELLED'] as const) {
      expect(isCheckpointMissed(new Date('2026-08-18T10:15:00.001Z'), { state, missed_after: MISSED })).toBe(false);
    }
  });

  it('never lets one checkpoint decide another', () => {
    // Reads only its own window and state, so a verified later checkpoint
    // cannot imply an earlier one was missed.
    const earlier = window_({ sequence_number: 1, missed_after: '2026-08-18T10:30:00.000Z' });
    const now = new Date('2026-08-18T10:20:00.000Z');
    expect(isCheckpointMissed(now, earlier)).toBe(false);
    expect(resolveCheckpointTiming(now, earlier)).toBe('LATE');
  });

  it('enforces server-authoritative ordering on verification', () => {
    const siblings = [
      { sequence_number: 1, state: 'PENDING' as const },
      { sequence_number: 2, state: 'PENDING' as const },
      { sequence_number: 3, state: 'PENDING' as const },
    ];
    // Cannot skip ahead while an earlier checkpoint is still outstanding.
    expect(canVerifySequence(2, siblings)).toBe(false);
    expect(canVerifySequence(1, siblings)).toBe(true);

    // Any resolved earlier state permits progression — including MISSED, so a
    // missed checkpoint does not strand the rest of the patrol.
    for (const resolved of ['VERIFIED', 'LATE', 'MISSED', 'CANCELLED'] as const) {
      expect(canVerifySequence(2, [{ sequence_number: 1, state: resolved }, { sequence_number: 2, state: 'PENDING' }])).toBe(true);
    }
  });
});
