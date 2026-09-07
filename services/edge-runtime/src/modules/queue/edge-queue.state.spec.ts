import { describe, expect, it } from 'vitest';
import { EdgeOperationStateSchema } from '@sentinel/contracts';
import {
  EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES,
  EDGE_QUEUE_CRASH_INTERRUPTED_STATE,
  EDGE_QUEUE_CRASH_RECOVERY_CATEGORY,
  EDGE_QUEUE_FAILURE_CATEGORIES,
  EDGE_QUEUE_FORWARDABLE_STATES,
  EDGE_QUEUE_SETTLED_STATES,
  EDGE_QUEUE_STATES,
  EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY,
  EDGE_QUEUE_TRANSITIONS,
  canTransitionEdgeQueueState,
  toEdgeOperationState,
  type EdgeQueueState,
} from './edge-queue.state';

/**
 * The state model, proven against the FROZEN contract rather than against
 * itself.
 *
 * Every assertion below is about the same question: can any arrangement of
 * local states produce a claim that central committed, when central has not
 * said so? The store enforces the answer three more times — in its types, in
 * its transaction gate, and in SQL — but it starts here, in the pure model,
 * where it can be checked exhaustively.
 */
describe('edge queue state model', () => {
  it('maps every local state onto a member of the frozen two, and nothing else', () => {
    for (const state of EDGE_QUEUE_STATES) {
      expect(EdgeOperationStateSchema.safeParse(toEdgeOperationState(state)).success).toBe(true);
    }
  });

  it('maps exactly the two central answers to TERMINAL', () => {
    const terminal = EDGE_QUEUE_STATES.filter((state) => toEdgeOperationState(state) === 'TERMINAL');
    expect(terminal).toEqual([...EDGE_QUEUE_SETTLED_STATES]);
  });

  /**
   * The named trap. `FAILED_RETRYABLE` and `UNKNOWN` read like verdicts and are
   * not: the frozen contract has no FAILED state precisely because "Edge saw a
   * transport error" is a fact about the wire, not about the operation. An
   * entry in either state is still QUEUED and is still holding an operative's
   * work.
   */
  it('keeps both FAILED-sounding states QUEUED, because neither is a verdict about the operation', () => {
    expect(toEdgeOperationState('FAILED_RETRYABLE')).toBe('QUEUED');
    expect(toEdgeOperationState('UNKNOWN')).toBe('QUEUED');
  });

  /**
   * WP-20's lifecycle: `OFFLINE_PROCESSING_LEASE_MS` exists because an APPLYING
   * receipt left by a dead process is reclaimed and RETRIED. So central having
   * the bytes is not central having applied them, and an Edge that conflated the
   * two would stop chasing an operation whose effect never committed.
   */
  it('keeps CENTRAL_RECEIVED and CENTRAL_APPLYING QUEUED — central having it is not central applying it', () => {
    expect(toEdgeOperationState('CENTRAL_RECEIVED')).toBe('QUEUED');
    expect(toEdgeOperationState('CENTRAL_APPLYING')).toBe('QUEUED');
  });

  // -------------------------------------------------------------------------
  // No local path to a central-committed state
  // -------------------------------------------------------------------------

  it('lets nothing reach a settled state without first passing through FORWARDING', () => {
    for (const settled of EDGE_QUEUE_SETTLED_STATES) {
      const predecessors = EDGE_QUEUE_STATES.filter((from) => canTransitionEdgeQueueState(from, settled));
      // A central answer is the reply to a request. Every state that may
      // receive one is a state in which a request was actually made, or one in
      // which central has already spoken about this entry once.
      const mayReceiveAnAnswer: readonly EdgeQueueState[] = ['FORWARDING', ...EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES];
      for (const from of predecessors) expect(mayReceiveAnAnswer).toContain(from);
      expect(canTransitionEdgeQueueState('STORED_LOCAL', settled)).toBe(false);
      expect(canTransitionEdgeQueueState('READY_TO_FORWARD', settled)).toBe(false);
      expect(canTransitionEdgeQueueState('FAILED_RETRYABLE', settled)).toBe(false);
      expect(canTransitionEdgeQueueState('UNKNOWN', settled)).toBe(false);
    }
  });

  it('makes a settled entry a sink — central has answered and there is nowhere else to go', () => {
    for (const settled of EDGE_QUEUE_SETTLED_STATES) {
      expect(EDGE_QUEUE_TRANSITIONS[settled]).toEqual([]);
    }
  });

  it('gives STORED_LOCAL and READY_TO_FORWARD exactly one successor each', () => {
    expect(EDGE_QUEUE_TRANSITIONS.STORED_LOCAL).toEqual(['READY_TO_FORWARD']);
    expect(EDGE_QUEUE_TRANSITIONS.READY_TO_FORWARD).toEqual(['FORWARDING']);
  });

  it('names only states the model knows, on both sides of every edge', () => {
    for (const [from, targets] of Object.entries(EDGE_QUEUE_TRANSITIONS)) {
      expect(EDGE_QUEUE_STATES).toContain(from as EdgeQueueState);
      for (const to of targets) expect(EDGE_QUEUE_STATES).toContain(to);
    }
  });

  // -------------------------------------------------------------------------
  // Failure categories
  // -------------------------------------------------------------------------

  /**
   * The category list is derived from the frozen `EdgeTransportResult` by an
   * exhaustive `Record`, so a reason added to the contract fails the build. This
   * pins the values as well, so a reason REMOVED from the contract is equally
   * visible.
   */
  it('carries exactly the frozen transport-unknown reasons and nothing invented locally', () => {
    expect([...EDGE_QUEUE_FAILURE_CATEGORIES].sort()).toEqual(
      ['CONNECT_FAILED', 'NOT_ATTEMPTED', 'RESPONSE_UNINTELLIGIBLE', 'TIMED_OUT', 'TRANSPORT_ERROR'].sort(),
    );
  });

  it('files only the provably-unreached failure as retryable, and every ambiguous one as UNKNOWN', () => {
    expect(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY.CONNECT_FAILED).toBe('FAILED_RETRYABLE');
    // All three of these are shapes in which central MAY already have applied
    // the operation. Calling any of them a clean failure is how a queue produces
    // a duplicate effect or loses a real one.
    expect(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY.TIMED_OUT).toBe('UNKNOWN');
    expect(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY.TRANSPORT_ERROR).toBe('UNKNOWN');
    expect(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY.RESPONSE_UNINTELLIGIBLE).toBe('UNKNOWN');
  });

  it('never maps a wire fact to a settled state', () => {
    for (const category of EDGE_QUEUE_FAILURE_CATEGORIES) {
      expect(toEdgeOperationState(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY[category])).toBe('QUEUED');
    }
  });

  it('resumes a crash-interrupted attempt as UNKNOWN, never as a failure and never as ready', () => {
    expect(EDGE_QUEUE_CRASH_INTERRUPTED_STATE).toBe('FORWARDING');
    expect(EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY[EDGE_QUEUE_CRASH_RECOVERY_CATEGORY]).toBe('UNKNOWN');
  });

  it('never offers an unwitnessed or in-flight entry to the transport', () => {
    expect(EDGE_QUEUE_FORWARDABLE_STATES).not.toContain('STORED_LOCAL');
    expect(EDGE_QUEUE_FORWARDABLE_STATES).not.toContain('FORWARDING');
    for (const settled of EDGE_QUEUE_SETTLED_STATES) {
      expect(EDGE_QUEUE_FORWARDABLE_STATES).not.toContain(settled);
    }
  });
});
