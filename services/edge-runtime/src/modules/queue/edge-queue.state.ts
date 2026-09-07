import type { EdgeOperationState, EdgeTransportResult } from '@sentinel/contracts';

/**
 * ============================================================================
 * WP-29B / LANE B — THE LOCAL QUEUE STATES, AND HOW THEY MAP ONTO THE FROZEN
 * TWO.
 *
 * `EdgeOperationStateSchema` has exactly two members, QUEUED and TERMINAL, and
 * its comment explains at length why there is no FAILED, no EXPIRED and no
 * ABANDONED: each of those would be Edge making a judgement about work it did
 * not author and cannot evaluate, and each is a way for a box on a site LAN to
 * make an operation vanish without central ever learning it existed.
 *
 * NOTHING BELOW CONTRADICTS THAT, AND THE MAPPING IS THE PROOF.
 *
 * The nine states here are OPERATIONAL DETAIL INSIDE `QUEUED`, plus the two
 * ways central can end an entry. They answer an operator's question — "where is
 * this operation right now" — which the frozen pair deliberately does not, and
 * they answer it without acquiring the power to end anything:
 *
 *   LOCAL STATE          FROZEN    WHAT IT MEANS
 *   ------------------   --------  -------------------------------------------
 *   STORED_LOCAL         QUEUED    Durably written. Not yet offered to the
 *                                  forwarder — typically because the witness
 *                                  step has not run yet.
 *   READY_TO_FORWARD     QUEUED    Eligible. Its backoff, if any, has elapsed.
 *   FORWARDING           QUEUED    An attempt is in flight, or WAS in flight
 *                                  when this process died. See the recovery
 *                                  note below: this is the crash-critical one.
 *   CENTRAL_RECEIVED     QUEUED    Central said RECEIVED. It has the bytes. It
 *                                  has NOT said it applied them.
 *   CENTRAL_APPLYING     QUEUED    Central said APPLYING. Still not applied.
 *   CENTRAL_APPLIED      TERMINAL  Central said APPLIED, and named the record.
 *   FAILED_RETRYABLE     QUEUED    The last attempt provably did not reach
 *                                  central. A fact about the wire.
 *   FAILED_TERMINAL      TERMINAL  Central REFUSED, and named the refusal.
 *   UNKNOWN              QUEUED    The last attempt may or may not have reached
 *                                  central. Honest ignorance.
 *
 * THE TWO NAMES THAT LOOK LIKE VERDICTS AND ARE NOT
 * -------------------------------------------------
 * FAILED_RETRYABLE and UNKNOWN both map to QUEUED. The word "FAILED" in the
 * first is about THE ATTEMPT, never about the operation, and the mapping is
 * where that stops being a comment: an entry in either state is still queued,
 * is still forwarded, and is still holding a Field operative's work. There is
 * no arrangement of local states that produces TERMINAL without a central
 * answer, because TERMINAL is not a state this module can enter — it is a state
 * `settle()` derives FROM the answer it was handed.
 *
 * WHY CENTRAL_RECEIVED AND CENTRAL_APPLYING ARE STILL "QUEUED"
 * ------------------------------------------------------------
 * This is the rule the whole file exists for. WP-20's receipt lifecycle is
 * RECEIVED then APPLYING then APPLIED or REJECTED, and `OFFLINE_PROCESSING_LEASE_MS`
 * exists precisely because a receipt left in APPLYING by a process that died is
 * RECLAIMED and retried. So "central has it" and "central applied it" are
 * different facts, and an Edge that treated the first as the second would stop
 * forwarding an operation whose effect may never have committed — the entry
 * would sit locally marked done, central would never see it again, and the
 * operative's action would be gone with a green tick beside it.
 *
 * Only APPLIED and REJECTED are answers. Everything else is progress.
 * ============================================================================
 */
export const EDGE_QUEUE_STATES = [
  'STORED_LOCAL',
  'READY_TO_FORWARD',
  'FORWARDING',
  'CENTRAL_RECEIVED',
  'CENTRAL_APPLYING',
  'CENTRAL_APPLIED',
  'FAILED_RETRYABLE',
  'FAILED_TERMINAL',
  'UNKNOWN',
] as const;

export type EdgeQueueState = (typeof EDGE_QUEUE_STATES)[number];

/**
 * The two states central's answer produces, and the ONLY two that map to the
 * frozen TERMINAL.
 *
 * Named as data because the SQL schema needs the same list in a CHECK
 * constraint, and a second hand-typed list in the DDL is exactly how a database
 * ends up permitting a row the type system forbids.
 */
export const EDGE_QUEUE_SETTLED_STATES = ['CENTRAL_APPLIED', 'FAILED_TERMINAL'] as const;

/**
 * The states in which CENTRAL HAS SAID SOMETHING about the entry — progress or
 * an answer.
 *
 * Needed as its own list because it decides whether a row may carry a
 * `failure_category`. A wire failure is Edge's account of why it has no word
 * from central; once central HAS spoken, keeping a stale transport reason
 * beside its word is how an entry ends up described by whichever of the two a
 * reader looked at first.
 */
export const EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES = [
  'CENTRAL_RECEIVED',
  'CENTRAL_APPLYING',
  'CENTRAL_APPLIED',
  'FAILED_TERMINAL',
] as const;

/**
 * The states from which Edge may hand an entry to the transport.
 *
 * STORED_LOCAL is absent: it has not been witnessed yet, and forwarding it
 * would send an operation with no Edge provenance when provenance was about to
 * be attached. FORWARDING is absent: an attempt is already in flight, and a
 * second concurrent attempt for one envelope is the shape in which one act
 * becomes two requests.
 */
export const EDGE_QUEUE_FORWARDABLE_STATES = [
  'READY_TO_FORWARD',
  'FAILED_RETRYABLE',
  'UNKNOWN',
  'CENTRAL_RECEIVED',
  'CENTRAL_APPLYING',
] as const;

export type EdgeQueueCentralAcknowledgedState = (typeof EDGE_QUEUE_CENTRAL_ACKNOWLEDGED_STATES)[number];

export type EdgeQueueSettledState = (typeof EDGE_QUEUE_SETTLED_STATES)[number];

/** True when central has answered. Nothing else may make this true. */
export function isEdgeQueueSettledState(state: EdgeQueueState): state is EdgeQueueSettledState {
  return (EDGE_QUEUE_SETTLED_STATES as readonly EdgeQueueState[]).includes(state);
}

/**
 * The mapping onto the frozen contract. One line, one direction, no exceptions.
 *
 * Deriving it from `isEdgeQueueSettledState` rather than from a second table
 * means the frozen state and the settlement evidence can never be computed from
 * different rules — which is the shape in which a queue starts reporting
 * TERMINAL for an entry that carries no answer.
 */
export function toEdgeOperationState(state: EdgeQueueState): EdgeOperationState {
  return isEdgeQueueSettledState(state) ? 'TERMINAL' : 'QUEUED';
}

// ---------------------------------------------------------------------------
// Failure categories — every one of them a fact about the wire
// ---------------------------------------------------------------------------

/**
 * THE PERSISTED FAILURE CATEGORY IS THE FROZEN UNKNOWN REASON, AND NOTHING
 * ELSE.
 *
 * Derived from `EdgeTransportResult` by type extraction rather than written out
 * as a new enum, so this column's domain cannot grow a member the contract does
 * not have. That matters more than it sounds: a locally-invented category is
 * how a queue acquires a value like `REJECTED_LOCALLY` or `GAVE_UP`, and the
 * moment one exists somebody writes the branch that acts on it.
 *
 * Read the members and note what is absent: every one is a fact about the WIRE
 * — not attempted, could not connect, timed out, transport broke, answer
 * unreadable — and none is evidence about the operation. There is no value in
 * this column that means "this operation is bad".
 */
export type EdgeQueueFailureCategory = Extract<EdgeTransportResult, { outcome: 'UNKNOWN' }>['reason'];

/** The two transport answers that may end an entry. Both are central's. */
export type EdgeTransportTerminalAnswer = Extract<EdgeTransportResult, { terminal: true }>;

/**
 * REASON IN, STATE OUT — AND THE CALLER DOES NOT GET A VOTE.
 *
 * This is a `Record` over the full union, so adding a reason to the frozen
 * contract fails THIS file to compile rather than silently falling through to a
 * default. It is simultaneously the exhaustiveness proof and the mapping, which
 * is why it is one table and not two.
 *
 * THE LINE IT DRAWS, AND WHY THE CALLER MUST NOT BE ABLE TO MOVE IT:
 *
 *   CONNECT_FAILED           the connection never established, so central
 *                            CERTAINLY did not see the bytes. Retrying carries
 *                            no duplicate risk at all. FAILED_RETRYABLE.
 *
 *   TIMED_OUT                the bytes may already have been applied.
 *   TRANSPORT_ERROR          Same ambiguity. Retrying relies on WP-20 / C15-05
 *   RESPONSE_UNINTELLIGIBLE  replay identity converging the second submission
 *                            on the stored outcome. UNKNOWN, honestly.
 *
 *   NOT_ATTEMPTED            not a failure at all. Edge has not tried yet, so
 *                            the entry is simply eligible.
 *
 * Handing this decision to a transport author is how a timeout gets logged as a
 * clean failure: the retry then looks free, the operator's dashboard shows no
 * ambiguity, and a duplicate effect or a lost one is discovered by a customer.
 * The store therefore computes the state from the reason and offers no
 * parameter by which it can be overridden.
 */
export const EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY: Readonly<Record<EdgeQueueFailureCategory, EdgeQueueState>> = {
  NOT_ATTEMPTED: 'READY_TO_FORWARD',
  CONNECT_FAILED: 'FAILED_RETRYABLE',
  TIMED_OUT: 'UNKNOWN',
  TRANSPORT_ERROR: 'UNKNOWN',
  RESPONSE_UNINTELLIGIBLE: 'UNKNOWN',
};

/** Every failure category, for the SQL CHECK and for the tests. */
export const EDGE_QUEUE_FAILURE_CATEGORIES = Object.keys(
  EDGE_QUEUE_STATE_FOR_FAILURE_CATEGORY,
) as readonly EdgeQueueFailureCategory[];

/**
 * The category recorded for an entry that has just been admitted.
 *
 * Every row carries either central's answer or Edge's honest reason for not
 * having one — never both, never neither — and a freshly stored operation's
 * reason is that nobody has tried yet. The schema enforces the exclusive-or;
 * this constant is what makes a brand-new row satisfy it truthfully rather than
 * with a NULL that means nothing in particular.
 */
export const EDGE_QUEUE_INITIAL_FAILURE_CATEGORY: EdgeQueueFailureCategory = 'NOT_ATTEMPTED';

// ---------------------------------------------------------------------------
// The transition table
// ---------------------------------------------------------------------------

/**
 * WHAT MAY FOLLOW WHAT.
 *
 * Two properties are load-bearing, and both are visible by reading the table
 * rather than by trusting a comment:
 *
 * 1. THE TWO SETTLED STATES HAVE NO OUTGOING EDGES. Central's answer is final.
 *    An entry cannot be un-settled, re-queued or re-sent, so a settled row can
 *    never produce a second effect. (A database trigger enforces the same rule
 *    a level lower, against a writer that never comes through this table.)
 *
 * 2. NOTHING REACHES A SETTLED STATE WITHOUT PASSING THROUGH `FORWARDING`.
 *    STORED_LOCAL and READY_TO_FORWARD have exactly one successor each. That is
 *    not tidiness: a central answer is the response to a request, and an entry
 *    that has never been forwarded has never asked central anything. An edge
 *    from READY_TO_FORWARD straight to CENTRAL_APPLIED would be Edge recording
 *    a reply to a question it did not ask — which is precisely the local lie
 *    "no local state may falsely mean CENTRAL COMMITTED" is about.
 *
 * The re-entry into FORWARDING from CENTRAL_RECEIVED and CENTRAL_APPLYING is
 * deliberate and is not a duplicate submission in the harmful sense: it is how
 * Edge asks again about an operation central has acknowledged but not resolved,
 * and C15-05 replay identity converges it on the stored outcome.
 */
export const EDGE_QUEUE_TRANSITIONS: Readonly<Record<EdgeQueueState, readonly EdgeQueueState[]>> = {
  STORED_LOCAL: ['READY_TO_FORWARD'],
  READY_TO_FORWARD: ['FORWARDING'],
  FORWARDING: [
    'CENTRAL_RECEIVED',
    'CENTRAL_APPLYING',
    'CENTRAL_APPLIED',
    'FAILED_TERMINAL',
    'FAILED_RETRYABLE',
    'UNKNOWN',
    // The forwarder handed the entry back untried — no route, not its turn.
    // NOT_ATTEMPTED is the honest reason, and it is not a failure.
    'READY_TO_FORWARD',
  ],
  CENTRAL_RECEIVED: ['FORWARDING', 'CENTRAL_APPLYING', 'CENTRAL_APPLIED', 'FAILED_TERMINAL', 'UNKNOWN'],
  CENTRAL_APPLYING: ['FORWARDING', 'CENTRAL_APPLIED', 'FAILED_TERMINAL', 'UNKNOWN'],
  FAILED_RETRYABLE: ['READY_TO_FORWARD', 'FORWARDING'],
  UNKNOWN: ['READY_TO_FORWARD', 'FORWARDING'],
  CENTRAL_APPLIED: [],
  FAILED_TERMINAL: [],
};

export function canTransitionEdgeQueueState(from: EdgeQueueState, to: EdgeQueueState): boolean {
  return EDGE_QUEUE_TRANSITIONS[from].includes(to);
}

/**
 * The state a crashed process can leave behind that is NOT safe to resume from
 * as it stands.
 *
 * Only FORWARDING qualifies, and it is the whole reason a recovery sweep
 * exists. An entry in FORWARDING means an attempt was in flight when the
 * process died, so central may have received it, may have applied it, or may
 * never have seen a byte — and that is the definition of UNKNOWN, not of
 * failure. Resuming it as READY_TO_FORWARD would erase the ambiguity from the
 * record; resuming it as FAILED anything would be Edge inventing a verdict out
 * of its own crash.
 */
export const EDGE_QUEUE_CRASH_INTERRUPTED_STATE: EdgeQueueState = 'FORWARDING';

/**
 * The reason a crash-interrupted attempt is filed under.
 *
 * `TRANSPORT_ERROR` — "transport-level failure mid-exchange, same ambiguity as
 * a timeout" — is the exact shape of a process that died with a request open.
 * It is not `CONNECT_FAILED`, which would claim central never saw the bytes,
 * and Edge cannot know that: the socket may have been established and the
 * request fully written a microsecond before the power went.
 */
export const EDGE_QUEUE_CRASH_RECOVERY_CATEGORY: EdgeQueueFailureCategory = 'TRANSPORT_ERROR';
