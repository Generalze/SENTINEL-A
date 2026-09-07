import {
  PROOF_D_BUNDLE_KIND,
  PROOF_D_BUNDLE_SCHEMA_VERSION,
  PROOF_D_CLAIM,
  PROOF_D_CLAIM_STATEMENT,
  PROOF_D_EVIDENCE_SOURCES,
  PROOF_D_FINALIZED_STATUSES,
  PROOF_D_OUTBOX_SOURCES,
  PROOF_D_PENDING_SOURCES,
} from './proof-d-evidence.constants';
import {
  absent,
  absentFrom,
  attested,
  clientClaimed,
  derived,
  observed,
  observedFrom,
  ProofDEvidenceIntegrityError,
  scanBundleForForbiddenMaterial,
  sourceNotPresent,
  sourceNotReadable,
  withheld,
} from './proof-d-evidence.facts';
import type {
  EvidenceFact,
  ProofDBundle,
  ProofDBundleAcceptance,
  ProofDHarnessAttestation,
  ProofDObservation,
  ProofDOperationEvidence,
  ProofDReceiptObservation,
} from './proof-d-evidence.types';

/**
 * WP-31 — THE COLLECTOR.
 *
 * Pure shaping. It takes what the reader observed and what the harness
 * attested, and produces the bundle. It opens no connection, so its behaviour —
 * including every privacy exclusion — is testable without a database, which is
 * the only way a privacy guard actually gets exercised on every run.
 *
 * THE RULE THIS FILE FOLLOWS EVERYWHERE
 * -------------------------------------
 * If durable state can answer the question, the answer is OBSERVED and cites
 * the tables it came from. Only where the answer genuinely cannot be recovered
 * from the database does an attested value appear, and it is labelled as
 * attested. The two are never blended into one field, and wherever an attested
 * fact HAS a durable shadow — a lease that expired during the attested window,
 * a quiet interval in the audit trail — the shadow is emitted as its own
 * OBSERVED corroboration fact beside it rather than being folded in to make the
 * attestation look stronger than it is.
 */

const FINALIZED: ReadonlySet<string> = new Set(PROOF_D_FINALIZED_STATUSES);

function toMillis(iso: string | null): number | null {
  if (iso === null) {
    return null;
  }
  const parsed = Date.parse(iso);
  return Number.isNaN(parsed) ? null : parsed;
}

function withinWindow(iso: string | null, startMs: number | null, endMs: number | null): boolean {
  const at = toMillis(iso);
  if (at === null || startMs === null) {
    return false;
  }
  if (at < startMs) {
    return false;
  }
  return endMs === null ? true : at <= endMs;
}

/**
 * Labelled counts, as an ARRAY of pairs.
 *
 * Deliberately not an object keyed by the label. A histogram keyed by a
 * database value would let row content decide bundle KEY names, which is the
 * one position the privacy scanner polices — so a status or an audit kind
 * would be checked against the forbidden-field list as though somebody had
 * written it into the schema. The label belongs in a value, where it is data.
 */
function countLabels(values: readonly string[]): readonly (readonly [string, number])[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
}

function tallyStatus(values: readonly string[]): readonly { status: string; count: number }[] {
  return countLabels(values).map(([status, count]) => ({ status, count }));
}

function tallyKind(values: readonly string[]): readonly { kind: string; count: number }[] {
  return countLabels(values).map(([kind, count]) => ({ kind, count }));
}

function distinct(values: readonly string[]): number {
  return new Set(values).size;
}

/**
 * The per-operation row. Every timestamp is wrapped, and the two derived
 * durations inherit the weaker of their inputs — which is why
 * `offline_dwell_ms` comes out CLIENT_CLAIMED and `central_settlement_ms`
 * comes out OBSERVED even though both are subtractions.
 */
function shapeOperation(receipt: ProofDReceiptObservation): ProofDOperationEvidence {
  const clientCreatedAt = clientClaimed(
    'field_offline_operation_receipts',
    receipt.client_created_at,
    'C10-06: the device\'s claim of when it queued the operation. Telemetry, never server authority, and it cannot backdate a transition.',
  );
  const firstReceivedAt = observed('field_offline_operation_receipts', receipt.first_received_at);
  const finalizedAt =
    receipt.finalized_at === null
      ? absent<string>('field_offline_operation_receipts', 'the operation has not been finalized')
      : observed('field_offline_operation_receipts', receipt.finalized_at);

  return {
    offline_operation_id: receipt.offline_operation_id,
    device_sequence: receipt.device_sequence,
    operation_kind: receipt.operation_kind,
    request_fingerprint: receipt.request_fingerprint,
    downstream_idempotency_key: receipt.downstream_idempotency_key,
    status: receipt.status,
    outcome: receipt.outcome,
    conflict_code: receipt.conflict_code,
    attempt_count: receipt.attempt_count,
    first_trace_id: receipt.first_trace_id,
    policy_lease_id:
      receipt.policy_lease_id === null
        ? absent<string>(
            'field_offline_operation_receipts',
            'null is an ERA MARKER, not a quality flag (D29A-26 §21): this receipt predates WP-29A, when no lease mechanism existed. The offline-envelope path has no branch that writes null.',
          )
        : observed('field_offline_operation_receipts', receipt.policy_lease_id),
    result_ref:
      receipt.result_ref === null
        ? absent<string>('field_offline_operation_receipts', 'the operation produced no entity reference')
        : observed('field_offline_operation_receipts', receipt.result_ref),
    client_created_at: clientCreatedAt,
    first_received_at: firstReceivedAt,
    processing_claimed_at:
      receipt.processing_claimed_at === null
        ? absent<string>('field_offline_operation_receipts', 'no worker ever claimed this receipt')
        : observed('field_offline_operation_receipts', receipt.processing_claimed_at),
    finalized_at: finalizedAt,
    offline_dwell_ms: derived(
      clientCreatedAt,
      firstReceivedAt,
      'field_offline_operation_receipts',
      () => {
        const from = toMillis(receipt.client_created_at);
        const to = toMillis(receipt.first_received_at);
        return from === null || to === null ? null : to - from;
      },
      'How long the operation sat between the device claiming it queued the work and central first seeing it. One end is a device clock, so the whole figure inherits CLIENT_CLAIMED; it is an indication of dwell, not a measurement of it.',
    ),
    central_settlement_ms: derived(
      firstReceivedAt,
      finalizedAt,
      'field_offline_operation_receipts',
      () => {
        const from = toMillis(receipt.first_received_at);
        const to = toMillis(receipt.finalized_at);
        return from === null || to === null ? null : to - from;
      },
      'Both ends are the server clock: first receipt to finalization.',
    ),
  };
}

function shapeAcceptance(
  attestation: ProofDHarnessAttestation,
  observation: ProofDObservation,
  edgeReceiptSourcePresent: boolean,
): ProofDBundleAcceptance {
  const reasons: string[] = [];

  if (attestation.environment !== 'FIELD') {
    reasons.push(
      `the harness attested environment ${attestation.environment}; the locked definition requires central online, a real Field device connected and an Edge operational`,
    );
  }
  if (attestation.wan.severance_method === 'SIMULATED') {
    reasons.push(
      'the severance was SIMULATED; the locked definition requires an actual outage, not a mocked method call and not an offline flag',
    );
  }
  if (attestation.wan.restored_at === null) {
    reasons.push('the link had not been restored when this bundle was taken, so no reconnect half exists to assess');
  }
  if (attestation.edge === null || attestation.edge.remained_operational !== true) {
    reasons.push('no attestation that an Edge continued authorised critical local functions during the severance');
  }
  if (attestation.field_client === null || attestation.field_client.local_refusals.length === 0) {
    reasons.push(
      'no operation was attested as explicitly refused during the outage; the refusals matter as much as the successes, and a degraded client that quietly allows everything has stopped enforcing rather than survived',
    );
  }
  if (attestation.reconnect === null || attestation.reconnect.at === null) {
    reasons.push('no authenticated reconnect was attested');
  }
  if (!edgeReceiptSourcePresent) {
    reasons.push(
      'no Edge receipt source exists to prove Edge-side persistence; the durable Edge queue is owned by another work package and has not landed',
    );
  }
  if (observation.receipts.length === 0) {
    reasons.push('central holds no offline operation receipts for this namespace, so there is nothing to reconcile');
  }

  return {
    physical_acceptance_eligible: reasons.length === 0,
    reasons,
    claim: 'UNCLAIMED',
  };
}

/**
 * Build the bundle.
 *
 * `generatedAt` is injected rather than read from the clock so a bundle is
 * reproducible from its inputs — an evidence artefact that changes every time
 * you rebuild it is one nobody can check.
 */
export function collectProofDEvidence(
  observation: ProofDObservation,
  attestation: ProofDHarnessAttestation,
  generatedAt: string,
): ProofDBundle {
  assertScopesAgree(observation, attestation);

  const attestor = attestation.attested_by;
  const severedMs = toMillis(attestation.wan.severed_at);
  const restoredMs = toMillis(attestation.wan.restored_at);
  const presentSources = new Set(observation.present_sources);

  // -------------------------------------------------------------------------
  // 1. The outage window. Attested, with an observed corroboration beside it.
  // -------------------------------------------------------------------------
  const serverStamps: string[] = [
    ...observation.receipts.map((receipt) => receipt.first_received_at),
    ...observation.gateway_events.map((event) => event.occurred_at),
    ...observation.field_audit.map((entry) => entry.at),
    ...observation.device_security_events.map((event) => event.occurred_at),
  ]
    .map((stamp) => toMillis(stamp))
    .filter((stamp): stamp is number => stamp !== null)
    .map((stamp) => new Date(stamp).toISOString())
    .sort();

  const lastBefore =
    severedMs === null ? null : (serverStamps.filter((stamp) => Date.parse(stamp) < severedMs).pop() ?? null);
  const firstAfter =
    restoredMs === null ? null : (serverStamps.find((stamp) => Date.parse(stamp) >= restoredMs) ?? null);

  // -------------------------------------------------------------------------
  // 4/5. Admission, and the two kinds of refusal.
  // -------------------------------------------------------------------------
  const operations = observation.receipts.map(shapeOperation);
  const centralRefusals = observation.receipts
    .filter((receipt) => receipt.conflict_code !== null)
    .map((receipt) => ({
      offline_operation_id: receipt.offline_operation_id,
      conflict_code: receipt.conflict_code ?? '',
      device_sequence: receipt.device_sequence,
    }));
  const gatewayRefusals = observation.gateway_events
    .filter((event) => event.event_type === 'OPERATION_REFUSED' && event.refusal_reason !== null)
    .map((event) => ({
      refusal_reason: event.refusal_reason ?? '',
      occurred_at: event.occurred_at,
      trace_id: event.trace_id,
    }));

  const leaseCorroboration = observation.policy_leases.map((lease) => ({
    policy_lease_id: lease.policy_lease_id,
    expires_at: lease.expires_at,
    revoked_at: lease.revoked_at,
    expired_during_outage: withinWindow(lease.expires_at, severedMs, restoredMs),
  }));

  // -------------------------------------------------------------------------
  // 7. The first operation central saw.
  // -------------------------------------------------------------------------
  const orderedByReceipt = [...observation.receipts].sort(
    (left, right) => (toMillis(left.first_received_at) ?? 0) - (toMillis(right.first_received_at) ?? 0),
  );
  const firstReceipt = orderedByReceipt[0] ?? null;

  // -------------------------------------------------------------------------
  // 8/9. Convergence and conflict.
  // -------------------------------------------------------------------------
  const downstreamKeys = observation.receipts.map((receipt) => receipt.downstream_idempotency_key);
  const operationIds = observation.receipts.map((receipt) => receipt.offline_operation_id);
  const sequences = observation.receipts.map((receipt) => String(receipt.device_sequence));
  const retried = observation.receipts
    .filter((receipt) => receipt.attempt_count > 1)
    .map((receipt) => ({ offline_operation_id: receipt.offline_operation_id, attempt_count: receipt.attempt_count }));
  const convergedEvents = observation.gateway_events.filter(
    (event) => event.event_type === 'OPERATION_CONVERGED',
  ).length;

  const sequenceReused = [
    ...observation.receipts
      .filter((receipt) => receipt.conflict_code === 'SEQUENCE_REUSED')
      .map((receipt) => ({
        offline_operation_id: receipt.offline_operation_id,
        device_sequence: receipt.device_sequence,
      })),
  ];
  const otherConflicts = observation.receipts
    .filter((receipt) => receipt.conflict_code !== null && receipt.conflict_code !== 'SEQUENCE_REUSED')
    .map((receipt) => ({
      offline_operation_id: receipt.offline_operation_id,
      conflict_code: receipt.conflict_code ?? '',
    }));

  // -------------------------------------------------------------------------
  // 10-12. Final state.
  // -------------------------------------------------------------------------
  const finalizedReceipts = observation.receipts.filter((receipt) => FINALIZED.has(receipt.status));
  const unfinalized = observation.receipts
    .filter((receipt) => !FINALIZED.has(receipt.status))
    .map((receipt) => receipt.offline_operation_id);
  const maxFinalizedSequence = finalizedReceipts.reduce<number | null>(
    (highest, receipt) => (highest === null || receipt.device_sequence > highest ? receipt.device_sequence : highest),
    null,
  );
  const cursorAgrees = observation.cursor !== null && observation.cursor.last_finalized_sequence === maxFinalizedSequence;

  // -------------------------------------------------------------------------
  // 13. No duplicate operational action.
  // -------------------------------------------------------------------------
  const constraintPresent = (indexName: string): boolean =>
    observation.structural_constraints.some((entry) => entry.index_name === indexName && entry.present);
  const countsAreSingular = (
    counts: readonly { idempotency_key: string; row_count: number }[],
  ): { holds: boolean; detail: string } => {
    const offenders = counts.filter((entry) => entry.row_count > 1);
    return {
      holds: offenders.length === 0,
      detail:
        offenders.length === 0
          ? `${counts.length} downstream key(s) checked; none produced more than one domain action row`
          : `${offenders.length} downstream key(s) produced more than one domain action row`,
    };
  };

  const assignmentSingularity = countsAreSingular(observation.assignment_action_counts);
  const stateSingularity = countsAreSingular(observation.state_update_counts);
  const messageSingularity = countsAreSingular(observation.message_action_counts);

  const checks = [
    {
      check: 'One receipt per queue position in the authenticated namespace',
      basis:
        'Structural. Enforced by the unique index field_offline_receipt_sequence_key, verified present in pg_indexes; not counted by any service.',
      holds: constraintPresent('field_offline_receipt_sequence_key') && distinct(sequences) === sequences.length,
      detail: `${sequences.length} receipt(s) occupy ${distinct(sequences)} distinct queue position(s)`,
    },
    {
      check: 'One queue position per offline operation id',
      basis:
        'Structural. Enforced by the unique index field_offline_receipt_operation_key, so a service-bypassing writer cannot smuggle the same operation in twice.',
      holds: constraintPresent('field_offline_receipt_operation_key') && distinct(operationIds) === operationIds.length,
      detail: `${operationIds.length} receipt(s) carry ${distinct(operationIds)} distinct operation id(s)`,
    },
    {
      check: 'One server-derived downstream idempotency key per receipt',
      basis:
        'Derived from field_offline_operation_receipts. The key is server-derived (C10-09), so a retry converges the domain onto the first result instead of double-firing.',
      holds: distinct(downstreamKeys) === downstreamKeys.length,
      detail: `${downstreamKeys.length} receipt(s) carry ${distinct(downstreamKeys)} distinct downstream key(s)`,
    },
    {
      check: 'Each downstream key produced at most one assignment action',
      basis: 'Counted against field_assignment_action_idempotency by key. Counts only; no row content crosses.',
      holds: assignmentSingularity.holds,
      detail: assignmentSingularity.detail,
    },
    {
      check: 'Each downstream key produced at most one operative state update',
      basis: 'Counted against field_state_update_idempotency by key.',
      holds: stateSingularity.holds,
      detail: stateSingularity.detail,
    },
    {
      check: 'Each downstream key produced at most one message action',
      basis:
        'Counted against incident_field_message_action_idempotency by key. A COUNT ONLY: that table carries recipient_user_id, and the reader\'s return type has nowhere to put it.',
      holds: messageSingularity.holds,
      detail: messageSingularity.detail,
    },
    {
      check: 'The cursor stands exactly at the highest finalized queue position',
      basis: 'field_offline_device_cursors.last_finalized_sequence against the receipts that consumed a position.',
      holds: cursorAgrees,
      detail:
        observation.cursor === null
          ? 'no cursor row exists for this namespace'
          : `cursor at ${String(observation.cursor.last_finalized_sequence)}, highest finalized position ${String(maxFinalizedSequence)}`,
    },
    {
      check: 'No operation is left in flight',
      basis:
        'Receipt status. An UNKNOWN outcome never advances the cursor (C10-08); it is retried into convergence, so a residue here is unfinished business rather than a duplicate.',
      holds: unfinalized.length === 0,
      detail: `${unfinalized.length} receipt(s) are not finalized`,
    },
  ];

  const bundleWithoutIntegrity: Omit<ProofDBundle, 'integrity'> = {
    bundle_schema_version: PROOF_D_BUNDLE_SCHEMA_VERSION,
    bundle_kind: PROOF_D_BUNDLE_KIND,
    generated_at: generatedAt,
    run_id: attestation.run_id,
    claim: { ...PROOF_D_CLAIM, statement: PROOF_D_CLAIM_STATEMENT },
    acceptance: shapeAcceptance(attestation, observation, presentSources.has('edge_operation_receipts')),
    scope: observation.scope,
    collection_window: observation.window,
    harness: {
      attested_by: attestor,
      attested_at: attestation.attested_at,
      environment: attestation.environment,
      notes: attestation.notes,
    },

    outage_window: {
      severed_at: attested(
        attestor,
        attestation.wan.severed_at,
        'Central cannot observe an interval it was absent for. This is the harness clock, not a server record.',
      ),
      restored_at: attested(
        attestor,
        attestation.wan.restored_at,
        attestation.wan.restored_at === null
          ? 'The link had not been restored when this bundle was taken.'
          : 'The harness clock. Central learns of restoration only by traffic arriving, which is a consequence rather than the event.',
      ),
      severance_method: attested(
        attestor,
        attestation.wan.severance_method,
        `How the link was cut, as attested: ${attestation.wan.note}`,
      ),
      central_observation_gap: observedFrom(
        [
          'field_offline_operation_receipts',
          'device_gateway_operation_events',
          'field_audit_log',
          'device_security_events',
        ],
        {
          last_event_before_attested_severance: lastBefore,
          first_event_after_attested_restore: firstAfter,
          gap_ms:
            lastBefore !== null && firstAfter !== null ? Date.parse(firstAfter) - Date.parse(lastBefore) : null,
        },
        'CORROBORATION ONLY. A quiet interval in central\'s own audit trail is consistent with an outage and does not establish one — an idle system is also quiet. It is emitted beside the attestation rather than folded into it.',
      ),
    },

    edge: {
      identity:
        observation.edges.length > 0
          ? observed('edges', observation.edges)
          : absent('edges', 'no Edge is enrolled at this site'),
      remained_operational:
        attestation.edge === null
          ? sourceNotPresent(
              'harness_attestation.edge',
              'The attestation carried no Edge section. Central cannot observe Edge liveness during a severance — it is the party that was cut off — so nothing answers this.',
            )
          : attested(
              attestor,
              attestation.edge.remained_operational,
              `Whether the Edge kept serving authorised local functions while central was unreachable. Only the Edge and the harness were present. ${attestation.edge.note}`,
            ),
      security_events:
        observation.edge_security_events.length > 0
          ? observed('edge_security_events', observation.edge_security_events)
          : absent('edge_security_events', 'the Edge raised no security events in this window'),
    },

    field_client: {
      device_id:
        observation.receipts.length > 0
          ? observed('field_offline_operation_receipts', observation.scope.device_id)
          : absent(
              'field_offline_operation_receipts',
              'no receipt names this device, so central never saw it queue anything',
            ),
      degraded_state_recognised_at:
        attestation.field_client === null
          ? sourceNotPresent(
              'harness_attestation.field_client',
              'The attestation carried no Field client section. A client recognising degradation is a client-side event during the cut; it reaches no server.',
            )
          : attested(
              attestor,
              attestation.field_client.degraded_state_recognised_at,
              'When the client recognised it was degraded. This happens while the link is down and produces no central row.',
            ),
      queued_offline_operation_ids:
        attestation.field_client === null
          ? sourceNotPresent(
              'harness_attestation.field_client',
              'The attestation carried no Field client section, so what the local queue held during the cut is unstated.',
            )
          : attested(
              attestor,
              attestation.field_client.queued_offline_operation_ids,
              'What the local queue held. Central sees only what was later submitted, so an operation queued and never sent would be invisible here without the attestation.',
            ),
      composed_during_attested_outage: clientClaimed(
        'field_offline_operation_receipts',
        observation.receipts
          .filter((receipt) => withinWindow(receipt.client_created_at, severedMs, restoredMs))
          .map((receipt) => receipt.offline_operation_id),
        'Receipts whose client_created_at falls inside the attested window. The membership test uses a device clock, so this is the device\'s account of what it composed while offline, durably kept — not central\'s observation of it.',
      ),
    },

    admission: {
      operations,
      admitted:
        observation.receipts.length > 0
          ? observed('field_offline_operation_receipts', operationIds)
          : absent(
              'field_offline_operation_receipts',
              'no operation was admitted; a receipt is what admission means, so there is nothing here',
            ),
      gateway_events:
        observation.gateway_events.length > 0
          ? observed('device_gateway_operation_events', observation.gateway_events)
          : absent('device_gateway_operation_events', 'the gateway recorded no events for this device in this window'),
    },

    refusal: {
      central_refusals:
        centralRefusals.length > 0
          ? observed('field_offline_operation_receipts', centralRefusals)
          : absent('field_offline_operation_receipts', 'no admitted operation was refused at central'),
      gateway_refusals:
        gatewayRefusals.length > 0
          ? observed('device_gateway_operation_events', gatewayRefusals)
          : absent(
              'device_gateway_operation_events',
              'the gateway refused nothing in this window. The refusal_reason recorded there is deliberately richer than anything the caller was told.',
            ),
      device_local_refusals:
        attestation.field_client === null
          ? sourceNotPresent(
              'harness_attestation.field_client',
              'The locked definition requires operations explicitly refused because policy expired or authority was unavailable. Those refusals are taken ON THE DEVICE while the link is down and produce no central row at all, so without an attestation this half of Proof D is simply unevidenced.',
            )
          : attested(
              attestor,
              attestation.field_client.local_refusals.map((refusal) => ({
                offline_operation_id: refusal.offline_operation_id,
                reason: refusal.reason,
                at: refusal.at,
              })),
              'Refusals taken by the client during the outage. Unobservable centrally by construction; see lease_expiry_corroboration for the durable shadow of a policy-expiry refusal.',
            ),
      lease_expiry_corroboration:
        leaseCorroboration.length > 0
          ? observed('device_policy_leases', leaseCorroboration)
          : absent(
              'device_policy_leases',
              'no policy lease was issued to this device, so no lease can corroborate a policy-expiry refusal',
            ),
    },

    edge_persistence: {
      receipt: presentSources.has('edge_operation_receipts')
        ? sourceNotReadable(
            'edge_operation_receipts',
            'The Edge receipt source now EXISTS and this collector version has no reader for it. This field is unanswered, not empty; extend the reader rather than reading the silence as absence.',
          )
        : sourceNotPresent(
            'edge_operation_receipts',
            'No Edge receipt source exists at this commit. The durable Edge queue is owned by WP-29B/WP-30, so "which Edge receipt proves persistence" cannot be answered from central at all yet.',
          ),
    },

    reconnect: {
      attested_at:
        attestation.reconnect === null
          ? sourceNotPresent('harness_attestation.reconnect', 'The attestation carried no reconnect section.')
          : attested(
              attestor,
              attestation.reconnect.at,
              `When the link came back, per the harness. ${attestation.reconnect.note}`,
            ),
      authenticated_device_contexts:
        observation.device_contexts.length > 0
          ? observed('authenticated_device_contexts', observation.device_contexts)
          : absent(
              'authenticated_device_contexts',
              'no device context was established in this window. A context is a scope statement and not a credential; its presence is what makes the reconnecting device identifiable.',
            ),
      edge_identity: presentSources.has('edge_sessions')
        ? sourceNotReadable(
            'edge_sessions',
            'An Edge session source now exists and this collector version has no reader for it.',
          )
        : sourceNotPresent(
            'edge_sessions',
            'Central keeps no Edge session record at this commit, so "which authenticated Edge identity reconnected" has no durable answer. What IS observable is the Edge roster and standing at this site — see the edge.identity fact.',
          ),
    },

    first_central_receipt: {
      operation:
        firstReceipt === null
          ? absent(
              'field_offline_operation_receipts',
              'central received no operation from this device in this window',
            )
          : observed('field_offline_operation_receipts', {
              offline_operation_id: firstReceipt.offline_operation_id,
              device_sequence: firstReceipt.device_sequence,
              operation_kind: firstReceipt.operation_kind,
              first_received_at: firstReceipt.first_received_at,
              outcome: firstReceipt.outcome,
              conflict_code: firstReceipt.conflict_code,
              finalized_at: firstReceipt.finalized_at,
              first_trace_id: firstReceipt.first_trace_id,
            }),
    },

    duplicate_convergence: {
      structural_enforcement: observed('pg_indexes', observation.structural_constraints),
      retried_operations:
        retried.length > 0
          ? observed('field_offline_operation_receipts', retried)
          : absent('field_offline_operation_receipts', 'no operation needed more than one attempt'),
      converged_gateway_events: observed('device_gateway_operation_events', convergedEvents),
      distinct_downstream_keys: observed('field_offline_operation_receipts', {
        receipts: downstreamKeys.length,
        distinct_keys: distinct(downstreamKeys),
        equal: distinct(downstreamKeys) === downstreamKeys.length,
      }),
    },

    conflict_convergence: {
      sequence_reused:
        sequenceReused.length > 0
          ? observed('field_offline_operation_receipts', sequenceReused)
          : absentFrom(
              ['field_offline_operation_receipts', 'device_gateway_operation_events'],
              'No admitted operation was refused SEQUENCE_REUSED. Note that a changed request at an already-consumed position is refused in the classifying transaction and therefore leaves NO receipt; the refusal surfaces in the gateway refusal stream instead, which this bundle reports under refusal.gateway_refusals.',
            ),
      other_conflicts:
        otherConflicts.length > 0
          ? observed('field_offline_operation_receipts', otherConflicts)
          : absent('field_offline_operation_receipts', 'no other conflict code was recorded on a receipt'),
    },

    final_state: {
      cursor:
        observation.cursor === null
          ? absent(
              'field_offline_device_cursors',
              'no cursor row exists: the namespace is fresh and OFFLINE_SEQUENCE_START has not been consumed',
            )
          : observed('field_offline_device_cursors', observation.cursor),
      queue: observed('field_offline_operation_receipts', {
        total_receipts: observation.receipts.length,
        by_status: tallyStatus(observation.receipts.map((receipt) => receipt.status)),
        unfinalized,
        cursor_agrees_with_finalized_maximum: cursorAgrees,
      }),
      domain_assignments:
        observation.assignments.length > 0
          ? observed('field_assignments', observation.assignments)
          : absent('field_assignments', 'no assignment was touched by this run'),
      domain_operative_state:
        observation.operative_current_state === null
          ? absent('field_operative_current_states', 'this operative has no current state row at this site')
          : observed('field_operative_current_states', observation.operative_current_state),
      domain_message_state: withheld(
        'Message domain state is NOT collected. Reading incident_field_messages or incident_field_message_recipients — even to count — would let this artefact reconstruct the WP-18 protected recipient set, which is exactly the need-to-know boundary §62.1 exists to hold. The single-effect guarantee for a message action is evidenced instead by a count against a known server-derived idempotency key, which reveals nothing about who the message was for.',
      ),
    },

    no_duplicate_action: {
      checks,
      all_checks_hold: checks.every((entry) => entry.holds),
      limitation:
        'These checks establish that the durable state this run produced contains no duplicate operational action. They do not establish that the run was a real outage, they do not speak for any operation central never received, and they are not an acceptance. Proof D remains UNCLAIMED.',
    },

    fanout_recovery: {
      backlogs:
        observation.outbox_backlogs.length > 0
          ? observedFrom(
              [...PROOF_D_OUTBOX_SOURCES],
              observation.outbox_backlogs,
              'published_at IS NULL, counted at organisation scope. Each of the four tables is already indexed for this predicate, which is why fan-out recovery needs no new instrumentation. Counts only: incident_field_message_outbox routes per recipient, and a per-recipient breakdown of it would be the protected recipient set with extra steps.',
            )
          : absentFrom([...PROOF_D_OUTBOX_SOURCES], 'no outbox backlog was observed'),
    },

    audit_chain: {
      field_audit_kinds:
        observation.field_audit.length > 0
          ? observed('field_audit_log', tallyKind(observation.field_audit.map((entry) => entry.kind)))
          : absent('field_audit_log', 'the Field audit trail holds nothing for this scope in this window'),
      device_security_events:
        observation.device_security_events.length > 0
          ? observed('device_security_events', observation.device_security_events)
          : absent('device_security_events', 'no device security event was raised in this window'),
      trust_transitions:
        observation.trust_transitions.length > 0
          ? observed('device_trust_transitions', observation.trust_transitions)
          : absent('device_trust_transitions', 'this device\'s standing did not change in this window'),
      trace_ids: observedFrom(
        ['field_offline_operation_receipts', 'device_gateway_operation_events', 'authenticated_device_contexts'],
        [
          ...new Set([
            ...observation.receipts.map((receipt) => receipt.first_trace_id),
            ...observation.gateway_events.map((event) => event.trace_id),
            ...observation.device_contexts.map((context) => context.issuance_trace_id),
          ]),
        ].sort(),
        'trace_id joins the chain end to end. A legitimate retry may carry a fresh trace without changing the request, which is why the receipt retains the FIRST one.',
      ),
    },

    source_survey: {
      present: [...observation.present_sources].sort(),
      not_present: PROOF_D_PENDING_SOURCES.filter((pending) => !presentSources.has(pending.table_name)).map(
        (pending) => ({ table_name: pending.table_name, question: pending.question, owner: pending.owner }),
      ),
      unrecognised: [...observation.unrecognised_sources].sort(),
    },
  };

  /**
   * The scan runs over the bundle MINUS its own integrity block, then the
   * result becomes that block. The alternative — scanning a bundle that
   * contains a placeholder summary of the scan — would let the summary and the
   * thing summarised disagree, and the summary is the more convincing of the
   * two to a reader.
   */
  const scan = scanBundleForForbiddenMaterial(bundleWithoutIntegrity);

  return {
    ...bundleWithoutIntegrity,
    integrity: {
      fact_count_by_provenance: scan.fact_count_by_provenance,
      observed_source_allowlist: [...PROOF_D_EVIDENCE_SOURCES],
      privacy_scan: 'PASS',
      cited_sources: scan.cited_sources,
    },
  };
}

/**
 * The observation and the attestation must describe the SAME run.
 *
 * A bundle assembled from one device's receipts and another device's outage
 * would be internally coherent and completely wrong, and nothing downstream
 * could tell. The reader is driven by the attestation's scope, so a mismatch
 * means something between the two has been edited by hand.
 */
function assertScopesAgree(observation: ProofDObservation, attestation: ProofDHarnessAttestation): void {
  const mismatches: string[] = [];
  const pairs: readonly [string, string, string][] = [
    ['organisation_id', observation.scope.organisation_id, attestation.scope.organisation_id],
    ['site_id', observation.scope.site_id, attestation.scope.site_id],
    ['device_id', observation.scope.device_id, attestation.scope.device_id],
    ['actor_user_id', observation.scope.actor_user_id, attestation.scope.actor_user_id],
  ];
  for (const [field, observed_, attested_] of pairs) {
    if (observed_ !== attested_) {
      mismatches.push(`${field}: observed ${observed_}, attested ${attested_}`);
    }
  }
  if (mismatches.length > 0) {
    throw new ProofDEvidenceIntegrityError(
      `the observation and the attestation describe different runs (${mismatches.join('; ')})`,
    );
  }
}

export type { EvidenceFact };
