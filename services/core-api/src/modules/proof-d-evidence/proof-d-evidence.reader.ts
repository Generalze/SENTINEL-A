import { MAX_OFFLINE_DEVICE_SEQUENCE } from '@sentinel/contracts';
import {
  PROOF_D_EVIDENCE_SOURCES,
  PROOF_D_KNOWN_UNREAD_SOURCES,
  PROOF_D_PENDING_SOURCES,
  PROOF_D_SOURCE_SURVEY_PREFIXES,
  PROOF_D_STRUCTURAL_CONSTRAINTS,
} from './proof-d-evidence.constants';
import type {
  ProofDAssignmentObservation,
  ProofDCursorObservation,
  ProofDDeviceContextObservation,
  ProofDEdgeObservation,
  ProofDFieldAuditObservation,
  ProofDGatewayEventObservation,
  ProofDIdempotencyCountObservation,
  ProofDObservation,
  ProofDOperativeStateObservation,
  ProofDOutboxBacklogObservation,
  ProofDPolicyLeaseObservation,
  ProofDReadWindow,
  ProofDReceiptObservation,
  ProofDScope,
  ProofDSecurityEventObservation,
  ProofDStructuralConstraintObservation,
  ProofDTrustTransitionObservation,
} from './proof-d-evidence.types';

/**
 * WP-31 — THE READER.
 *
 * Turns a live database into a `ProofDObservation`. It makes no judgements and
 * builds no facts: every question about provenance, privacy labelling or
 * eligibility is the collector's, and keeping the two apart is what lets the
 * collector be tested without Postgres.
 *
 * EVERY QUERY IS A NAMED PROJECTION. Not one `SELECT *` appears below, and
 * that is a privacy control rather than a style preference. `field_assignments`
 * carries `need_to_know_summary`, `field_operative_current_states` carries
 * `location`, `field_audit_log` and `device_gateway_operation_events` carry
 * `payload`, and `incident_field_message_action_idempotency` carries
 * `recipient_user_id`. A star projection would pull every one of them into an
 * evidence artefact the day somebody added a column; a named projection
 * requires a deliberate edit, which is a reviewable diff.
 *
 * THE MESSAGE TABLES ARE NOT READ AT ALL. Neither `incident_field_messages`
 * nor `incident_field_message_recipients` appears here, and neither is on the
 * source allowlist. The single-effect guarantee for a message action is
 * evidenced by a COUNT against a known server-derived idempotency key — a
 * number that says whether one action produced one row, and says nothing about
 * who the message was for.
 *
 * NO WHISPER TABLE IS READ, EITHER. Proof D is about ordering and idempotency
 * under WAN loss. A per-device or per-user duress counter would be traffic
 * analysis on a duress channel, which is a safety defect and not merely a
 * privacy one, so the query set simply does not contain one.
 */

/**
 * The narrowest possible database seam: parameterised SQL in, rows out.
 *
 * Deliberately not the Prisma client itself. A reader that held a full client
 * could reach any table in the schema; this one can only run the statements
 * written in this file, and the adapter that supplies it lives in the CLI.
 */
export interface ProofDSqlClient {
  query(sql: string, params: readonly unknown[]): Promise<readonly unknown[]>;
}

function asRecord(row: unknown): Record<string, unknown> {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    throw new TypeError('expected a row object from the evidence query');
  }
  return row as Record<string, unknown>;
}

function text(row: Record<string, unknown>, column: string): string {
  const value = row[column];
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    return String(value);
  }
  throw new TypeError(`column ${column} was expected to be text`);
}

function nullableText(row: Record<string, unknown>, column: string): string | null {
  const value = row[column];
  return value === null || value === undefined ? null : text(row, column);
}

/**
 * Timestamps arrive as `Date` from the driver and as text from a cast, so both
 * are normalised to ISO-8601 here. A bundle full of driver-shaped values would
 * not survive being written to a file and read back by anything else.
 */
function timestamp(row: Record<string, unknown>, column: string): string {
  const value = row[column];
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return new Date(parsed).toISOString();
    }
  }
  throw new TypeError(`column ${column} was expected to be a timestamp`);
}

function nullableTimestamp(row: Record<string, unknown>, column: string): string | null {
  const value = row[column];
  return value === null || value === undefined ? null : timestamp(row, column);
}

function integer(row: Record<string, unknown>, column: string): number {
  const value = row[column];
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === 'bigint' || typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) {
      return parsed;
    }
  }
  throw new TypeError(`column ${column} was expected to be an integer`);
}

/**
 * `device_sequence` and `last_finalized_sequence` are BIGINT.
 *
 * The repository's rule applies here for the same reason it applies there: a
 * silent rounding would name a DIFFERENT queue position, and a bundle that
 * reported the wrong position would be evidence for a duplication story that
 * never happened. Every crossing is cast to text in SQL and range-asserted on
 * the way back.
 */
function sequence(row: Record<string, unknown>, column: string): number {
  const parsed = Number(text(row, column));
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_OFFLINE_DEVICE_SEQUENCE) {
    throw new RangeError(`column ${column} is outside the safe offline sequence range`);
  }
  return parsed;
}

function stringArray(row: Record<string, unknown>, column: string): readonly string[] {
  const value = row[column];
  if (!Array.isArray(value)) {
    throw new TypeError(`column ${column} was expected to be an array`);
  }
  return value.map((entry) => String(entry));
}

/**
 * Read everything the collector is allowed to know.
 *
 * One function rather than a class: there is no state to hold, nothing to
 * inject, and a Nest provider would imply this participates in the running
 * application. It does not. It is run once, from a gated script, against a
 * database that has already finished the run being evidenced.
 */
export async function readProofDObservation(
  sql: ProofDSqlClient,
  scope: ProofDScope,
  window: ProofDReadWindow,
  readAt: string,
): Promise<ProofDObservation> {
  const { organisation_id: org, site_id: site, device_id: device, actor_user_id: actor } = scope;

  // -------------------------------------------------------------------------
  // Which sources exist. Asked first, so every later answer can be qualified.
  // -------------------------------------------------------------------------
  const candidateTables = [
    ...PROOF_D_EVIDENCE_SOURCES.filter((source) => !source.includes('.') && source !== 'pg_indexes'),
    ...PROOF_D_PENDING_SOURCES.map((pending) => pending.table_name),
  ];
  const presentRows = await sql.query(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = ANY($1::text[])`,
    [candidateTables],
  );
  const presentSources = presentRows.map((row) => text(asRecord(row), 'table_name')).sort();

  const surveyRows = await sql.query(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name LIKE ANY($1::text[])`,
    [PROOF_D_SOURCE_SURVEY_PREFIXES.map((prefix) => `${prefix}%`)],
  );
  const known = new Set<string>([...candidateTables, ...PROOF_D_KNOWN_UNREAD_SOURCES]);
  const unrecognisedSources = surveyRows
    .map((row) => text(asRecord(row), 'table_name'))
    .filter((table) => !known.has(table))
    .sort();

  const indexRows = await sql.query(
    `SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = ANY($1::text[])`,
    [PROOF_D_STRUCTURAL_CONSTRAINTS.map((entry) => entry.index_name)],
  );
  const presentIndexes = new Set(indexRows.map((row) => text(asRecord(row), 'indexname')));
  const structuralConstraints: readonly ProofDStructuralConstraintObservation[] = PROOF_D_STRUCTURAL_CONSTRAINTS.map(
    (entry) => ({
      index_name: entry.index_name,
      table_name: entry.table_name,
      present: presentIndexes.has(entry.index_name),
    }),
  );

  // -------------------------------------------------------------------------
  // The offline replay executor's durable state.
  // -------------------------------------------------------------------------
  const receiptRows = await sql.query(
    `SELECT offline_operation_id,
            device_sequence::text AS device_sequence,
            operation_kind,
            request_fingerprint,
            downstream_idempotency_key,
            status,
            outcome,
            conflict_code,
            attempt_count,
            client_created_at,
            first_received_at,
            processing_claimed_at,
            finalized_at,
            first_trace_id,
            policy_lease_id,
            result_ref
       FROM field_offline_operation_receipts
      WHERE organisation_id = $1 AND site_id = $2 AND user_id = $3 AND device_id = $4
      ORDER BY device_sequence ASC`,
    [org, site, actor, device],
  );
  const receipts: readonly ProofDReceiptObservation[] = receiptRows.map((raw) => {
    const row = asRecord(raw);
    return {
      offline_operation_id: text(row, 'offline_operation_id'),
      device_sequence: sequence(row, 'device_sequence'),
      operation_kind: text(row, 'operation_kind'),
      request_fingerprint: text(row, 'request_fingerprint'),
      downstream_idempotency_key: text(row, 'downstream_idempotency_key'),
      status: text(row, 'status'),
      outcome: nullableText(row, 'outcome'),
      conflict_code: nullableText(row, 'conflict_code'),
      attempt_count: integer(row, 'attempt_count'),
      client_created_at: timestamp(row, 'client_created_at'),
      first_received_at: timestamp(row, 'first_received_at'),
      processing_claimed_at: nullableTimestamp(row, 'processing_claimed_at'),
      finalized_at: nullableTimestamp(row, 'finalized_at'),
      first_trace_id: text(row, 'first_trace_id'),
      policy_lease_id: nullableText(row, 'policy_lease_id'),
      result_ref: nullableText(row, 'result_ref'),
    };
  });

  const cursorRows = await sql.query(
    `SELECT last_finalized_sequence::text AS last_finalized_sequence, updated_at
       FROM field_offline_device_cursors
      WHERE organisation_id = $1 AND site_id = $2 AND user_id = $3 AND device_id = $4
      LIMIT 1`,
    [org, site, actor, device],
  );
  const cursorRow = cursorRows[0] === undefined ? null : asRecord(cursorRows[0]);
  const cursor: ProofDCursorObservation | null =
    cursorRow === null
      ? null
      : {
          last_finalized_sequence:
            cursorRow.last_finalized_sequence === null ? null : sequence(cursorRow, 'last_finalized_sequence'),
          updated_at: timestamp(cursorRow, 'updated_at'),
        };

  // -------------------------------------------------------------------------
  // The authenticated device boundary. `payload` is never selected.
  // -------------------------------------------------------------------------
  const gatewayRows = await sql.query(
    `SELECT event_type, outcome, refusal_reason, operation_kind, context_id, occurred_at, trace_id
       FROM device_gateway_operation_events
      WHERE organisation_id = $1 AND device_id = $2::uuid AND occurred_at >= $3::timestamptz AND occurred_at <= $4::timestamptz
      ORDER BY occurred_at ASC`,
    [org, device, window.from, window.to],
  );
  const gatewayEvents: readonly ProofDGatewayEventObservation[] = gatewayRows.map((raw) => {
    const row = asRecord(raw);
    return {
      event_type: text(row, 'event_type'),
      outcome: text(row, 'outcome'),
      refusal_reason: nullableText(row, 'refusal_reason'),
      operation_kind: nullableText(row, 'operation_kind'),
      authenticated_device_context_id: nullableText(row, 'context_id'),
      occurred_at: timestamp(row, 'occurred_at'),
      trace_id: text(row, 'trace_id'),
    };
  });

  const contextRows = await sql.query(
    `SELECT id, establishment_id, key_id, key_version, issued_at, expires_at, closed_at, close_reason, issuance_trace_id
       FROM authenticated_device_contexts
      WHERE organisation_id = $1 AND device_id = $2::uuid AND issued_at >= $3::timestamptz AND issued_at <= $4::timestamptz
      ORDER BY issued_at ASC`,
    [org, device, window.from, window.to],
  );
  const deviceContexts: readonly ProofDDeviceContextObservation[] = contextRows.map((raw) => {
    const row = asRecord(raw);
    return {
      authenticated_device_context_id: text(row, 'id'),
      establishment_id: text(row, 'establishment_id'),
      key_id: text(row, 'key_id'),
      key_version: integer(row, 'key_version'),
      issued_at: timestamp(row, 'issued_at'),
      expires_at: timestamp(row, 'expires_at'),
      closed_at: nullableTimestamp(row, 'closed_at'),
      close_reason: nullableText(row, 'close_reason'),
      issuance_trace_id: text(row, 'issuance_trace_id'),
    };
  });

  const leaseRows = await sql.query(
    `SELECT id, authority_basis_id, scope, issued_at, expires_at, revoked_at
       FROM device_policy_leases
      WHERE organisation_id = $1 AND device_id = $2::uuid AND site_id = $3 AND actor_user_id = $4
      ORDER BY issued_at ASC`,
    [org, device, site, actor],
  );
  const policyLeases: readonly ProofDPolicyLeaseObservation[] = leaseRows.map((raw) => {
    const row = asRecord(raw);
    return {
      policy_lease_id: text(row, 'id'),
      authority_basis_id: text(row, 'authority_basis_id'),
      scope: stringArray(row, 'scope'),
      issued_at: timestamp(row, 'issued_at'),
      expires_at: timestamp(row, 'expires_at'),
      revoked_at: nullableTimestamp(row, 'revoked_at'),
    };
  });

  const trustRows = await sql.query(
    `SELECT previous_trust, new_trust, reason, occurred_at, trace_id
       FROM device_trust_transitions
      WHERE organisation_id = $1 AND device_id = $2::uuid AND occurred_at >= $3::timestamptz AND occurred_at <= $4::timestamptz
      ORDER BY occurred_at ASC`,
    [org, device, window.from, window.to],
  );
  const trustTransitions: readonly ProofDTrustTransitionObservation[] = trustRows.map((raw) => {
    const row = asRecord(raw);
    return {
      previous_trust: text(row, 'previous_trust'),
      new_trust: text(row, 'new_trust'),
      reason: text(row, 'reason'),
      occurred_at: timestamp(row, 'occurred_at'),
      trace_id: text(row, 'trace_id'),
    };
  });

  const deviceSecurityRows = await sql.query(
    `SELECT event_type, occurred_at, trace_id
       FROM device_security_events
      WHERE organisation_id = $1 AND device_id = $2::uuid AND occurred_at >= $3::timestamptz AND occurred_at <= $4::timestamptz
      ORDER BY occurred_at ASC`,
    [org, device, window.from, window.to],
  );
  const deviceSecurityEvents: readonly ProofDSecurityEventObservation[] = deviceSecurityRows.map((raw) => {
    const row = asRecord(raw);
    return {
      event_type: text(row, 'event_type'),
      occurred_at: timestamp(row, 'occurred_at'),
      trace_id: text(row, 'trace_id'),
    };
  });

  // -------------------------------------------------------------------------
  // Edge identity and standing. This is ALL central can say about an Edge at
  // this commit: there is no session, receipt or queue table to read.
  // -------------------------------------------------------------------------
  const edgeRows = await sql.query(
    `SELECT id, enrolment_state, edge_trust, activated_at, withdrawn_at
       FROM edges
      WHERE organisation_id = $1 AND site_id = $2
      ORDER BY created_at ASC`,
    [org, site],
  );
  const edges: readonly ProofDEdgeObservation[] = edgeRows.map((raw) => {
    const row = asRecord(raw);
    return {
      edge_id: text(row, 'id'),
      enrolment_state: text(row, 'enrolment_state'),
      edge_trust: text(row, 'edge_trust'),
      activated_at: nullableTimestamp(row, 'activated_at'),
      withdrawn_at: nullableTimestamp(row, 'withdrawn_at'),
    };
  });

  const edgeSecurityRows = await sql.query(
    `SELECT event_type, occurred_at, trace_id
       FROM edge_security_events
      WHERE organisation_id = $1 AND occurred_at >= $2::timestamptz AND occurred_at <= $3::timestamptz
      ORDER BY occurred_at ASC`,
    [org, window.from, window.to],
  );
  const edgeSecurityEvents: readonly ProofDSecurityEventObservation[] = edgeSecurityRows.map((raw) => {
    const row = asRecord(raw);
    return {
      event_type: text(row, 'event_type'),
      occurred_at: timestamp(row, 'occurred_at'),
      trace_id: text(row, 'trace_id'),
    };
  });

  // -------------------------------------------------------------------------
  // The Field capability audit trail. Kind and time only; `payload` is not
  // selected, because an audit payload is read by oversight and does not
  // belong in an artefact that travels.
  // -------------------------------------------------------------------------
  const auditRows = await sql.query(
    `SELECT kind, at
       FROM field_audit_log
      WHERE organisation_id = $1 AND site_id = $2 AND at >= $3::timestamptz AND at <= $4::timestamptz
      ORDER BY at ASC`,
    [org, site, window.from, window.to],
  );
  const fieldAudit: readonly ProofDFieldAuditObservation[] = auditRows.map((raw) => {
    const row = asRecord(raw);
    return { kind: text(row, 'kind'), at: timestamp(row, 'at') };
  });

  // -------------------------------------------------------------------------
  // Fan-out recovery. Counts at organisation scope, never a per-recipient or
  // per-site breakdown.
  // -------------------------------------------------------------------------
  const outboxBacklogs: ProofDOutboxBacklogObservation[] = [];
  for (const table of ['field_outbox', 'incident_field_message_outbox', 'incident_update_outbox', 'events'] as const) {
    const rows = await sql.query(
      `SELECT count(*)::text AS unpublished_count, min(created_at) AS oldest_unpublished_created_at
         FROM ${table}
        WHERE published_at IS NULL AND organisation_id = $1`,
      [org],
    );
    const row = rows[0] === undefined ? null : asRecord(rows[0]);
    outboxBacklogs.push({
      table_name: table,
      unpublished_count: row === null ? 0 : integer(row, 'unpublished_count'),
      oldest_unpublished_created_at: row === null ? null : nullableTimestamp(row, 'oldest_unpublished_created_at'),
    });
  }

  // -------------------------------------------------------------------------
  // Domain-side single-effect evidence.
  // -------------------------------------------------------------------------
  const assignmentIds = [
    ...new Set(
      receipts
        .filter((receipt) => receipt.operation_kind.startsWith('FIELD_ASSIGNMENT_'))
        .map((receipt) => receipt.result_ref)
        .filter((ref): ref is string => ref !== null),
    ),
  ];
  const assignments: readonly ProofDAssignmentObservation[] =
    assignmentIds.length === 0
      ? []
      : (
          await sql.query(
            `SELECT id, status, delivery_state, updated_at
               FROM field_assignments
              WHERE organisation_id = $1 AND site_id = $2 AND id = ANY($3::uuid[])
              ORDER BY updated_at ASC`,
            [org, site, assignmentIds],
          )
        ).map((raw) => {
          const row = asRecord(raw);
          return {
            assignment_id: text(row, 'id'),
            status: text(row, 'status'),
            delivery_state: text(row, 'delivery_state'),
            updated_at: timestamp(row, 'updated_at'),
          };
        });

  const downstreamKeys = [...new Set(receipts.map((receipt) => receipt.downstream_idempotency_key))];

  /**
   * COUNT BY KEY, and nothing else leaves any of these three tables.
   *
   * Keys with no row are filled in at zero rather than dropped: "this key
   * produced no domain action" is a finding, and a missing entry would read as
   * a key nobody checked.
   */
  const countByKey = async (table: string, extraWhere: string, params: readonly unknown[]): Promise<readonly ProofDIdempotencyCountObservation[]> => {
    if (downstreamKeys.length === 0) {
      return [];
    }
    const rows = await sql.query(
      `SELECT idempotency_key, count(*)::text AS row_count
         FROM ${table}
        WHERE idempotency_key = ANY($1::text[])${extraWhere}
        GROUP BY idempotency_key`,
      [downstreamKeys, ...params],
    );
    const counted = new Map<string, number>();
    for (const raw of rows) {
      const row = asRecord(raw);
      counted.set(text(row, 'idempotency_key'), integer(row, 'row_count'));
    }
    return downstreamKeys.map((key) => ({ idempotency_key: key, row_count: counted.get(key) ?? 0 }));
  };

  const assignmentActionCounts = await countByKey('field_assignment_action_idempotency', '', []);
  const stateUpdateCounts = await countByKey(
    'field_state_update_idempotency',
    ' AND organisation_id = $2 AND site_id = $3 AND user_id = $4 AND device_id = $5',
    [org, site, actor, device],
  );
  const messageActionCounts = await countByKey('incident_field_message_action_idempotency', '', []);

  const operativeRows = await sql.query(
    `SELECT state, source_at, received_at, updated_at
       FROM field_operative_current_states
      WHERE organisation_id = $1 AND site_id = $2 AND user_id = $3
      LIMIT 1`,
    [org, site, actor],
  );
  const operativeRow = operativeRows[0] === undefined ? null : asRecord(operativeRows[0]);
  const operativeCurrentState: ProofDOperativeStateObservation | null =
    operativeRow === null
      ? null
      : {
          state: text(operativeRow, 'state'),
          source_at: timestamp(operativeRow, 'source_at'),
          received_at: timestamp(operativeRow, 'received_at'),
          updated_at: timestamp(operativeRow, 'updated_at'),
        };

  const historyRows = await sql.query(
    `SELECT count(*)::text AS history_count
       FROM field_operative_state_history
      WHERE organisation_id = $1 AND site_id = $2 AND user_id = $3
        AND created_at >= $4::timestamptz AND created_at <= $5::timestamptz`,
    [org, site, actor, window.from, window.to],
  );
  const historyRow = historyRows[0] === undefined ? null : asRecord(historyRows[0]);

  return {
    read_at: readAt,
    window,
    scope,
    present_sources: presentSources,
    unrecognised_sources: unrecognisedSources,
    structural_constraints: structuralConstraints,
    receipts,
    cursor,
    gateway_events: gatewayEvents,
    device_contexts: deviceContexts,
    policy_leases: policyLeases,
    trust_transitions: trustTransitions,
    device_security_events: deviceSecurityEvents,
    edges,
    edge_security_events: edgeSecurityEvents,
    field_audit: fieldAudit,
    outbox_backlogs: outboxBacklogs,
    assignments,
    assignment_action_counts: assignmentActionCounts,
    state_update_counts: stateUpdateCounts,
    message_action_counts: messageActionCounts,
    operative_current_state: operativeCurrentState,
    operative_state_history_count: historyRow === null ? 0 : integer(historyRow, 'history_count'),
  };
}
