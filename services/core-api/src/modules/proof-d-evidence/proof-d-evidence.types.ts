import { z } from 'zod';
import {
  PROOF_D_BUNDLE_KIND,
  PROOF_D_BUNDLE_SCHEMA_VERSION,
  PROOF_D_HARNESS_ENVIRONMENTS,
  PROOF_D_SEVERANCE_METHODS,
  type EvidenceProvenance,
  type ProofDEvidenceSource,
} from './proof-d-evidence.constants';

/**
 * WP-31 — the bundle's shape, the reader's shape, and the harness attestation.
 *
 * THE READER AND THE COLLECTOR ARE SEPARATE ON PURPOSE. The collector shapes a
 * `ProofDObservation` plus a `ProofDHarnessAttestation` into a bundle and
 * touches no database; the reader turns a database into a `ProofDObservation`
 * and makes no judgements. That seam is what lets the shaping and the privacy
 * exclusions be unit-tested without a live Postgres — which matters, because
 * "the privacy guard is asserted by a test that needs a database and therefore
 * usually does not run" is not a guard.
 */

// ---------------------------------------------------------------------------
// The fact envelope
// ---------------------------------------------------------------------------

/**
 * ONE FACT, WITH ITS PROVENANCE ATTACHED.
 *
 * There is no unwrapped value anywhere in a bundle. That is deliberate and it
 * is the single most important shape in this module: the failure mode Proof D
 * evidence has is not a wrong number, it is a number whose origin has been
 * forgotten, so that something the harness said becomes something the server
 * saw. A reader of the bundle can always ask "who says so?" and get an answer.
 */
export interface EvidenceFact<T> {
  provenance: EvidenceProvenance;
  /** `null` for every provenance that has no value to report. */
  value: T | null;
  /**
   * The durable source. Constrained to `ProofDEvidenceSource` at every
   * construction site for OBSERVED / CLIENT_CLAIMED / ABSENT; widened to
   * `string` only so SOURCE_NOT_PRESENT can name a table that, by definition,
   * is not yet on the allowlist.
   */
  source: string | null;
  /** Who attested, for HARNESS_ATTESTED. Never set for an observed fact. */
  attested_by: string | null;
  /**
   * Why this fact is attested, absent, withheld or client-claimed rather than
   * observed. Mandatory for every provenance except OBSERVED, because those
   * are exactly the cases where a reader is owed an explanation.
   */
  note: string | null;
}

// ---------------------------------------------------------------------------
// What the reader observes
// ---------------------------------------------------------------------------

/** The authenticated replay namespace a Proof D run is scoped to. */
export interface ProofDScope {
  organisation_id: string;
  site_id: string;
  device_id: string;
  /**
   * The ACTING operative. Admissible, and not in tension with the recipient
   * rule: the actor is the subject of the run and already appears in
   * `field_audit_log.actor_user_id`. A RECIPIENT is a different person whose
   * relationship to a message is the protected fact, and no recipient
   * identifier enters this module at any point.
   */
  actor_user_id: string;
}

/** One offline operation receipt, projected. `result_snapshot` is not read. */
export interface ProofDReceiptObservation {
  offline_operation_id: string;
  device_sequence: number;
  operation_kind: string;
  request_fingerprint: string;
  /** Already a SHA-256 digest of a server-derived preimage; not a credential. */
  downstream_idempotency_key: string;
  status: string;
  outcome: string | null;
  conflict_code: string | null;
  attempt_count: number;
  /** C10-06: the device's CLAIM. Never server authority. */
  client_created_at: string;
  first_received_at: string;
  processing_claimed_at: string | null;
  finalized_at: string | null;
  first_trace_id: string;
  /** WP-29A era marker: null means the receipt predates policy leases. */
  policy_lease_id: string | null;
  result_ref: string | null;
}

export interface ProofDCursorObservation {
  last_finalized_sequence: number | null;
  updated_at: string;
}

export interface ProofDGatewayEventObservation {
  event_type: string;
  outcome: string;
  refusal_reason: string | null;
  operation_kind: string | null;
  authenticated_device_context_id: string | null;
  occurred_at: string;
  trace_id: string;
}

export interface ProofDDeviceContextObservation {
  authenticated_device_context_id: string;
  establishment_id: string;
  key_id: string;
  key_version: number;
  issued_at: string;
  expires_at: string;
  closed_at: string | null;
  close_reason: string | null;
  issuance_trace_id: string;
}

export interface ProofDPolicyLeaseObservation {
  policy_lease_id: string;
  authority_basis_id: string;
  scope: readonly string[];
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface ProofDTrustTransitionObservation {
  previous_trust: string;
  new_trust: string;
  reason: string;
  occurred_at: string;
  trace_id: string;
}

/** Event types and times only. `payload` is never read. */
export interface ProofDSecurityEventObservation {
  event_type: string;
  occurred_at: string;
  trace_id: string;
}

export interface ProofDEdgeObservation {
  edge_id: string;
  enrolment_state: string;
  edge_trust: string;
  activated_at: string | null;
  withdrawn_at: string | null;
}

/** Audit kinds and times only. `payload` is never read. */
export interface ProofDFieldAuditObservation {
  kind: string;
  at: string;
}

export interface ProofDOutboxBacklogObservation {
  table_name: string;
  unpublished_count: number;
  oldest_unpublished_created_at: string | null;
}

/** `need_to_know_summary` is not among these columns, and never will be. */
export interface ProofDAssignmentObservation {
  assignment_id: string;
  status: string;
  delivery_state: string;
  updated_at: string;
}

/**
 * A COUNT AGAINST A KNOWN KEY, and structurally nothing else.
 *
 * This is the shape that lets `incident_field_message_action_idempotency` be
 * read at all. A row of that table carries `recipient_user_id`; this type has
 * no field it could travel in, so the recipient set cannot be reconstructed
 * from anything the reader returns, whatever a future edit does to the query.
 */
export interface ProofDIdempotencyCountObservation {
  idempotency_key: string;
  row_count: number;
}

/** `location` is deliberately absent. Operative position is not a Proof D fact. */
export interface ProofDOperativeStateObservation {
  state: string;
  source_at: string;
  received_at: string;
  updated_at: string;
}

export interface ProofDStructuralConstraintObservation {
  index_name: string;
  table_name: string;
  present: boolean;
}

/**
 * The interval the reader swept.
 *
 * Supplied rather than guessed, and recorded in the bundle, because "no event
 * was observed" means nothing without knowing what was looked at. A reader that
 * chose its own window would let the size of the search decide the finding.
 */
export interface ProofDReadWindow {
  from: string;
  to: string;
}

/** Everything the collector is allowed to know about the database. */
export interface ProofDObservation {
  read_at: string;
  window: ProofDReadWindow;
  scope: ProofDScope;
  /** Tables from the allowlist and the pending list that actually exist. */
  present_sources: readonly string[];
  /**
   * Tables matching a survey prefix that this collector does not know how to
   * read. Reported so a lane landing a source under an unexpected name is
   * VISIBLE, rather than being indistinguishable from a source that does not
   * exist.
   */
  unrecognised_sources: readonly string[];
  structural_constraints: readonly ProofDStructuralConstraintObservation[];
  receipts: readonly ProofDReceiptObservation[];
  cursor: ProofDCursorObservation | null;
  gateway_events: readonly ProofDGatewayEventObservation[];
  device_contexts: readonly ProofDDeviceContextObservation[];
  policy_leases: readonly ProofDPolicyLeaseObservation[];
  trust_transitions: readonly ProofDTrustTransitionObservation[];
  device_security_events: readonly ProofDSecurityEventObservation[];
  edges: readonly ProofDEdgeObservation[];
  edge_security_events: readonly ProofDSecurityEventObservation[];
  field_audit: readonly ProofDFieldAuditObservation[];
  outbox_backlogs: readonly ProofDOutboxBacklogObservation[];
  assignments: readonly ProofDAssignmentObservation[];
  assignment_action_counts: readonly ProofDIdempotencyCountObservation[];
  state_update_counts: readonly ProofDIdempotencyCountObservation[];
  message_action_counts: readonly ProofDIdempotencyCountObservation[];
  operative_current_state: ProofDOperativeStateObservation | null;
  operative_state_history_count: number;
}

// ---------------------------------------------------------------------------
// What the harness attests
// ---------------------------------------------------------------------------

const isoTimestamp = z.string().datetime({ offset: true });

/**
 * THE HARNESS ATTESTATION.
 *
 * Everything in here is a fact central could NOT observe, and the schema is
 * deliberately narrow so that it stays that way. There is no free-form
 * `observations` object a future harness could use to inject something the
 * bundle would then present with more authority than it earned.
 *
 * `environment` is the field that decides whether the run is even the KIND of
 * run the locked definition speaks about. A SIMULATED severance is a perfectly
 * good engineering exercise and produces a perfectly good bundle; it is not,
 * and can never become, physical acceptance.
 */
export const ProofDHarnessAttestationSchema = z
  .object({
    attestation_schema_version: z.literal(1),
    run_id: z.string().min(1),
    /** The harness build and the human accountable for the attestation. */
    attested_by: z.string().min(1),
    attested_at: isoTimestamp,
    environment: z.enum(PROOF_D_HARNESS_ENVIRONMENTS),
    scope: z
      .object({
        organisation_id: z.string().min(1),
        site_id: z.string().min(1),
        device_id: z.string().min(1),
        actor_user_id: z.string().min(1),
      })
      .strict(),
    wan: z
      .object({
        /** When the link was cut. Central has no record of this by definition. */
        severed_at: isoTimestamp,
        /** `null` if the link had not been restored when the bundle was taken. */
        restored_at: isoTimestamp.nullable(),
        severance_method: z.enum(PROOF_D_SEVERANCE_METHODS),
        note: z.string().min(1),
      })
      .strict(),
    edge: z
      .object({
        edge_id: z.string().min(1).nullable(),
        /**
         * Whether the Edge kept serving authorised local functions while
         * central was unreachable. Central cannot know this; only the Edge and
         * the harness were there.
         */
        remained_operational: z.boolean().nullable(),
        note: z.string().min(1),
      })
      .strict()
      .nullable(),
    field_client: z
      .object({
        degraded_state_recognised_at: isoTimestamp.nullable(),
        queued_offline_operation_ids: z.array(z.string().min(1)).readonly(),
        /**
         * THE REFUSALS THAT NEVER REACHED CENTRAL.
         *
         * The locked definition requires operations to be explicitly refused
         * during the outage because policy expired or authority was
         * unavailable — and a refusal taken on the device while the link is
         * down produces no central row at all. These are attested, and the
         * bundle corroborates them against `device_policy_leases` expiry
         * without ever converting them into observations.
         */
        local_refusals: z
          .array(
            z
              .object({
                offline_operation_id: z.string().min(1).nullable(),
                reason: z.string().min(1),
                at: isoTimestamp.nullable(),
                note: z.string().min(1),
              })
              .strict(),
          )
          .readonly(),
        note: z.string().min(1),
      })
      .strict()
      .nullable(),
    reconnect: z
      .object({
        at: isoTimestamp.nullable(),
        note: z.string().min(1),
      })
      .strict()
      .nullable(),
    notes: z.array(z.string().min(1)).readonly(),
  })
  .strict();

export type ProofDHarnessAttestation = z.infer<typeof ProofDHarnessAttestationSchema>;

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/** One row of the per-operation table, every timestamp provenance-tagged. */
export interface ProofDOperationEvidence {
  offline_operation_id: string;
  device_sequence: number;
  operation_kind: string;
  request_fingerprint: string;
  downstream_idempotency_key: string;
  status: string;
  outcome: string | null;
  conflict_code: string | null;
  attempt_count: number;
  first_trace_id: string;
  policy_lease_id: EvidenceFact<string>;
  result_ref: EvidenceFact<string>;
  /** Device clock. Weaker than a server clock and labelled as such. */
  client_created_at: EvidenceFact<string>;
  first_received_at: EvidenceFact<string>;
  processing_claimed_at: EvidenceFact<string>;
  finalized_at: EvidenceFact<string>;
  /**
   * `first_received_at - client_created_at`. Carries the WEAKER of its two
   * inputs' provenances, because a derived value cannot be more trustworthy
   * than the least trustworthy thing it was derived from.
   */
  offline_dwell_ms: EvidenceFact<number>;
  /** `finalized_at - first_received_at`. Both ends are the server's clock. */
  central_settlement_ms: EvidenceFact<number>;
}

export interface ProofDBundleAcceptance {
  /**
   * Whether the run is of the KIND the locked definition speaks about. False
   * for every simulated severance, and false whenever a required real-world
   * element was absent.
   */
  physical_acceptance_eligible: boolean;
  reasons: readonly string[];
  /** Always UNCLAIMED. There is no writer for this field. */
  claim: 'UNCLAIMED';
}

export interface ProofDBundleIntegrity {
  fact_count_by_provenance: Readonly<Record<EvidenceProvenance, number>>;
  observed_source_allowlist: readonly ProofDEvidenceSource[];
  privacy_scan: 'PASS';
  /**
   * Sources this bundle cites as OBSERVED. A reader can diff this against the
   * allowlist to see exactly which durable state the run actually rested on.
   */
  cited_sources: readonly string[];
}

export interface ProofDBundle {
  bundle_schema_version: typeof PROOF_D_BUNDLE_SCHEMA_VERSION;
  bundle_kind: typeof PROOF_D_BUNDLE_KIND;
  generated_at: string;
  run_id: string;
  claim: {
    proof_c: string;
    proof_d: string;
    wp_26_physical_acceptance: string;
    wp_28: string;
    statement: string;
  };
  acceptance: ProofDBundleAcceptance;
  scope: ProofDScope;
  /** What the reader swept, so an ABSENT fact can be read against its search. */
  collection_window: ProofDReadWindow;
  harness: {
    attested_by: string;
    attested_at: string;
    environment: string;
    notes: readonly string[];
  };
  /** 1. When the WAN was cut and restored. */
  outage_window: {
    severed_at: EvidenceFact<string>;
    restored_at: EvidenceFact<string>;
    severance_method: EvidenceFact<string>;
    /**
     * The interval central itself has no rows in, computed from durable state.
     * It CORROBORATES the attested window; it does not establish it, and a
     * quiet period is not the same thing as an outage.
     */
    central_observation_gap: EvidenceFact<{
      last_event_before_attested_severance: string | null;
      first_event_after_attested_restore: string | null;
      gap_ms: number | null;
    }>;
  };
  /** 2. Which Edge remained operational. */
  edge: {
    identity: EvidenceFact<readonly ProofDEdgeObservation[]>;
    remained_operational: EvidenceFact<boolean>;
    security_events: EvidenceFact<readonly ProofDSecurityEventObservation[]>;
  };
  /** 3. Which Field client queued work. */
  field_client: {
    device_id: EvidenceFact<string>;
    degraded_state_recognised_at: EvidenceFact<string>;
    queued_offline_operation_ids: EvidenceFact<readonly string[]>;
    /** Operations whose device-claimed creation falls inside the attested cut. */
    composed_during_attested_outage: EvidenceFact<readonly string[]>;
  };
  /** 4. Admissions and refusals, and why each refusal occurred. */
  admission: {
    operations: readonly ProofDOperationEvidence[];
    admitted: EvidenceFact<readonly string[]>;
    gateway_events: EvidenceFact<readonly ProofDGatewayEventObservation[]>;
  };
  refusal: {
    /** Refused at central, on reconnect. Fully observed. */
    central_refusals: EvidenceFact<
      readonly { offline_operation_id: string; conflict_code: string; device_sequence: number }[]
    >;
    gateway_refusals: EvidenceFact<readonly { refusal_reason: string; occurred_at: string; trace_id: string }[]>;
    /** Refused on the device during the cut. Never centrally observable. */
    device_local_refusals: EvidenceFact<
      readonly { offline_operation_id: string | null; reason: string; at: string | null }[]
    >;
    /**
     * The durable half of a device-local policy refusal: leases whose expiry
     * falls inside the attested outage window. Central cannot see the refusal,
     * but it can see that the authority the device was relying on ran out.
     */
    lease_expiry_corroboration: EvidenceFact<
      readonly { policy_lease_id: string; expires_at: string; revoked_at: string | null; expired_during_outage: boolean }[]
    >;
  };
  /** 5. Which Edge receipt proves persistence. */
  edge_persistence: {
    receipt: EvidenceFact<string>;
  };
  /** 6. Reconnect, and which authenticated identity reconnected. */
  reconnect: {
    attested_at: EvidenceFact<string>;
    /**
     * Named plural, and not `device_context`, because that exact key is on the
     * frozen `DEVICE_AUDIT_FORBIDDEN_FIELDS` list and the scanner refuses it.
     * The refusal is correct even though the payload here is safe: a context id
     * authorises nothing, but the list exists so that nobody has to relitigate
     * which of the context-shaped fields was the dangerous one.
     */
    authenticated_device_contexts: EvidenceFact<readonly ProofDDeviceContextObservation[]>;
    edge_identity: EvidenceFact<string>;
  };
  /** 7. First operation received centrally, and what central produced. */
  first_central_receipt: {
    operation: EvidenceFact<{
      offline_operation_id: string;
      device_sequence: number;
      operation_kind: string;
      first_received_at: string;
      outcome: string | null;
      conflict_code: string | null;
      finalized_at: string | null;
      first_trace_id: string;
    }>;
  };
  /** 8. How duplicates converged. */
  duplicate_convergence: {
    structural_enforcement: EvidenceFact<readonly ProofDStructuralConstraintObservation[]>;
    retried_operations: EvidenceFact<readonly { offline_operation_id: string; attempt_count: number }[]>;
    converged_gateway_events: EvidenceFact<number>;
    distinct_downstream_keys: EvidenceFact<{ receipts: number; distinct_keys: number; equal: boolean }>;
  };
  /** 9. How changed requests conflicted. */
  conflict_convergence: {
    sequence_reused: EvidenceFact<readonly { offline_operation_id: string; device_sequence: number }[]>;
    other_conflicts: EvidenceFact<readonly { offline_operation_id: string; conflict_code: string }[]>;
  };
  /** 10-12. Final cursor, final queue, final domain state. */
  final_state: {
    cursor: EvidenceFact<ProofDCursorObservation>;
    queue: EvidenceFact<{
      total_receipts: number;
      /**
       * An ARRAY of labelled counts, never an object keyed by the label.
       * Values read out of the database must not become bundle KEY names: the
       * privacy scanner refuses forbidden key names, and a dynamic key would
       * put a database value in the position the scanner polices — turning a
       * legitimate row into either a crash or, worse, a way to name a field.
       */
      by_status: readonly { status: string; count: number }[];
      unfinalized: readonly string[];
      cursor_agrees_with_finalized_maximum: boolean;
    }>;
    domain_assignments: EvidenceFact<readonly ProofDAssignmentObservation[]>;
    domain_operative_state: EvidenceFact<ProofDOperativeStateObservation>;
    domain_message_state: EvidenceFact<never>;
  };
  /** 13. Proof that no duplicate operational action occurred. */
  no_duplicate_action: {
    checks: readonly {
      check: string;
      basis: string;
      holds: boolean;
      detail: string;
    }[];
    all_checks_hold: boolean;
    /** What this section does NOT establish. Stated in the artefact itself. */
    limitation: string;
  };
  /** Fan-out recovery. */
  fanout_recovery: {
    backlogs: EvidenceFact<readonly ProofDOutboxBacklogObservation[]>;
  };
  /** The end-to-end audit chain. */
  audit_chain: {
    /** Labelled counts as an array, for the reason `by_status` states. */
    field_audit_kinds: EvidenceFact<readonly { kind: string; count: number }[]>;
    device_security_events: EvidenceFact<readonly ProofDSecurityEventObservation[]>;
    trust_transitions: EvidenceFact<readonly ProofDTrustTransitionObservation[]>;
    trace_ids: EvidenceFact<readonly string[]>;
  };
  /** Which sources answered, which did not exist, which were not understood. */
  source_survey: {
    present: readonly string[];
    not_present: readonly { table_name: string; question: string; owner: string }[];
    unrecognised: readonly string[];
  };
  integrity: ProofDBundleIntegrity;
}
