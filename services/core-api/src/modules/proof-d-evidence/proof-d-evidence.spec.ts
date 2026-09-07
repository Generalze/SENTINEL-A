import { describe, expect, it } from 'vitest';
import {
  assertCollectorGateOpen,
  deriveReadWindow,
  PROOF_D_DEFAULT_LOOKBACK_MS,
  ProofDCollectorGateError,
} from './proof-d-evidence.cli';
import { collectProofDEvidence } from './proof-d-evidence.collector';
import {
  PROOF_D_EVIDENCE_SOURCES,
  PROOF_D_KNOWN_UNREAD_SOURCES,
  PROOF_D_PENDING_SOURCES,
} from './proof-d-evidence.constants';
import { ProofDEvidenceIntegrityError } from './proof-d-evidence.facts';
import { fixtureAttestation, fixtureObservation, FIXTURE_SCOPE } from './proof-d-evidence.test-support';
import type { ProofDBundle } from './proof-d-evidence.types';

/**
 * WP-31 — the collector's shaping.
 *
 * These tests are about ONE property expressed many ways: the bundle must never
 * present something the harness said as something the server saw, and must
 * never present an unbuilt capability as an empty one. Everything else the
 * collector does is arithmetic; this is the part that decides whether the
 * artefact is honest.
 */

const GENERATED_AT = '2026-09-05T10:30:00.000Z';

function bundle(): ProofDBundle {
  return collectProofDEvidence(fixtureObservation(), fixtureAttestation(), GENERATED_AT);
}

describe('Proof D evidence bundle — the claim never moves', () => {
  it('reports Proof D UNCLAIMED regardless of how clean the run was', () => {
    const result = bundle();
    expect(result.claim.proof_d).toBe('UNCLAIMED');
    expect(result.claim.proof_c).toBe('UNCLAIMED');
    expect(result.claim.wp_26_physical_acceptance).toBe('DEFERRED — NOT WAIVED');
    expect(result.claim.wp_28).toBe('BLOCKED — NOT STARTED');
    expect(result.acceptance.claim).toBe('UNCLAIMED');
  });

  it('never emits the words that would read as a passed proof', () => {
    const serialised = JSON.stringify(bundle());
    expect(serialised).not.toMatch(/Proof D PASS/i);
    expect(serialised).not.toMatch(/proof_d["\s:]+"?PASS/i);
    expect(serialised).not.toMatch(/milestone (3 )?complete/i);
  });

  it('refuses physical-acceptance eligibility for a simulated severance', () => {
    const result = bundle();
    expect(result.acceptance.physical_acceptance_eligible).toBe(false);
    expect(result.acceptance.reasons.join(' ')).toMatch(/SIMULATED/);
  });

  it('still refuses eligibility for a perfectly attested FIELD run, because the Edge receipt source does not exist', () => {
    // Everything the locked definition asks of the harness is attested here.
    // The bundle must still decline, because central has no way to evidence
    // Edge-side persistence at this commit — the durable Edge queue belongs to
    // another work package. A collector that let a strong attestation paper
    // over a missing source would be manufacturing the very thing WP-31 exists
    // to avoid manufacturing.
    const result = collectProofDEvidence(
      fixtureObservation(),
      fixtureAttestation({
        environment: 'FIELD',
        wan: {
          severed_at: '2026-09-05T09:00:00.000Z',
          restored_at: '2026-09-05T10:00:00.000Z',
          severance_method: 'PHYSICAL',
          note: 'Uplink cable removed at the site cabinet.',
        },
      }),
      GENERATED_AT,
    );
    expect(result.acceptance.physical_acceptance_eligible).toBe(false);
    expect(result.acceptance.reasons.join(' ')).toMatch(/Edge receipt source/);
  });
});

describe('Proof D evidence bundle — attested facts are never dressed as observations', () => {
  it('labels the outage window as harness-attested and names the attestor', () => {
    const result = bundle();
    expect(result.outage_window.severed_at.provenance).toBe('HARNESS_ATTESTED');
    expect(result.outage_window.severed_at.source).toBeNull();
    expect(result.outage_window.severed_at.attested_by).toBe(fixtureAttestation().attested_by);
    expect(result.outage_window.restored_at.provenance).toBe('HARNESS_ATTESTED');
  });

  it('emits the central observation gap as a separate OBSERVED corroboration, not as part of the attestation', () => {
    const gap = bundle().outage_window.central_observation_gap;
    expect(gap.provenance).toBe('OBSERVED');
    expect(gap.source).toContain('device_gateway_operation_events');
    expect(gap.note).toMatch(/CORROBORATION ONLY/);
    // Nothing central recorded falls inside the attested cut in the fixture.
    expect(gap.value?.first_event_after_attested_restore).toBe('2026-09-05T10:00:00.500Z');
  });

  it('keeps the device clock labelled CLIENT_CLAIMED even though it is durably stored', () => {
    const operation = bundle().admission.operations[0];
    expect(operation?.client_created_at.provenance).toBe('CLIENT_CLAIMED');
    expect(operation?.first_received_at.provenance).toBe('OBSERVED');
  });

  it('gives a derived duration the weaker of its two inputs', () => {
    const operation = bundle().admission.operations[0];
    // One end is the device's clock, so the dwell figure inherits it.
    expect(operation?.offline_dwell_ms.provenance).toBe('CLIENT_CLAIMED');
    // Both ends are the server's clock.
    expect(operation?.central_settlement_ms.provenance).toBe('OBSERVED');
    expect(operation?.central_settlement_ms.value).toBe(1000);
  });

  it('treats an operation composed during the cut as the device\'s account, not central\'s', () => {
    const composed = bundle().field_client.composed_during_attested_outage;
    expect(composed.provenance).toBe('CLIENT_CLAIMED');
    expect(composed.value).toHaveLength(3);
  });

  it('reports device-local refusals as attested and their durable shadow as observed', () => {
    const result = bundle();
    expect(result.refusal.device_local_refusals.provenance).toBe('HARNESS_ATTESTED');
    expect(result.refusal.device_local_refusals.value?.[0]?.reason).toBe('POLICY_LEASE_EXPIRED');

    const corroboration = result.refusal.lease_expiry_corroboration;
    expect(corroboration.provenance).toBe('OBSERVED');
    expect(corroboration.source).toBe('device_policy_leases');
    expect(corroboration.value?.[0]?.expired_during_outage).toBe(true);
  });
});

describe('Proof D evidence bundle — an absent fact is visibly absent', () => {
  it('distinguishes a source that does not exist from one that held nothing', () => {
    const result = bundle();
    expect(result.edge_persistence.receipt.provenance).toBe('SOURCE_NOT_PRESENT');
    expect(result.edge_persistence.receipt.source).toBe('edge_operation_receipts');
    expect(result.reconnect.edge_identity.provenance).toBe('SOURCE_NOT_PRESENT');

    expect(result.audit_chain.trust_transitions.provenance).toBe('ABSENT');
    expect(result.audit_chain.trust_transitions.source).toBe('device_trust_transitions');
  });

  it('reports a source that has since arrived as unreadable rather than missing', () => {
    // The mirror-image failure: another lane lands the Edge receipt table and
    // this collector, which has no reader for it, must not go on reporting the
    // system as lacking a capability it now has.
    const result = collectProofDEvidence(
      fixtureObservation({
        present_sources: ['field_offline_operation_receipts', 'edge_operation_receipts'],
      }),
      fixtureAttestation(),
      GENERATED_AT,
    );
    expect(result.edge_persistence.receipt.provenance).toBe('SOURCE_NOT_READABLE');
    expect(result.edge_persistence.receipt.note).toMatch(/EXISTS/);
  });

  it('names every unanswered question and who owns the answer', () => {
    const notPresent = bundle().source_survey.not_present;
    expect(notPresent.map((entry) => entry.table_name).sort()).toEqual(
      PROOF_D_PENDING_SOURCES.map((entry) => entry.table_name).sort(),
    );
    for (const entry of notPresent) {
      expect(entry.question.length).toBeGreaterThan(0);
      expect(entry.owner).toMatch(/WP-2\d/);
    }
  });

  it('keeps the unrecognised-source survey meaningful by declaring what it deliberately does not read', () => {
    // A signal that fires on every run is a signal nobody reads. Without this
    // list the survey would report the whole Edge enrolment ceremony every
    // time, and the one case it exists for — a genuinely new source arriving
    // under an unexpected name — would arrive inside that noise and be missed.
    for (const unread of PROOF_D_KNOWN_UNREAD_SOURCES) {
      expect(PROOF_D_EVIDENCE_SOURCES).not.toContain(unread);
    }
    for (const pending of PROOF_D_PENDING_SOURCES) {
      expect(PROOF_D_KNOWN_UNREAD_SOURCES).not.toContain(pending.table_name);
    }
  });

  it('surfaces a source it does not recognise instead of ignoring it', () => {
    const result = collectProofDEvidence(
      fixtureObservation({ unrecognised_sources: ['edge_durable_outbox'] }),
      fixtureAttestation(),
      GENERATED_AT,
    );
    expect(result.source_survey.unrecognised).toEqual(['edge_durable_outbox']);
  });

  it('records a privacy exclusion as a withheld fact rather than a missing field', () => {
    const withheldFact = bundle().final_state.domain_message_state;
    expect(withheldFact.provenance).toBe('WITHHELD_BY_PRIVACY_RULE');
    expect(withheldFact.value).toBeNull();
    expect(withheldFact.note).toMatch(/protected recipient set/);
  });
});

describe('Proof D evidence bundle — what durable state answers on its own', () => {
  it('reads duplicate suppression as a structural property, not a measured one', () => {
    const result = bundle();
    const enforcement = result.duplicate_convergence.structural_enforcement;
    expect(enforcement.provenance).toBe('OBSERVED');
    expect(enforcement.source).toBe('pg_indexes');
    expect(enforcement.value?.map((entry) => entry.index_name)).toContain('field_offline_receipt_sequence_key');
    expect(enforcement.value?.every((entry) => entry.present)).toBe(true);
  });

  it('identifies the first operation central received and what central produced', () => {
    const first = bundle().first_central_receipt.operation;
    expect(first.provenance).toBe('OBSERVED');
    expect(first.value?.offline_operation_id).toBe('aaaaaaaa-0000-4000-8000-000000000001');
    expect(first.value?.outcome).toBe('APPLIED');
  });

  it('reports convergence and conflict from the sources that hold each', () => {
    const result = bundle();
    expect(result.duplicate_convergence.retried_operations.value).toEqual([
      { offline_operation_id: 'aaaaaaaa-0000-4000-8000-000000000001', attempt_count: 2 },
    ]);
    expect(result.duplicate_convergence.converged_gateway_events.value).toBe(1);
    expect(result.duplicate_convergence.distinct_downstream_keys.value?.equal).toBe(true);

    // A changed request at a consumed position is refused before a receipt
    // exists, so the bundle must point the reader at the gateway stream rather
    // than reporting silence.
    expect(result.conflict_convergence.sequence_reused.provenance).toBe('ABSENT');
    expect(result.conflict_convergence.sequence_reused.note).toMatch(/leaves NO receipt/);
    expect(result.refusal.gateway_refusals.value).toEqual([
      { refusal_reason: 'OFFLINE_SEQUENCE_REUSED', occurred_at: '2026-09-05T10:00:08.000Z', trace_id: 'trace-gateway-3' },
    ]);
  });

  it('reports the final cursor, the final queue and the operation still in flight', () => {
    const result = bundle();
    expect(result.final_state.cursor.value?.last_finalized_sequence).toBe(1);
    expect(result.final_state.queue.value?.total_receipts).toBe(3);
    expect(result.final_state.queue.value?.unfinalized).toEqual(['aaaaaaaa-0000-4000-8000-000000000003']);
    expect(result.final_state.queue.value?.cursor_agrees_with_finalized_maximum).toBe(true);
  });

  it('labels a null policy lease as an era marker rather than a defect', () => {
    const legacy = bundle().admission.operations[2];
    expect(legacy?.policy_lease_id.provenance).toBe('ABSENT');
    expect(legacy?.policy_lease_id.note).toMatch(/ERA MARKER/);
  });

  it('states what the no-duplicate checks do not establish', () => {
    const section = bundle().no_duplicate_action;
    expect(section.checks.length).toBeGreaterThanOrEqual(8);
    expect(section.all_checks_hold).toBe(false); // one operation is still in flight
    expect(section.checks.find((entry) => entry.check.includes('in flight'))?.holds).toBe(false);
    expect(section.checks.find((entry) => entry.check.includes('queue position'))?.holds).toBe(true);
    expect(section.limitation).toMatch(/not an acceptance/);
    expect(section.limitation).toMatch(/UNCLAIMED/);
  });

  it('fails the structural check when the unique index is not in the database', () => {
    // A missing constraint is a far louder finding than any counter could be,
    // so it must not be quietly compensated for by the derived count agreeing.
    const result = collectProofDEvidence(
      fixtureObservation({
        structural_constraints: [
          { index_name: 'field_offline_receipt_sequence_key', table_name: 'field_offline_operation_receipts', present: false },
        ],
      }),
      fixtureAttestation(),
      GENERATED_AT,
    );
    expect(result.no_duplicate_action.checks.find((entry) => entry.check.includes('queue position'))?.holds).toBe(false);
  });
});

describe('Proof D evidence bundle — integrity', () => {
  it('refuses to assemble a bundle whose observation and attestation describe different runs', () => {
    expect(() =>
      collectProofDEvidence(
        fixtureObservation(),
        fixtureAttestation({ scope: { ...FIXTURE_SCOPE, device_id: '99999999-9999-4999-8999-999999999999' } }),
        GENERATED_AT,
      ),
    ).toThrow(ProofDEvidenceIntegrityError);
  });

  it('tallies provenance and cites only sources on the allowlist', () => {
    const result = bundle();
    expect(result.integrity.privacy_scan).toBe('PASS');
    expect(result.integrity.fact_count_by_provenance.OBSERVED).toBeGreaterThan(0);
    expect(result.integrity.fact_count_by_provenance.HARNESS_ATTESTED).toBeGreaterThan(0);
    expect(result.integrity.fact_count_by_provenance.CLIENT_CLAIMED).toBeGreaterThan(0);
    expect(result.integrity.fact_count_by_provenance.SOURCE_NOT_PRESENT).toBeGreaterThan(0);
    expect(result.integrity.fact_count_by_provenance.WITHHELD_BY_PRIVACY_RULE).toBeGreaterThan(0);
    for (const cited of result.integrity.cited_sources) {
      expect(result.integrity.observed_source_allowlist).toContain(cited);
    }
  });

  it('is reproducible from its inputs', () => {
    expect(JSON.stringify(bundle())).toEqual(JSON.stringify(bundle()));
  });

  it('records the window it swept, so an absent fact can be read against the search', () => {
    expect(bundle().collection_window).toEqual({
      from: '2026-09-05T08:00:00.000Z',
      to: '2026-09-05T11:00:00.000Z',
    });
  });
});

describe('the collector gate and its read window', () => {
  it('refuses to run unless the operator has said so explicitly', () => {
    // A check that can be satisfied by accident is indistinguishable from no
    // check. This collector reads the device-security audit trail across four
    // modules; it is not run by mistake.
    expect(() => assertCollectorGateOpen({})).toThrow(ProofDCollectorGateError);
    expect(() => assertCollectorGateOpen({ SENTINEL_PROOF_D_EVIDENCE: 'true' })).toThrow(ProofDCollectorGateError);
    expect(() => assertCollectorGateOpen({ SENTINEL_PROOF_D_EVIDENCE: '1' })).not.toThrow();
  });

  it('sweeps past the restoration, because reconciliation happens after the link returns', () => {
    const window = deriveReadWindow(
      '2026-09-05T09:00:00.000Z',
      '2026-09-05T10:00:00.000Z',
      '2026-09-05T10:05:00.000Z',
      PROOF_D_DEFAULT_LOOKBACK_MS,
    );
    expect(window.from).toBe('2026-09-05T08:00:00.000Z');
    // A window that stopped at the restore instant would miss the entire half
    // of the run Proof D is actually about.
    expect(Date.parse(window.to)).toBeGreaterThan(Date.parse('2026-09-05T10:05:00.000Z'));
  });

  it('ends at the read time when the link has not been restored', () => {
    const window = deriveReadWindow('2026-09-05T09:00:00.000Z', null, '2026-09-05T09:30:00.000Z', 0);
    expect(window).toEqual({ from: '2026-09-05T09:00:00.000Z', to: '2026-09-05T09:30:00.000Z' });
  });
});
