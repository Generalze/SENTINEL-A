import { describe, expect, it, vi } from 'vitest';
import { IncidentsConsumer, organisationIdFromCandidateSubject } from './incidents.consumer';

const candidate = {
  schema_version: 1,
  incident_candidate_id: '00000000-0000-4000-8000-000000000001',
  hypothesis_id: '00000000-0000-4000-8000-000000000002',
  organisation_id: 'org-a',
  site_id: 'site-a',
  zone_id: null,
  threat_state: 4,
  detection_confidence: 0.9,
  threat_probability: 0.9,
  potential_impact: 'HIGH',
  operational_severity: 'SEV1',
  supporting_event_ids: [],
  contradicting_event_ids: [],
  confidence_explanation: 'test',
  rule_or_model_versions: ['fusion-rules-1.0.0'],
  re_escalation: false,
  emission_number: 1,
  triggering_event_id: 'event-a',
  emitted_at: '2026-08-16T09:00:00.000Z',
  hypothesis_version: 1,
};

describe('IncidentsConsumer', () => {
  it('parses only the exact organisation-scoped incident-candidate subject', () => {
    expect(organisationIdFromCandidateSubject('sentinel.fusion.incident-candidate.org-a')).toBe('org-a');
    expect(organisationIdFromCandidateSubject('sentinel.fusion.incident-candidate.org-a.extra')).toBeNull();
    expect(organisationIdFromCandidateSubject('sentinel.fusion.hypothesis.org-a')).toBeNull();
  });

  it('terminates a candidate whose subject tenant differs from its payload tenant', async () => {
    const incidents = { handleCandidate: vi.fn() };
    const consumer = new IncidentsConsumer({ isConfigured: () => false } as never, incidents as never);
    const msg = {
      subject: 'sentinel.fusion.incident-candidate.org-b',
      data: new TextEncoder().encode(JSON.stringify(candidate)),
      term: vi.fn(),
      ack: vi.fn(),
      nak: vi.fn(),
    };
    await consumer.handle(msg as never);
    expect(msg.term).toHaveBeenCalledOnce();
    expect(msg.ack).not.toHaveBeenCalled();
    expect(incidents.handleCandidate).not.toHaveBeenCalled();
  });
});
