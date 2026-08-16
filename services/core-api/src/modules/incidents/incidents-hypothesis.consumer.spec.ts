import { describe, expect, it, vi } from 'vitest';
import { IncidentsHypothesisConsumer, organisationIdFromHypothesisSubject } from './incidents-hypothesis.consumer';

const update = {
  schema_version: 1, emitted_at: '2026-08-16T10:00:00.000Z', triggering_event_id: 'event-a', hypothesis_version: 2,
  hypothesis: { hypothesis_id: '00000000-0000-4000-8000-000000000002', organisation_id: 'org-a', site_id: 'site-a', state: 4, operational_severity: 'SEV2', threat_probability: 0.9, supporting_event_ids: ['a'], contradicting_event_ids: [] },
};

describe('IncidentsHypothesisConsumer', () => {
  it('accepts only the exact tenant-bound hypothesis subject', () => {
    expect(organisationIdFromHypothesisSubject('sentinel.fusion.hypothesis.org-a')).toBe('org-a');
    expect(organisationIdFromHypothesisSubject('sentinel.fusion.hypothesis.org-a.extra')).toBeNull();
  });

  it('terminates a cross-tenant update before incident advancement', async () => {
    const incidents = { handleHypothesisUpdate: vi.fn() };
    const consumer = new IncidentsHypothesisConsumer({ isConfigured: () => false } as never, incidents as never);
    const msg = { subject: 'sentinel.fusion.hypothesis.org-b', data: new TextEncoder().encode(JSON.stringify(update)), term: vi.fn(), ack: vi.fn(), nak: vi.fn() };
    await consumer.handle(msg as never);
    expect(msg.term).toHaveBeenCalledOnce();
    expect(incidents.handleHypothesisUpdate).not.toHaveBeenCalled();
  });
});
