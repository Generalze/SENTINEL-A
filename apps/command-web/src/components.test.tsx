import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DegradedBanner, DeliveryChip, IncidentQueue, RelatedEvidence, ResponseTasks } from './components';
import type { Incident } from './types';

function incident(id: string, severity: Incident['severity'], opened_at: string): Incident {
  return { id, organisation_id: 'org-1', site_id: 'site-1', incident_type: id, severity, threat_state: 2, confidence: .5, status: 'open', opened_at };
}

describe('command components', () => {
  it('orders queue by severity then age', () => {
    const items = [incident('old-sev2', 'SEV2', '2026-08-16T01:00:00Z'), incident('new-sev1', 'SEV1', '2026-08-16T03:00:00Z'), incident('new-sev2', 'SEV2', '2026-08-16T04:00:00Z')];
    render(<IncidentQueue incidents={items} onSelect={() => undefined} />);
    const names = screen.getAllByRole('button').map((button) => button.textContent ?? '');
    expect(names[0]).toContain('new-sev1'); expect(names[1]).toContain('old-sev2'); expect(names[2]).toContain('new-sev2');
  });

  it('keeps contradicting evidence visible beside supporting evidence', () => {
    render(<RelatedEvidence events={[{ id: 'support-1', relation: 'supporting', summary: 'camera corroboration' }, { id: 'against-1', relation: 'contradicting', summary: 'door remained closed' }]} />);
    expect(screen.getByText('camera corroboration')).toBeVisible(); expect(screen.getByText('door remained closed')).toBeVisible(); expect(screen.getByText(/CONTRADICTING \(1\)/)).toBeVisible();
  });

  it('renders delivery states verbatim', () => { render(<DeliveryChip state="ACKNOWLEDGED" />); expect(screen.getByText('ACKNOWLEDGED')).toBeVisible(); });

  it('does not optimistically replace a delivery chip before the server response', () => { render(<ResponseTasks tasks={[{ id: 'task-1', task_type: 'dispatch-field', delivery_state: 'DELIVERED' }]} onAcknowledge={() => undefined} />); screen.getByRole('button', { name: 'Acknowledge' }).click(); expect(screen.getByText('DELIVERED')).toBeVisible(); expect(screen.queryByText('ACKNOWLEDGED')).not.toBeInTheDocument(); });

  it('shows degraded banner only when degraded', () => { const { rerender } = render(<DegradedBanner degraded={false} />); expect(screen.queryByRole('alert')).not.toBeInTheDocument(); rerender(<DegradedBanner degraded />); expect(screen.getByRole('alert')).toHaveTextContent('DEGRADED MODE'); });
});
