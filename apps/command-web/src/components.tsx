import { useEffect, useRef, useState } from 'react';
import type { DeliveryState, Incident, RelatedEvent, ResponseTask, TimelineEntry } from './types';

const severityRank: Record<Incident['severity'], number> = { SEV1: 1, SEV2: 2, SEV3: 3, SEV4: 4, SEV5: 5 };

/** Highest operational severity first; ties are oldest-first to avoid starvation. */
export function sortIncidents(incidents: Incident[]): Incident[] {
  return [...incidents].sort((a, b) => {
    const severity = severityRank[a.severity] - severityRank[b.severity];
    if (severity !== 0) return severity;
    return new Date(a.opened_at).getTime() - new Date(b.opened_at).getTime();
  });
}

export function formatAge(openedAt: string, now = Date.now()): string {
  const seconds = Math.max(0, Math.floor((now - new Date(openedAt).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function DeliveryChip({ state }: { state: DeliveryState }): React.JSX.Element {
  return <span className={`delivery-chip delivery-${state.toLowerCase()}`}>{state}</span>;
}

export function IncidentQueue({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: Incident[];
  selectedId?: string;
  onSelect: (id: string) => void;
}): React.JSX.Element {
  const ordered = sortIncidents(incidents);
  return (
    <section className="panel queue-panel" aria-label="Prioritised incident queue">
      <div className="panel-heading">
        <h2>INCIDENT QUEUE</h2>
        <span className="count-badge">{ordered.length}</span>
      </div>
      {ordered.length === 0 ? <p className="empty-state">No active incidents in this organisation.</p> : null}
      <div className="queue-list">
        {ordered.map((incident) => (
          <button
            className={`queue-item ${incident.id === selectedId ? 'selected' : ''}`}
            key={incident.id}
            onClick={() => onSelect(incident.id)}
            type="button"
          >
            <div className="queue-item-top">
              <span className={`severity severity-${incident.severity.toLowerCase()}`}>{incident.severity}</span>
              <span className="queue-age">{formatAge(incident.opened_at)}</span>
            </div>
            <strong>{incident.incident_type}</strong>
            <div className="queue-meta">
              <span>Threat: {incident.threat_state}</span>
              <span>Confidence: {formatPercent(incident.confidence)}</span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

export function Timeline({ entries }: { entries: TimelineEntry[] }): React.JSX.Element {
  const endRef = useRef<React.ElementRef<'div'>>(null);
  const ordered = [...entries].sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime());
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'nearest' });
  }, [entries.length]);
  return (
    <section className="workspace-section">
      <div className="section-heading"><h3>TIMELINE</h3><span className="muted">Append-only · newest last</span></div>
      <div className="timeline" aria-label="Incident timeline">
        {ordered.length === 0 ? <p className="empty-state">No timeline entries recorded.</p> : null}
        {ordered.map((entry, index) => (
          <article className="timeline-entry" key={entry.id ?? `${entry.at}-${entry.kind}-${index}`}>
            <time dateTime={entry.at}>{new Date(entry.at).toLocaleTimeString()}</time>
            <div><strong>{entry.kind}</strong>{entry.actor_user_id ? <span className="muted"> · {entry.actor_user_id}</span> : null}
              {entry.payload ? <p>{JSON.stringify(entry.payload)}</p> : null}</div>
          </article>
        ))}
        <div ref={endRef} />
      </div>
    </section>
  );
}

function eventLabel(event: RelatedEvent): string {
  return event.summary ?? event.event_id ?? event.id;
}

export function RelatedEvidence({ events = [], relatedIds = [], supportingIds = [], contradictingIds = [] }: { events?: RelatedEvent[]; relatedIds?: string[]; supportingIds?: string[]; contradictingIds?: string[] }): React.JSX.Element {
  const supporting = events.filter((event) => event.relation === 'supporting' || event.relation === 'support');
  const contradicting = events.filter((event) => event.relation === 'contradicting' || event.relation === 'contradiction');
  const unclassified = events.filter((event) => !event.relation);
  const ids = [...new Set([...supportingIds, ...relatedIds])].filter((id) => !events.some((event) => event.id === id || event.event_id === id));
  const contradictionIds = [...new Set(contradictingIds)].filter((id) => !events.some((event) => event.id === id || event.event_id === id));
  return (
    <section className="workspace-section evidence-section">
      <div className="section-heading"><h3>RELATED EVENTS</h3><span className="muted">Evidence is not a determination</span></div>
      <div className="evidence-columns">
        <div className="evidence-column supporting"><h4>SUPPORTING ({supporting.length + unclassified.length + ids.length})</h4>
          {supporting.map((event) => <div className="evidence-item" key={event.id}>{eventLabel(event)}</div>)}
          {unclassified.map((event) => <div className="evidence-item" key={event.id}>{eventLabel(event)} <span className="muted">(unclassified)</span></div>)}
          {ids.map((id) => <div className="evidence-item" key={id}>{id}</div>)}
          {supporting.length + unclassified.length + ids.length === 0 ? <p className="empty-state">None recorded.</p> : null}
        </div>
        <div className="evidence-column contradicting"><h4>CONTRADICTING ({contradicting.length + contradictionIds.length})</h4>
          {contradicting.map((event) => <div className="evidence-item" key={event.id}>{eventLabel(event)}</div>)}
          {contradictionIds.map((id) => <div className="evidence-item" key={id}>{id}</div>)}
          {contradicting.length + contradictionIds.length === 0 ? <p className="empty-state">None recorded.</p> : null}
        </div>
      </div>
    </section>
  );
}

export function IncidentLifecycle({ incident, onContain, onClose, busy }: { incident: Incident; onContain: () => void; onClose: (reason: string) => void; busy?: boolean }): React.JSX.Element | null {
  const [reason, setReason] = useState('');
  if (incident.status === 'closed') return null;
  if (incident.status === 'open') return <div className="lifecycle-action"><p className="muted">Acknowledge the operational transition before closing.</p><button type="button" className="secondary-button" disabled={busy} onClick={onContain}>{busy ? 'Containing…' : 'Mark contained'}</button></div>;
  return <form className="close-form" onSubmit={(event) => { event.preventDefault(); if (reason.trim()) onClose(reason.trim()); }}><label htmlFor="closure-reason">Closure reason (required)</label><textarea id="closure-reason" required minLength={1} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain why this incident is closed" /><button className="danger-button" disabled={busy || !reason.trim()} type="submit">{busy ? 'Closing…' : 'Close incident'}</button></form>;
}

export function ResponseTasks({ tasks, onAcknowledge, acknowledging }: {
  tasks: ResponseTask[];
  onAcknowledge: (task: ResponseTask) => void;
  acknowledging?: string;
}): React.JSX.Element {
  return <section className="workspace-section"><div className="section-heading"><h3>RESPONSE TASKS</h3><span className="muted">Server-confirmed delivery</span></div>
    <div className="task-list">{tasks.length === 0 ? <p className="empty-state">No response tasks.</p> : tasks.map((task) => <div className="task-row" key={task.id}>
      <div><strong>{task.name ?? task.task_type ?? task.id}</strong>{task.required_action ? <p className="muted">{task.required_action}</p> : null}</div>
      <DeliveryChip state={task.delivery_state} />
      {task.delivery_state === 'DELIVERED' ? <button type="button" className="secondary-button" disabled={acknowledging === task.id} onClick={() => onAcknowledge(task)}>{acknowledging === task.id ? 'Confirming…' : 'Acknowledge'}</button> : null}
    </div>)}</div>
  </section>;
}

export function DegradedBanner({ degraded }: { degraded: boolean }): React.JSX.Element | null {
  return degraded ? <div className="degraded-banner" role="alert">DEGRADED MODE · API readiness is unavailable. Live operational state may be incomplete.</div> : null;
}
