import { useEffect, useMemo, useState } from 'react';
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, commandApi, getDevUserId, setDevUserId } from './api';
import { DegradedBanner, IncidentLifecycle, IncidentQueue, RelatedEvidence, ResponseTasks, Timeline } from './components';
import { createCommandSocket, type ConnectionState } from './realtime';
import type { ResponseTask } from './types';
import './App.css';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2_000, retry: 1, refetchOnWindowFocus: false } } });

export const queueQueryKey = (userId: string): readonly ['incidents', string] => ['incidents', userId];

function useIncidentQueries(userId: string) {
  const client = useQueryClient();
  const [selectedId, setSelectedId] = useState<string>();
  const queue = useQuery({ queryKey: queueQueryKey(userId), queryFn: commandApi.listIncidents, enabled: Boolean(userId), refetchInterval: 10_000 });
  const incidents = queue.data?.incidents ?? [];
  useEffect(() => {
    if (incidents.length === 0) { setSelectedId(undefined); return; }
    if (!selectedId || !incidents.some((item) => item.id === selectedId)) setSelectedId(incidents[0]?.id);
  }, [incidents, selectedId]);
  const workspace = useQuery({ queryKey: ['incident', selectedId, userId], queryFn: () => commandApi.getIncident(selectedId as string), enabled: Boolean(selectedId && userId), refetchInterval: 10_000 });
  useEffect(() => {
    if (!userId) return;
    const invalidate = (): void => { void client.invalidateQueries({ queryKey: ['incidents', userId] }); if (selectedId) void client.invalidateQueries({ queryKey: ['incident', selectedId, userId] }); };
    const socket = createCommandSocket(() => undefined, invalidate, invalidate, () => { void client.invalidateQueries({ queryKey: ['presence', userId] }); });
    return () => { socket.close(); };
  }, [client, selectedId, userId]);
  const lastVerifiedAt = Math.max(queue.dataUpdatedAt, workspace.dataUpdatedAt);
  return { incidents, incident: workspace.data, selectedId, setSelectedId, queueError: queue.error ?? undefined, workspaceError: workspace.error ?? undefined, queueLoading: queue.isLoading, lastVerifiedAt, queryError: queue.error ?? workspace.error ?? undefined };
}

function ConnectionIndicator({ userId, lastVerifiedAt, queryError }: { userId: string; lastVerifiedAt: number; queryError?: Error }): React.JSX.Element {
  const [state, setState] = useState<ConnectionState>('connecting'); const [staleSince, setStaleSince] = useState<Date>();
  useEffect(() => {
    if (!userId) { setState('disconnected'); setStaleSince(undefined); return; }
    const socket = createCommandSocket(setState, () => undefined, () => undefined); const onDisconnect = (): void => setStaleSince((previous) => previous ?? new Date());
    socket.on('disconnect', onDisconnect); socket.on('connect', () => setStaleSince(undefined)); return () => { socket.off('disconnect', onDisconnect); socket.close(); };
  }, [userId]);
  useEffect(() => {
    const refresh = (): void => {
      const old = lastVerifiedAt > 0 && Date.now() - lastVerifiedAt > 20_000;
      if (queryError || old) setStaleSince((previous) => previous ?? new Date(lastVerifiedAt || Date.now()));
      else if (lastVerifiedAt > 0) setStaleSince(undefined);
    };
    refresh(); const timer = window.setInterval(refresh, 5_000); return () => window.clearInterval(timer);
  }, [lastVerifiedAt, queryError]);
  const live = state === 'connected' && !staleSince;
  return <div className="connection-state" aria-live="polite"><span className={`connection-dot ${live ? 'connected' : state}`} />{live ? 'LIVE' : state === 'connecting' ? 'CONNECTING' : staleSince ? `STALE · since ${staleSince.toLocaleTimeString()}` : 'DISCONNECTED'}</div>;
}

function UserPicker({ userId, onChange }: { userId: string; onChange: (value: string) => void }): React.JSX.Element {
  const [value, setValue] = useState(userId);
  return <label className="dev-picker">DEV AUTH · user id<input aria-label="Development user id" value={value} placeholder="user id" onChange={(event) => setValue(event.target.value)} onBlur={() => { setDevUserId(value); onChange(value.trim()); }} /></label>;
}

function CommandShell(): React.JSX.Element {
  const [userId, setUserId] = useState(getDevUserId()); const client = useQueryClient();
  const { incidents, incident, selectedId, setSelectedId, queueError, workspaceError, queueLoading, lastVerifiedAt, queryError } = useIncidentQueries(userId);
  const presence = useQuery({ queryKey: ['presence', userId], queryFn: commandApi.listPresence, enabled: Boolean(userId), refetchInterval: 15_000 });
  const readiness = useQuery({ queryKey: ['health', 'ready'], queryFn: commandApi.readiness, retry: false, refetchInterval: 10_000 });
  const degraded = readiness.isError && (readiness.error instanceof ApiError ? readiness.error.status === 503 || readiness.error.status === 0 : true);
  const [acknowledging, setAcknowledging] = useState<string>();
  const ack = useMutation({ mutationFn: ({ task }: { task: ResponseTask }) => { if (!incident) throw new Error('No incident selected'); return commandApi.acknowledgeTask(incident.id, task.id); }, onMutate: ({ task }) => setAcknowledging(task.id), onSettled: () => setAcknowledging(undefined), onSuccess: () => { void client.invalidateQueries({ queryKey: ['incidents', userId] }); void client.invalidateQueries({ queryKey: ['incident', selectedId, userId] }); } });
  const lifecycle = useMutation({ mutationFn: ({ status, reason }: { status: 'contained' | 'closed'; reason?: string }) => { if (!incident) throw new Error('No incident selected'); return commandApi.transitionIncident(incident.id, status, reason); }, onSuccess: () => { void client.invalidateQueries({ queryKey: ['incidents', userId] }); void client.invalidateQueries({ queryKey: ['incident', selectedId, userId] }); } });
  const tasks = useMemo(() => incident?.response_tasks ?? incident?.tasks ?? [], [incident]);
  return <div className="command-app"><header className="app-header"><div><p className="eyebrow">SENTINEL COMMAND</p><h1>Operational workspace</h1></div><div className="header-context"><span>SITE {incident?.site_id ?? '—'}</span><ConnectionIndicator userId={userId} lastVerifiedAt={lastVerifiedAt} queryError={queryError} /><UserPicker userId={userId} onChange={setUserId} /></div></header><DegradedBanner degraded={degraded} />{!userId ? <div className="setup-card"><h2>Development access required</h2><p>Choose a development user to load its server-scoped organisation. This picker is labelled and is not production authentication.</p><UserPicker userId={userId} onChange={setUserId} /></div> : <main className="three-column"><IncidentQueue incidents={incidents} selectedId={selectedId} onSelect={setSelectedId} /><section className="panel workspace-panel" aria-label="Selected incident workspace">{queueLoading ? <p className="loading-state">Loading incident queue…</p> : null}{queueError ? <p className="error-text">Queue unavailable: {queueError.message}</p> : null}{!incident && !queueLoading ? <p className="empty-state">Select an incident to open its workspace.</p> : null}{incident ? <><div className="workspace-header"><div><p className="eyebrow">{incident.id}</p><h2>{incident.incident_type}</h2><p className="muted">{incident.status.toUpperCase()} · {incident.response_mode ?? 'STANDARD'} · opened {new Date(incident.opened_at).toLocaleString()}</p></div><div className="workspace-values"><span className={`severity severity-${incident.severity.toLowerCase()}`}>Severity {incident.severity}</span><span className="confidence-value">Confidence {Math.round(incident.confidence * 100)}%</span></div></div>{workspaceError ? <p className="error-text">Workspace refresh unavailable: {workspaceError.message}</p> : null}<Timeline entries={incident.timeline ?? []} /><RelatedEvidence events={incident.related_events ?? []} relatedIds={incident.related_event_ids} supportingIds={incident.supporting_event_ids} contradictingIds={incident.contradicting_event_ids} /><ResponseTasks tasks={tasks} acknowledging={acknowledging} onAcknowledge={(task) => ack.mutate({ task })} />{ack.error ? <p className="error-text">Acknowledgement failed: {ack.error.message}. The delivery state above remains server-confirmed.</p> : null}{lifecycle.error ? <p className="error-text">Lifecycle transition failed: {lifecycle.error.message}. The displayed status remains server-confirmed.</p> : null}<IncidentLifecycle incident={incident} busy={lifecycle.isPending} onContain={() => lifecycle.mutate({ status: 'contained' })} onClose={(reason) => lifecycle.mutate({ status: 'closed', reason })} /></> : null}</section><aside className="panel presence-panel"><div className="panel-heading"><h2>PRESENCE</h2><span className="count-badge">{presence.data?.presence.length ?? 0}</span></div>{presence.isError ? <p className="error-text">Presence unavailable.</p> : null}{(presence.data?.presence ?? []).map((person) => <div className="presence-row" key={person.user_id}><span className="presence-dot" /><div><strong>{person.user_id}</strong><p className="muted">{person.sockets} connection{person.sockets === 1 ? '' : 's'}</p></div></div>)}{!presence.isError && (presence.data?.presence.length ?? 0) === 0 ? <p className="empty-state">No connected operators.</p> : null}</aside></main>}</div>;
}

function App(): React.JSX.Element { return <QueryClientProvider client={queryClient}><CommandShell /></QueryClientProvider>; }
export default App;
