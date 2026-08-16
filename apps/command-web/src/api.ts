import type { Incident, IncidentListResponse, PresenceResponse } from './types';

export const DEV_USER_STORAGE_KEY = 'sentinel.command.dev-user-id';

export function apiBaseUrl(): string {
  const configured = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env?.VITE_API_URL;
  // Empty means same-origin. Vite proxies these paths to core-api in dev;
  // production deployments can provide VITE_API_URL explicitly.
  return (configured ?? '').replace(/\/$/, '');
}

export function getDevUserId(): string {
  if (typeof window === 'undefined') return '';
  return window.localStorage.getItem(DEV_USER_STORAGE_KEY) ?? '';
}

export function setDevUserId(userId: string): void {
  if (typeof window === 'undefined') return;
  if (userId.trim()) window.localStorage.setItem(DEV_USER_STORAGE_KEY, userId.trim());
  else window.localStorage.removeItem(DEV_USER_STORAGE_KEY);
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: Parameters<typeof fetch>[1]): Promise<T> {
  const headers = new globalThis.Headers(init?.headers);
  headers.set('Accept', 'application/json');
  // This header is intentionally added only by the development user picker.
  // Production authentication belongs at the API boundary, never in this UI.
  const devUserId = getDevUserId();
  if (devUserId) headers.set('x-dev-user-id', devUserId);

  let response: Awaited<ReturnType<typeof fetch>>;
  try {
    response = await fetch(`${apiBaseUrl()}${path}`, { ...init, headers });
  } catch (error) {
    throw new ApiError(0, error instanceof Error ? error.message : 'Network request failed');
  }

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { error?: string; message?: string };
      message = body.error ?? body.message ?? message;
    } catch {
      // Keep the truthful status when the server did not return JSON.
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function normaliseIncidentList(payload: Incident[] | IncidentListResponse): IncidentListResponse {
  if (Array.isArray(payload)) return { incidents: payload };
  return { incidents: payload.incidents ?? [], next_cursor: payload.next_cursor ?? null };
}

export const commandApi = {
  listIncidents: async (): Promise<IncidentListResponse> =>
    // Keep contained incidents in the workspace so the operator can complete
    // the server-enforced open -> contained -> closed lifecycle.
    normaliseIncidentList(await request<Incident[] | IncidentListResponse>('/api/v1/incidents')),

  getIncident: (id: string): Promise<Incident> => request<Incident>(`/api/v1/incidents/${encodeURIComponent(id)}`),

  listPresence: (): Promise<PresenceResponse> => request<PresenceResponse>('/api/v1/presence'),

  acknowledgeTask: (incidentId: string, taskId: string): Promise<Incident> =>
    request<Incident>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/tasks/${encodeURIComponent(taskId)}/ack`, {
      method: 'POST',
    }),

  transitionIncident: (incidentId: string, status: 'contained' | 'closed', closureReason?: string): Promise<Incident> =>
    request<Incident>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/transition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, ...(closureReason ? { closure_reason: closureReason } : {}) }),
    }),

  closeIncident: (incidentId: string, closureReason: string): Promise<Incident> =>
    commandApi.transitionIncident(incidentId, 'closed', closureReason),

  readiness: async (): Promise<{ status: string }> => request<{ status: string }>('/health/ready'),
};

export { request as apiRequest };
