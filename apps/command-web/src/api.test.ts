import { beforeEach, describe, expect, it, vi } from 'vitest';
import { commandApi, setDevUserId } from './api';
import { queueQueryKey } from './App';

describe('command API adapter', () => {
  beforeEach(() => { vi.restoreAllMocks(); setDevUserId('operator-a'); });

  it('calls lifecycle transitions with server status and mandatory close reason', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 'inc-1' }) });
    vi.stubGlobal('fetch', fetchMock);
    await commandApi.transitionIncident('inc-1', 'contained');
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/incidents/inc-1/transition');
    expect(JSON.parse((fetchMock.mock.calls[0]?.[1] as { body: string }).body)).toEqual({ status: 'contained' });
    await commandApi.closeIncident('inc-1', 'No further threat');
    expect(JSON.parse((fetchMock.mock.calls[1]?.[1] as { body: string }).body)).toEqual({ status: 'closed', closure_reason: 'No further threat' });
  });

  it('does not change delivery state locally when acknowledgement is requested', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 'inc-1', tasks: [{ id: 'task-1', delivery_state: 'ACKNOWLEDGED' }] }) });
    vi.stubGlobal('fetch', fetchMock);
    const response = await commandApi.acknowledgeTask('inc-1', 'task-1');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/incidents/inc-1/tasks/task-1/ack', expect.objectContaining({ method: 'POST' }));
    expect(response.tasks?.[0]?.delivery_state).toBe('ACKNOWLEDGED');
  });

  it('keeps user-scoped query caches distinct when switching organisations', () => {
    expect(queueQueryKey('user-org-a')).not.toEqual(queueQueryKey('user-org-b'));
  });
});
