import { io, type Socket } from 'socket.io-client';
import { apiBaseUrl, getDevUserId } from './api';
import type { RealtimeUpdate } from './types';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected';

export function createCommandSocket(
  onState: (state: ConnectionState) => void,
  onIncidentUpdated: (payload: RealtimeUpdate) => void,
  onHypothesisUpdated: (payload: RealtimeUpdate) => void,
  onPresenceChanged?: () => void,
): Socket {
  const socket = io(apiBaseUrl() || (typeof window === 'undefined' ? undefined : window.location.origin), {
    path: '/ws',
    transports: ['websocket'],
    auth: { userId: getDevUserId() },
    autoConnect: true,
  });

  socket.on('connect', () => onState('connected'));
  socket.on('disconnect', () => onState('disconnected'));
  socket.on('connect_error', () => onState('disconnected'));
  socket.on('incident.updated', onIncidentUpdated);
  socket.on('hypothesis.updated', onHypothesisUpdated);
  socket.on('presence.changed', onPresenceChanged ?? (() => undefined));
  return socket;
}
