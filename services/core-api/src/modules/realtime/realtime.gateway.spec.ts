import { describe, expect, it, vi } from 'vitest';
import type { AppConfigService } from '../../config/config.service';
import type { PrismaService } from '../../prisma/prisma.service';
import { PresenceService } from './presence.service';
import { RealtimeGateway } from './realtime.gateway';
import { orgRoom, WS_EVENT_PRESENCE_CHANGED } from './realtime.constants';

function fakeConfig(devAuthEnabled: boolean): AppConfigService {
  return { values: { DEV_AUTH_ENABLED: devAuthEnabled } } as unknown as AppConfigService;
}

function fakePrisma(user: unknown): PrismaService {
  return { user: { findUnique: vi.fn().mockResolvedValue(user) } } as unknown as PrismaService;
}

function fakePresence(overrides: Partial<Record<keyof PresenceService, unknown>> = {}): PresenceService {
  return {
    recordConnect: vi.fn().mockResolvedValue(false),
    recordDisconnect: vi.fn().mockResolvedValue(false),
    list: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as unknown as PresenceService;
}

interface FakeSocket {
  id: string;
  handshake: { auth: Record<string, unknown>; headers: Record<string, string | string[] | undefined> };
  data: { principal?: unknown };
  join: ReturnType<typeof vi.fn>;
  disconnect: ReturnType<typeof vi.fn>;
}

function fakeSocket(auth: Record<string, unknown> = {}, headers: Record<string, string> = {}): FakeSocket {
  return {
    id: `socket_${Math.random().toString(36).slice(2)}`,
    handshake: { auth, headers },
    data: {},
    join: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(),
  };
}

/**
 * Drives the gateway's real production auth path: `afterInit` registers a
 * `server.use(...)` middleware, so this captures that middleware off a
 * fake server and runs it against `socket`, resolving with whatever
 * `next(...)` was called with (undefined = accepted).
 */
async function runHandshakeMiddleware(gateway: RealtimeGateway, socket: FakeSocket): Promise<Error | undefined> {
  let captured: ((socket: unknown, next: (error?: Error) => void) => void) | undefined;
  const fakeServer = { use: (fn: typeof captured) => { captured = fn; } };
  gateway.afterInit(fakeServer as never);

  return new Promise((resolve) => {
    captured?.(socket, (error?: Error) => resolve(error));
  });
}

describe('RealtimeGateway — handshake auth (deliverable #2, auth boundary)', () => {
  it('rejects every connection when DEV_AUTH_ENABLED is not true, even with a well-formed user id', async () => {
    const gateway = new RealtimeGateway(fakePrisma({ id: 'user_1', organisationId: 'org_1', roles: [] }), fakeConfig(false), fakePresence());
    const socket = fakeSocket({ userId: 'user_1' });

    const error = await runHandshakeMiddleware(gateway, socket);

    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toMatch(/DEV_AUTH_ENABLED/);
    expect(socket.data.principal).toBeUndefined();
  });

  it('rejects a connection with no user id anywhere in the handshake', async () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    const socket = fakeSocket({}, {});

    const error = await runHandshakeMiddleware(gateway, socket);

    expect(error).toBeInstanceOf(Error);
    expect(socket.data.principal).toBeUndefined();
  });

  it('rejects a connection for a user id that does not resolve to a real user', async () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    const socket = fakeSocket({ userId: 'ghost' });

    const error = await runHandshakeMiddleware(gateway, socket);

    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toMatch(/Unknown dev user/);
    expect(socket.data.principal).toBeUndefined();
  });

  it('accepts a known user id via handshake.auth.userId and attaches the principal to socket.data', async () => {
    const gateway = new RealtimeGateway(
      fakePrisma({ id: 'user_1', organisationId: 'org_1', roles: [{ role: 'operator' }] }),
      fakeConfig(true),
      fakePresence(),
    );
    const socket = fakeSocket({ userId: 'user_1' });

    const error = await runHandshakeMiddleware(gateway, socket);

    expect(error).toBeUndefined();
    expect(socket.data.principal).toEqual({ user_id: 'user_1', organisation_id: 'org_1', roles: ['operator'] });
  });

  it('falls back to the x-dev-user-id header when handshake.auth.userId is absent', async () => {
    const gateway = new RealtimeGateway(fakePrisma({ id: 'user_2', organisationId: 'org_2', roles: [] }), fakeConfig(true), fakePresence());
    const socket = fakeSocket({}, { 'x-dev-user-id': 'user_2' });

    const error = await runHandshakeMiddleware(gateway, socket);

    expect(error).toBeUndefined();
    expect(socket.data.principal).toEqual({ user_id: 'user_2', organisation_id: 'org_2', roles: [] });
  });

  it('prefers handshake.auth.userId over the header when both are present', async () => {
    const gateway = new RealtimeGateway(fakePrisma({ id: 'user_1', organisationId: 'org_1', roles: [] }), fakeConfig(true), fakePresence());
    const socket = fakeSocket({ userId: 'user_1' }, { 'x-dev-user-id': 'user_2' });

    await runHandshakeMiddleware(gateway, socket);

    expect(socket.data.principal).toMatchObject({ user_id: 'user_1' });
  });
});

describe('RealtimeGateway — room selection and presence broadcast (deliverables #2/#4)', () => {
  it('joins exactly the org room derived from the server-loaded principal, never from client input', async () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    gateway.server = { to: vi.fn().mockReturnValue({ emit: vi.fn() }), use: vi.fn() } as never;

    const socket = fakeSocket();
    socket.data.principal = { user_id: 'user_1', organisation_id: 'org_1', roles: [] };

    await gateway.handleConnection(socket as never);

    expect(socket.join).toHaveBeenCalledTimes(1);
    expect(socket.join).toHaveBeenCalledWith(orgRoom('org_1'));
  });

  it('disconnects a socket that somehow reaches handleConnection with no principal (defence in depth)', async () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    const socket = fakeSocket();

    await gateway.handleConnection(socket as never);

    expect(socket.disconnect).toHaveBeenCalledWith(true);
    expect(socket.join).not.toHaveBeenCalled();
  });

  it('broadcasts presence.changed(online:true) to the org room when the user just came online', async () => {
    const presence = fakePresence({ recordConnect: vi.fn().mockResolvedValue(true) });
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), presence);
    const emit = vi.fn();
    const to = vi.fn().mockReturnValue({ emit });
    gateway.server = { to, use: vi.fn() } as never;

    const socket = fakeSocket();
    socket.data.principal = { user_id: 'user_1', organisation_id: 'org_1', roles: [] };

    await gateway.handleConnection(socket as never);

    expect(presence.recordConnect).toHaveBeenCalledWith('org_1', 'user_1');
    expect(to).toHaveBeenCalledWith(orgRoom('org_1'));
    expect(emit).toHaveBeenCalledWith(WS_EVENT_PRESENCE_CHANGED, { user_id: 'user_1', online: true });
  });

  it('does not broadcast on connect when the user was already online (a second socket for the same user)', async () => {
    const presence = fakePresence({ recordConnect: vi.fn().mockResolvedValue(false) });
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), presence);
    const emit = vi.fn();
    gateway.server = { to: vi.fn().mockReturnValue({ emit }), use: vi.fn() } as never;

    const socket = fakeSocket();
    socket.data.principal = { user_id: 'user_1', organisation_id: 'org_1', roles: [] };

    await gateway.handleConnection(socket as never);

    expect(emit).not.toHaveBeenCalled();
  });

  it('broadcasts presence.changed(online:false) only once the user goes fully offline (last socket)', async () => {
    const presence = fakePresence({ recordDisconnect: vi.fn().mockResolvedValue(true) });
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), presence);
    const emit = vi.fn();
    gateway.server = { to: vi.fn().mockReturnValue({ emit }), use: vi.fn() } as never;

    const socket = fakeSocket();
    socket.data.principal = { user_id: 'user_1', organisation_id: 'org_1', roles: [] };

    await gateway.handleDisconnect(socket as never);

    expect(presence.recordDisconnect).toHaveBeenCalledWith('org_1', 'user_1');
    expect(emit).toHaveBeenCalledWith(WS_EVENT_PRESENCE_CHANGED, { user_id: 'user_1', online: false });
  });

  it('does not broadcast on disconnect when the user still has other live sockets', async () => {
    const presence = fakePresence({ recordDisconnect: vi.fn().mockResolvedValue(false) });
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), presence);
    const emit = vi.fn();
    gateway.server = { to: vi.fn().mockReturnValue({ emit }), use: vi.fn() } as never;

    const socket = fakeSocket();
    socket.data.principal = { user_id: 'user_1', organisation_id: 'org_1', roles: [] };

    await gateway.handleDisconnect(socket as never);

    expect(emit).not.toHaveBeenCalled();
  });

  it('handleDisconnect is a no-op when the socket never had a principal', async () => {
    const presence = fakePresence();
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), presence);

    await gateway.handleDisconnect(fakeSocket() as never);

    expect(presence.recordDisconnect).not.toHaveBeenCalled();
  });
});

describe('RealtimeGateway#broadcastToOrg', () => {
  it('never throws when the socket.io server is not yet initialised (deliverable #5)', () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    expect(() => gateway.broadcastToOrg('org_1', 'incident.updated', { id: 'x' })).not.toThrow();
  });

  it('emits to exactly org:{organisationId} and nowhere else', () => {
    const gateway = new RealtimeGateway(fakePrisma(null), fakeConfig(true), fakePresence());
    const emit = vi.fn();
    const to = vi.fn().mockReturnValue({ emit });
    gateway.server = { to, use: vi.fn() } as never;

    gateway.broadcastToOrg('org_42', 'incident.updated', { id: 'inc_1' });

    expect(to).toHaveBeenCalledTimes(1);
    expect(to).toHaveBeenCalledWith('org:org_42');
    expect(emit).toHaveBeenCalledWith('incident.updated', { id: 'inc_1' });
  });
});
