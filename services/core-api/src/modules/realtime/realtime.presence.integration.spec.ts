import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import Redis from 'ioredis';
import type { INestApplication } from '@nestjs/common';
import type { PrismaService } from '../../prisma/prisma.service';
import { PRESENCE_KEY_PREFIX, WS_EVENT_PRESENCE_CHANGED, WS_PATH } from './realtime.constants';
import {
  bootstrapRealtimeApp,
  cleanupOrgsAndUsers,
  LIVE_STACK_ENV,
  makeOrgAndUser,
  waitForEvent,
  withLiveStackEnv,
  type TestOrgUser,
} from './test-integration-support';

interface PresenceEntry {
  user_id: string;
  connected_at: string;
  sockets: number;
}

interface PresenceListResponse {
  organisation_id: string;
  presence: PresenceEntry[];
}

/** Acceptance criterion #4 (WP-12): presence add/remove reflected in Redis, the HTTP endpoint, and the presence.changed broadcast. */
describe('Realtime gateway — presence add/remove (live stack, AC4)', () => {
  let restoreEnv: () => void;
  let app: INestApplication;
  let baseUrl: string;
  let prisma: PrismaService;
  let redis: Redis;
  let org: TestOrgUser;
  let observerUser: TestOrgUser;
  const openSockets: ClientSocket[] = [];

  beforeAll(async () => {
    restoreEnv = withLiveStackEnv();
    ({ app, baseUrl, prisma } = await bootstrapRealtimeApp());
    org = await makeOrgAndUser(prisma, 'presence');
    observerUser = await makeOrgAndUser(prisma, 'presence-observer');
    // Same org as `org` so the observer socket sits in the same room and can witness the broadcast.
    await prisma.user.update({ where: { id: observerUser.userId }, data: { organisationId: org.organisationId } });
    redis = new Redis(LIVE_STACK_ENV.REDIS_URL);
  }, 30_000);

  afterEach(() => {
    for (const socket of openSockets.splice(0)) {
      socket.close();
    }
  });

  afterAll(async () => {
    await redis.del(`${PRESENCE_KEY_PREFIX}${org.organisationId}`);
    redis.disconnect();
    await cleanupOrgsAndUsers(prisma, [org.organisationId, observerUser.organisationId]);
    await app.close();
    restoreEnv();
  });

  function connectAs(userId: string): ClientSocket {
    const socket = io(baseUrl, {
      path: WS_PATH,
      transports: ['websocket'],
      reconnection: false,
      forceNew: true,
      auth: { userId },
    });
    openSockets.push(socket);
    return socket;
  }

  async function fetchPresence(organisationId: string): Promise<PresenceListResponse> {
    const response = await fetch(`${baseUrl}/api/v1/presence?organisation_id=${encodeURIComponent(organisationId)}`);
    expect(response.status).toBe(200);
    return (await response.json()) as PresenceListResponse;
  }

  it('connect adds the user to Redis + the endpoint and broadcasts presence.changed(online:true); disconnect reverses all three', async () => {
    const observer = connectAs(observerUser.userId);
    await waitForEvent(observer, 'connect');
    // The observer's own connect also broadcasts presence.changed(online:true)
    // to the org room it just joined — including back to itself (broadcastToOrg
    // has no "except sender" special case, by design: it's the same single path
    // the NATS bridge uses, where there is no "sender" socket at all). Drain
    // that self-event first so the listener below can only match the subject's.
    await waitForEvent(observer, WS_EVENT_PRESENCE_CHANGED);

    const onlineBroadcast = waitForEvent<{ user_id: string; online: boolean }>(observer, WS_EVENT_PRESENCE_CHANGED);
    const subject = connectAs(org.userId);
    await waitForEvent(subject, 'connect');

    // 1. presence.changed broadcast.
    await expect(onlineBroadcast).resolves.toEqual({ user_id: org.userId, online: true });

    // 2. Redis directly.
    const redisRaw = await redis.hget(`${PRESENCE_KEY_PREFIX}${org.organisationId}`, org.userId);
    expect(redisRaw).not.toBeNull();
    const redisEntry = JSON.parse(redisRaw ?? '{}') as { sockets: number; connected_at: string };
    expect(redisEntry.sockets).toBe(1);
    expect(typeof redisEntry.connected_at).toBe('string');

    // 3. GET /api/v1/presence. The observer itself is also connected (same
    // org), so the list has both entries — assert the subject's specifically.
    // Same connect-vs-record race as the two-socket test below: poll rather
    // than assume the endpoint sees the subject the instant it is connected.
    const afterConnect = await presenceEventually(org.organisationId, (entries) => entries.length === 2);
    expect(afterConnect).toHaveLength(2);
    expect(afterConnect).toEqual(expect.arrayContaining([expect.objectContaining({ user_id: org.userId, sockets: 1 })]));

    // Now disconnect and verify all three reverse.
    const offlineBroadcast = waitForEvent<{ user_id: string; online: boolean }>(observer, WS_EVENT_PRESENCE_CHANGED);
    subject.close();
    await expect(offlineBroadcast).resolves.toEqual({ user_id: org.userId, online: false });

    const redisRawAfter = await redis.hget(`${PRESENCE_KEY_PREFIX}${org.organisationId}`, org.userId);
    expect(redisRawAfter).toBeNull();

    // Only the observer (still connected) remains.
    const afterDisconnect = await fetchPresence(org.organisationId);
    expect(afterDisconnect.presence).toEqual([expect.objectContaining({ user_id: observerUser.userId })]);
  }, 10_000);

  /**
   * A client's `connect` event fires when the handshake completes, which is
   * strictly BEFORE the server's `handleConnection` has finished recording
   * presence in Redis. Asserting the presence endpoint immediately after
   * `connect` therefore races the server, and did intermittently fail. Polls
   * until the server-side state converges (or the deadline passes, so a real
   * regression still fails rather than hanging) instead of assuming the two
   * are synchronous, and replaces the fixed sleep the disconnect half used.
   */
  async function presenceEventually(organisationId: string, predicate: (entries: PresenceEntry[]) => boolean, timeoutMs = 4000): Promise<PresenceEntry[]> {
    const deadline = Date.now() + timeoutMs;
    let latest: PresenceEntry[] = [];
    for (;;) {
      latest = (await fetchPresence(organisationId)).presence;
      if (predicate(latest)) return latest;
      if (Date.now() >= deadline) return latest;
      await new Promise((resolve) => {
        setTimeout(resolve, 50);
      });
    }
  }

  it('a second socket for the same user increments the Redis/endpoint socket count and does not double-broadcast online', async () => {
    const first = connectAs(org.userId);
    await waitForEvent(first, 'connect');

    const second = connectAs(org.userId);
    await waitForEvent(second, 'connect');

    const list = await presenceEventually(org.organisationId, (entries) => entries.some((entry) => entry.sockets === 2));
    expect(list).toEqual([expect.objectContaining({ user_id: org.userId, sockets: 2 })]);

    first.close();

    const listAfterOneClose = await presenceEventually(org.organisationId, (entries) => entries.some((entry) => entry.sockets === 1));
    expect(listAfterOneClose).toEqual([expect.objectContaining({ user_id: org.userId, sockets: 1 })]);

    second.close();
  }, 15_000);

  it('GET /api/v1/presence requires organisation_id when no principal is present (dev bypass)', async () => {
    const response = await fetch(`${baseUrl}/api/v1/presence`);
    expect(response.status).toBe(400);
  });
});
