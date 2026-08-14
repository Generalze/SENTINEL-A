import { describe, expect, it, vi } from 'vitest';
import type { PresenceRedisClient } from './presence-redis.client';
import { PresenceService } from './presence.service';

interface FakeHash {
  [userId: string]: string;
}

/**
 * A minimal in-memory stand-in for the ioredis commands PresenceService
 * uses, keyed by the actual Redis key (so different organisations —
 * different `sentinel:presence:{organisation_id}` keys — never share
 * state, exactly like real Redis).
 */
function fakeRedisClient(): { client: PresenceRedisClient; hashes: Record<string, FakeHash> } {
  const hashes: Record<string, FakeHash> = {};
  const hashFor = (key: string): FakeHash => (hashes[key] ??= {});
  const raw = {
    hget: vi.fn((key: string, field: string) => Promise.resolve(hashFor(key)[field] ?? null)),
    hset: vi.fn((key: string, field: string, value: string) => {
      hashFor(key)[field] = value;
      return Promise.resolve(1);
    }),
    hdel: vi.fn((key: string, field: string) => {
      const existed = field in hashFor(key);
      delete hashFor(key)[field];
      return Promise.resolve(existed ? 1 : 0);
    }),
    hgetall: vi.fn((key: string) => Promise.resolve({ ...hashFor(key) })),
  };
  const client = {
    isConfigured: () => true,
    getClient: () => raw,
  } as unknown as PresenceRedisClient;
  return { client, hashes };
}

describe('PresenceService — connect/disconnect counting (deliverable #4)', () => {
  it('a first connect creates the hash entry with sockets=1 and returns true (went online)', async () => {
    const { client, hashes } = fakeRedisClient();
    const service = new PresenceService(client);

    const wentOnline = await service.recordConnect('org_1', 'user_1');

    expect(wentOnline).toBe(true);
    const entry = JSON.parse(hashes['sentinel:presence:org_1']?.user_1 ?? '{}') as { sockets: number };
    expect(entry.sockets).toBe(1);
  });

  it('a second socket for the same user increments sockets and does not report "went online" again', async () => {
    const { client } = fakeRedisClient();
    const service = new PresenceService(client);

    await service.recordConnect('org_1', 'user_1');
    const wentOnlineAgain = await service.recordConnect('org_1', 'user_1');

    expect(wentOnlineAgain).toBe(false);
    const list = await service.list('org_1');
    expect(list).toEqual([expect.objectContaining({ user_id: 'user_1', sockets: 2 })]);
  });

  it('disconnecting one of two sockets decrements but keeps the user online (no "went offline")', async () => {
    const { client } = fakeRedisClient();
    const service = new PresenceService(client);
    await service.recordConnect('org_1', 'user_1');
    await service.recordConnect('org_1', 'user_1');

    const wentOffline = await service.recordDisconnect('org_1', 'user_1');

    expect(wentOffline).toBe(false);
    const list = await service.list('org_1');
    expect(list).toEqual([expect.objectContaining({ user_id: 'user_1', sockets: 1 })]);
  });

  it('disconnecting the last socket removes the hash entry and reports "went offline"', async () => {
    const { client } = fakeRedisClient();
    const service = new PresenceService(client);
    await service.recordConnect('org_1', 'user_1');

    const wentOffline = await service.recordDisconnect('org_1', 'user_1');

    expect(wentOffline).toBe(true);
    expect(await service.list('org_1')).toEqual([]);
  });

  it('disconnecting a user with no recorded presence is a safe no-op', async () => {
    const { client } = fakeRedisClient();
    const service = new PresenceService(client);

    const wentOffline = await service.recordDisconnect('org_1', 'never-connected');

    expect(wentOffline).toBe(false);
  });

  it('keeps organisations isolated from each other', async () => {
    const { client } = fakeRedisClient();
    const service = new PresenceService(client);

    await service.recordConnect('org_A', 'user_1');
    await service.recordConnect('org_B', 'user_2');

    expect(await service.list('org_A')).toEqual([expect.objectContaining({ user_id: 'user_1' })]);
    expect(await service.list('org_B')).toEqual([expect.objectContaining({ user_id: 'user_2' })]);
  });
});

describe('PresenceService — degradation (deliverable #5)', () => {
  it('recordConnect degrades gracefully (returns false, never throws) on a Redis error', async () => {
    const client = {
      isConfigured: () => true,
      getClient: () => ({
        hget: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
      }),
    } as unknown as PresenceRedisClient;
    const service = new PresenceService(client);

    await expect(service.recordConnect('org_1', 'user_1')).resolves.toBe(false);
  });

  it('recordDisconnect degrades gracefully on a Redis error', async () => {
    const client = {
      isConfigured: () => true,
      getClient: () => ({
        hget: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
      }),
    } as unknown as PresenceRedisClient;
    const service = new PresenceService(client);

    await expect(service.recordDisconnect('org_1', 'user_1')).resolves.toBe(false);
  });

  it('list degrades to an empty array on a Redis error', async () => {
    const client = {
      isConfigured: () => true,
      getClient: () => ({
        hgetall: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
      }),
    } as unknown as PresenceRedisClient;
    const service = new PresenceService(client);

    await expect(service.list('org_1')).resolves.toEqual([]);
  });

  it('every method short-circuits to a safe default when Redis is not configured at all', async () => {
    const client = { isConfigured: () => false, getClient: vi.fn() } as unknown as PresenceRedisClient;
    const service = new PresenceService(client);

    await expect(service.recordConnect('org_1', 'user_1')).resolves.toBe(false);
    await expect(service.recordDisconnect('org_1', 'user_1')).resolves.toBe(false);
    await expect(service.list('org_1')).resolves.toEqual([]);
    expect(client.getClient).not.toHaveBeenCalled();
  });
});
