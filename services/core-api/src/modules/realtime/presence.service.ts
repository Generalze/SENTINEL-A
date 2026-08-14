import { Inject, Injectable, Logger } from '@nestjs/common';
import { PresenceRedisClient } from './presence-redis.client';
import { PRESENCE_KEY_PREFIX } from './realtime.constants';

/** One organisation's presence hash field value (deliverable #4). */
export interface PresenceEntry {
  readonly user_id: string;
  readonly connected_at: string;
  readonly sockets: number;
}

function presenceKey(organisationId: string): string {
  return `${PRESENCE_KEY_PREFIX}${organisationId}`;
}

function parseEntry(raw: string, userId: string): PresenceEntry {
  try {
    const parsed = JSON.parse(raw) as Partial<PresenceEntry>;
    return {
      user_id: userId,
      connected_at: typeof parsed.connected_at === 'string' ? parsed.connected_at : new Date().toISOString(),
      sockets: typeof parsed.sockets === 'number' && parsed.sockets > 0 ? parsed.sockets : 1,
    };
  } catch {
    // Corrupt/foreign value in the hash — treat as a single, freshly-seen socket rather than fail the caller.
    return { user_id: userId, connected_at: new Date().toISOString(), sockets: 1 };
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Deliverable #4: in-Redis presence, keyed `sentinel:presence:{organisation_id}`
 * (a hash of `user_id -> JSON {connected_at, sockets}`). Multiple sockets
 * for the same user increment/decrement `sockets`; the user only leaves
 * the hash entirely once their last socket disconnects. Every method
 * degrades gracefully on a Redis error (deliverable #5): logs a warning
 * and returns a safe default rather than throwing, so a Redis outage never
 * prevents a socket from connecting/disconnecting — presence is simply not
 * tracked while it's down.
 */
@Injectable()
export class PresenceService {
  private readonly logger = new Logger(PresenceService.name);

  constructor(@Inject(PresenceRedisClient) private readonly redis: PresenceRedisClient) {}

  /** Returns true iff this connect transitioned the user from offline to online (their first live socket). */
  async recordConnect(organisationId: string, userId: string): Promise<boolean> {
    if (!this.redis.isConfigured()) {
      return false;
    }
    try {
      const client = this.redis.getClient();
      const key = presenceKey(organisationId);
      const existingRaw = await client.hget(key, userId);
      if (!existingRaw) {
        const entry: PresenceEntry = { user_id: userId, connected_at: new Date().toISOString(), sockets: 1 };
        await client.hset(key, userId, JSON.stringify(entry));
        return true;
      }
      const existing = parseEntry(existingRaw, userId);
      const updated: PresenceEntry = { ...existing, sockets: existing.sockets + 1 };
      await client.hset(key, userId, JSON.stringify(updated));
      return false;
    } catch (error) {
      this.logger.warn(`presence recordConnect degraded (redis error, org=${organisationId}): ${errorMessage(error)}`);
      return false;
    }
  }

  /** Returns true iff this disconnect transitioned the user from online to fully offline (their last live socket). */
  async recordDisconnect(organisationId: string, userId: string): Promise<boolean> {
    if (!this.redis.isConfigured()) {
      return false;
    }
    try {
      const client = this.redis.getClient();
      const key = presenceKey(organisationId);
      const existingRaw = await client.hget(key, userId);
      if (!existingRaw) {
        return false;
      }
      const existing = parseEntry(existingRaw, userId);
      if (existing.sockets <= 1) {
        await client.hdel(key, userId);
        return true;
      }
      const updated: PresenceEntry = { ...existing, sockets: existing.sockets - 1 };
      await client.hset(key, userId, JSON.stringify(updated));
      return false;
    } catch (error) {
      this.logger.warn(`presence recordDisconnect degraded (redis error, org=${organisationId}): ${errorMessage(error)}`);
      return false;
    }
  }

  /** Deliverable #4: `GET /api/v1/presence`'s data source. */
  async list(organisationId: string): Promise<PresenceEntry[]> {
    if (!this.redis.isConfigured()) {
      return [];
    }
    try {
      const client = this.redis.getClient();
      const all = await client.hgetall(presenceKey(organisationId));
      return Object.entries(all).map(([userId, raw]) => parseEntry(raw, userId));
    } catch (error) {
      this.logger.warn(`presence list degraded (redis error, org=${organisationId}): ${errorMessage(error)}`);
      return [];
    }
  }
}
