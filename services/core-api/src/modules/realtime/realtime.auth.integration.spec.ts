import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import type { INestApplication } from '@nestjs/common';
import type { PrismaService } from '../../prisma/prisma.service';
import { WS_PATH } from './realtime.constants';
import {
  bootstrapRealtimeApp,
  cleanupOrgsAndUsers,
  makeOrgAndUser,
  waitForEvent,
  withLiveStackEnv,
  type TestOrgUser,
} from './test-integration-support';

/**
 * Acceptance criterion #2 (WP-12): "Unauthenticated connect rejected."
 * Exercised against a real bootstrapped app (live Postgres/NATS/Redis) on
 * an ephemeral port, using the real socket.io-client library — this is
 * the actual production auth path (server.use(...) handshake middleware
 * in realtime.gateway.ts), not a unit-level stand-in.
 */
describe('Realtime gateway — unauthenticated connect rejected (live stack, AC2)', () => {
  let restoreEnv: () => void;
  let app: INestApplication;
  let baseUrl: string;
  let prisma: PrismaService;
  let validUser: TestOrgUser;
  const openSockets: ClientSocket[] = [];

  beforeAll(async () => {
    restoreEnv = withLiveStackEnv();
    ({ app, baseUrl, prisma } = await bootstrapRealtimeApp());
    validUser = await makeOrgAndUser(prisma, 'auth');
  }, 30_000);

  afterEach(() => {
    for (const socket of openSockets.splice(0)) {
      socket.close();
    }
  });

  afterAll(async () => {
    await cleanupOrgsAndUsers(prisma, [validUser.organisationId]);
    await app.close();
    restoreEnv();
  });

  function connect(options: { auth?: Record<string, unknown>; extraHeaders?: Record<string, string> }): ClientSocket {
    const socket = io(baseUrl, {
      path: WS_PATH,
      transports: ['websocket'],
      reconnection: false,
      forceNew: true,
      auth: options.auth ?? {},
      extraHeaders: options.extraHeaders,
    });
    openSockets.push(socket);
    return socket;
  }

  it('rejects a connection with no user id supplied at all', async () => {
    const socket = connect({});
    const error = await waitForEvent<Error>(socket, 'connect_error');
    expect(error).toBeDefined();
    expect(socket.connected).toBe(false);
  });

  it('rejects a connection for a user id that does not exist', async () => {
    const socket = connect({ auth: { userId: 'this-user-does-not-exist' } });
    const error = await waitForEvent<Error>(socket, 'connect_error');
    expect(error).toBeDefined();
    expect(socket.connected).toBe(false);
  });

  it('accepts a connection for a real, known user (control case proving the rejections above are meaningful)', async () => {
    const socket = connect({ auth: { userId: validUser.userId } });
    await waitForEvent(socket, 'connect');
    expect(socket.connected).toBe(true);
  });

  it('accepts a connection authenticated via the x-dev-user-id header instead of handshake.auth', async () => {
    const socket = connect({ extraHeaders: { 'x-dev-user-id': validUser.userId } });
    await waitForEvent(socket, 'connect');
    expect(socket.connected).toBe(true);
  });
});
