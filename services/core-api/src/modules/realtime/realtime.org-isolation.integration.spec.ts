import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { JSONCodec, type NatsConnection } from 'nats';
import type { INestApplication } from '@nestjs/common';
import type { PrismaService } from '../../prisma/prisma.service';
import type { NatsProvider } from '../../infra/nats.provider';
import { WS_EVENT_HYPOTHESIS_UPDATED, WS_EVENT_INCIDENT_UPDATED, WS_PATH } from './realtime.constants';
import {
  assertNoEvent,
  bootstrapRealtimeApp,
  cleanupOrgsAndUsers,
  makeOrgAndUser,
  publishUntilReceived,
  waitForEvent,
  withLiveStackEnv,
  type TestOrgUser,
} from './test-integration-support';

/**
 * Acceptance criterion #1 (org isolation) and the whitelist-enforcement
 * criterion from WP-12's coordination note, both against the live stack
 * (real Postgres for principal loading, real NATS for the bridge, a real
 * socket.io-client per org).
 */
describe('Realtime gateway — org isolation + whitelist enforcement (live stack, AC1)', () => {
  let restoreEnv: () => void;
  let app: INestApplication;
  let baseUrl: string;
  let prisma: PrismaService;
  let natsProvider: NatsProvider;
  let nc: NatsConnection;
  let orgA: TestOrgUser;
  let orgB: TestOrgUser;
  const openSockets: ClientSocket[] = [];
  const jsonCodec = JSONCodec();

  beforeAll(async () => {
    restoreEnv = withLiveStackEnv();
    ({ app, baseUrl, prisma, natsProvider } = await bootstrapRealtimeApp());
    [orgA, orgB] = await Promise.all([makeOrgAndUser(prisma, 'iso-a'), makeOrgAndUser(prisma, 'iso-b')]);
    // Reuse the app's own NatsProvider connection to publish test messages
    // rather than opening a second one (see BootstrappedApp's doc comment on
    // `natsProvider`).
    nc = await natsProvider.getConnection();
    // No fixed sleep here any more. Waiting a guessed interval for the
    // bridge's background subscriptions to register is exactly the
    // "instantaneous assumption" that made this hook flaky; the tests below
    // republish until delivery instead (`publishUntilReceived`), which
    // converges on a slow machine and costs nothing on a fast one.
  }, 30_000);

  afterEach(() => {
    for (const socket of openSockets.splice(0)) {
      socket.close();
    }
  });

  afterAll(async () => {
    await cleanupOrgsAndUsers(prisma, [orgA.organisationId, orgB.organisationId]);
    // app.close() tears down NatsProvider (OnModuleDestroy closes `nc` for us) — don't close it ourselves.
    await app.close();
    restoreEnv();
  });

  function connectAs(user: TestOrgUser): ClientSocket {
    const socket = io(baseUrl, {
      path: WS_PATH,
      transports: ['websocket'],
      reconnection: false,
      forceNew: true,
      auth: { userId: user.userId },
    });
    openSockets.push(socket);
    return socket;
  }

  it("delivers an incident.updated event only to org A's client, never to org B's, and only whitelisted fields", async () => {
    const clientA = connectAs(orgA);
    const clientB = connectAs(orgB);
    await Promise.all([waitForEvent(clientA, 'connect'), waitForEvent(clientB, 'connect')]);

    const incidentId = 'inc_isolation_1';
    const payload = {
      id: incidentId,
      organisation_id: orgA.organisationId,
      site_id: 'site_1',
      severity: 'SEV1',
      status: 'open',
      updated_at: '2026-08-14T00:00:00.000Z',
      // Must never reach either client.
      commander_user_id: 'user_should_not_leak',
      related_event_ids: ['evt_1', 'evt_2'],
      playbook_version: 'v7',
    };

    const receivedByA = waitForEvent<Record<string, unknown>>(clientA, WS_EVENT_INCIDENT_UPDATED);
    const noneForB = assertNoEvent(clientB, WS_EVENT_INCIDENT_UPDATED, 1500);

    const delivered = publishUntilReceived(nc, `sentinel.incidents.updated.${orgA.organisationId}`, jsonCodec.encode(payload), receivedByA);

    const [received] = await Promise.all([delivered, noneForB]);

    expect(received).toEqual({
      id: incidentId,
      organisation_id: orgA.organisationId,
      site_id: 'site_1',
      severity: 'SEV1',
      status: 'open',
      updated_at: '2026-08-14T00:00:00.000Z',
    });
    expect(received).not.toHaveProperty('commander_user_id');
    expect(received).not.toHaveProperty('related_event_ids');
    expect(received).not.toHaveProperty('playbook_version');
  }, 10_000);

  it("delivers a hypothesis.updated event only to org B's client when published for org B", async () => {
    const clientA = connectAs(orgA);
    const clientB = connectAs(orgB);
    await Promise.all([waitForEvent(clientA, 'connect'), waitForEvent(clientB, 'connect')]);

    const payload = {
      hypothesis_id: 'hyp_isolation_1',
      type: 'tailgating',
      state: 3,
      updated_at: '2026-08-14T01:00:00.000Z',
      confidence_explanation: 'must never leak to a WS client',
      supporting_event_ids: ['evt_9'],
    };

    const receivedByB = waitForEvent<Record<string, unknown>>(clientB, WS_EVENT_HYPOTHESIS_UPDATED);
    const noneForA = assertNoEvent(clientA, WS_EVENT_HYPOTHESIS_UPDATED, 1500);

    const delivered = publishUntilReceived(nc, `sentinel.fusion.hypothesis.${orgB.organisationId}`, jsonCodec.encode(payload), receivedByB);

    const [received] = await Promise.all([delivered, noneForA]);

    expect(received).toEqual({
      id: 'hyp_isolation_1',
      organisation_id: orgB.organisationId,
      state: 3,
      updated_at: '2026-08-14T01:00:00.000Z',
    });
    expect(received).not.toHaveProperty('confidence_explanation');
    expect(received).not.toHaveProperty('supporting_event_ids');
    expect(received).not.toHaveProperty('type');
  }, 10_000);
});
