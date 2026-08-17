import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { JSONCodec, type NatsConnection } from 'nats';
import type { INestApplication } from '@nestjs/common';
import type { PrismaService } from '../../prisma/prisma.service';
import type { NatsProvider } from '../../infra/nats.provider';
import { WS_EVENT_FIELD_UPDATED, WS_PATH } from './realtime.constants';
import {
  assertNoEvent,
  bootstrapRealtimeApp,
  cleanupOrgsAndUsers,
  makeOrgAndUser,
  makeSite,
  makeUserWithRoles,
  sleep,
  waitForEvent,
  withLiveStackEnv,
  type TestOrgUser,
} from './test-integration-support';

/**
 * WP-17 acceptance criteria 1-5, against the live stack.
 *
 * WP-16 published Field events onto the organisation room, so every socket in
 * a tenant saw every site's Field traffic and the operative's `state` rode the
 * wire (WP-17/F1, F2). These are the regressions that prove both are closed:
 * delivery is site-scoped, organisation-wide Field authorities still see every
 * site over a single fanout path, a principal with no Field action sees
 * nothing, and the payload is a routing signal rather than a domain record.
 *
 * These assert room-fanout behaviour on a stable connection. They are not — and
 * cannot be — a transport exactly-once claim: the socket is a signal and REST
 * remains authoritative.
 */
describe('Realtime Field delivery — site scoping and need-to-know (live stack, WP-17 AC1-AC5)', () => {
  let restoreEnv: () => void;
  let app: INestApplication;
  let baseUrl: string;
  let prisma: PrismaService;
  let natsProvider: NatsProvider;
  let nc: NatsConnection;

  let orgA: string;
  let orgB: string;
  let siteA1: string;
  let siteA2: string;
  let operativeA1: TestOrgUser;
  let operativeA2: TestOrgUser;
  let dispatcherOrgWide: TestOrgUser;
  let custodianA1: TestOrgUser;
  let operativeB: TestOrgUser;

  const openSockets: ClientSocket[] = [];
  const jsonCodec = JSONCodec();

  beforeAll(async () => {
    restoreEnv = withLiveStackEnv();
    ({ app, baseUrl, prisma, natsProvider } = await bootstrapRealtimeApp());

    // makeOrgAndUser gives us the two tenants (its user is unused here; the
    // role-carrying fixtures below are what the room derivation reads).
    const [tenantA, tenantB] = await Promise.all([makeOrgAndUser(prisma, 'wp17-a'), makeOrgAndUser(prisma, 'wp17-b')]);
    orgA = tenantA.organisationId;
    orgB = tenantB.organisationId;

    [siteA1, siteA2] = await Promise.all([makeSite(prisma, orgA, 'a1'), makeSite(prisma, orgA, 'a2')]);
    const siteB1 = await makeSite(prisma, orgB, 'b1');

    [operativeA1, operativeA2, dispatcherOrgWide, custodianA1, operativeB] = await Promise.all([
      makeUserWithRoles(prisma, orgA, 'op-a1', [{ role: 'field.operative', siteId: siteA1 }]),
      makeUserWithRoles(prisma, orgA, 'op-a2', [{ role: 'field.operative', siteId: siteA2 }]),
      makeUserWithRoles(prisma, orgA, 'dispatch-all', [{ role: 'dispatcher', siteId: null }]),
      makeUserWithRoles(prisma, orgA, 'custodian-a1', [{ role: 'evidence.custodian', siteId: siteA1 }]),
      makeUserWithRoles(prisma, orgB, 'op-b1', [{ role: 'field.operative', siteId: siteB1 }]),
    ]);

    nc = await natsProvider.getConnection();
    // Let the bridge's background subscriptions register before any publish
    // (same race the org-isolation spec guards against).
    await sleep(700);
  }, 45_000);

  afterEach(() => {
    for (const socket of openSockets.splice(0)) {
      socket.close();
    }
  });

  afterAll(async () => {
    await cleanupOrgsAndUsers(prisma, [orgA, orgB]);
    await app.close();
    restoreEnv();
  }, 30_000);

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

  function publishFieldEvent(organisationId: string, siteId: string, payload: Record<string, unknown>): void {
    nc.publish(`sentinel.field.updated.${organisationId}.${siteId}`, jsonCodec.encode(payload));
  }

  it('AC1/AC2: a site A1 Field event reaches the A1 operative and neither the A2 operative nor another organisation', async () => {
    const clientA1 = connectAs(operativeA1);
    const clientA2 = connectAs(operativeA2);
    const clientB = connectAs(operativeB);
    await Promise.all([waitForEvent(clientA1, 'connect'), waitForEvent(clientA2, 'connect'), waitForEvent(clientB, 'connect')]);

    const receivedByA1 = waitForEvent<Record<string, unknown>>(clientA1, WS_EVENT_FIELD_UPDATED);
    const noneForA2 = assertNoEvent(clientA2, WS_EVENT_FIELD_UPDATED, 1500);
    const noneForB = assertNoEvent(clientB, WS_EVENT_FIELD_UPDATED, 1500);

    publishFieldEvent(orgA, siteA1, {
      kind: 'FIELD_ASSIGNMENT_CREATED',
      assignment_id: 'assignment-wp17-1',
      organisation_id: orgA,
      site_id: siteA1,
    });

    const [received] = await Promise.all([receivedByA1, noneForA2, noneForB]);

    expect(received).toEqual({
      kind: 'FIELD_ASSIGNMENT_CREATED',
      assignment_id: 'assignment-wp17-1',
      organisation_id: orgA,
      site_id: siteA1,
    });
  }, 15_000);

  it('AC3: a connected principal whose roles grant no Field action receives nothing', async () => {
    const clientCustodian = connectAs(custodianA1);
    const clientA1 = connectAs(operativeA1);
    await Promise.all([waitForEvent(clientCustodian, 'connect'), waitForEvent(clientA1, 'connect')]);

    const receivedByA1 = waitForEvent(clientA1, WS_EVENT_FIELD_UPDATED);
    const noneForCustodian = assertNoEvent(clientCustodian, WS_EVENT_FIELD_UPDATED, 1500);

    publishFieldEvent(orgA, siteA1, { kind: 'FIELD_ASSIGNMENT_ACCEPTED', assignment_id: 'assignment-wp17-2' });

    await Promise.all([receivedByA1, noneForCustodian]);
  }, 15_000);

  it('AC4: an organisation-wide Field authority receives every site over a single fanout path (no duplicate room delivery)', async () => {
    const clientDispatcher = connectAs(dispatcherOrgWide);
    await waitForEvent(clientDispatcher, 'connect');

    const received: Array<Record<string, unknown>> = [];
    clientDispatcher.on(WS_EVENT_FIELD_UPDATED, (payload: Record<string, unknown>) => {
      received.push(payload);
    });

    publishFieldEvent(orgA, siteA1, { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'assignment-site-a1' });
    publishFieldEvent(orgA, siteA2, { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'assignment-site-a2' });

    // Wait past the point where a room-fanout duplicate would have arrived,
    // then assert on the whole set — a "delivered twice by room membership"
    // bug is invisible to a first-event wait. (Scope: one stable connection,
    // one publish each; this says nothing about reconnect or publisher retry.)
    await sleep(1500);

    expect(received).toHaveLength(2);
    expect(received.map((payload) => payload.site_id).sort()).toEqual([siteA1, siteA2].sort());
    expect(received.map((payload) => payload.assignment_id).sort()).toEqual(['assignment-site-a1', 'assignment-site-a2']);
  }, 15_000);

  it('AC5: operative state never rides the socket, and scope comes from the subject rather than the payload', async () => {
    const clientA1 = connectAs(operativeA1);
    await waitForEvent(clientA1, 'connect');

    const receivedByA1 = waitForEvent<Record<string, unknown>>(clientA1, WS_EVENT_FIELD_UPDATED);

    publishFieldEvent(orgA, siteA1, {
      kind: 'FIELD_STATE_UPDATED',
      user_id: operativeA1.userId,
      // Everything below must be dropped: `state` is need-to-know (WP-17/F2),
      // and a payload that claims a different scope must not be able to
      // relabel what the client is looking at.
      state: 'COMPROMISED',
      location: { lat: 51.5, lon: -0.1 },
      need_to_know_summary: 'must never reach a websocket',
      organisation_id: 'org-claimed-by-payload',
      site_id: 'site-claimed-by-payload',
    });

    const received = await receivedByA1;

    expect(received).toEqual({
      kind: 'FIELD_STATE_UPDATED',
      user_id: operativeA1.userId,
      organisation_id: orgA,
      site_id: siteA1,
    });
    expect(received).not.toHaveProperty('state');
    expect(received).not.toHaveProperty('location');
    expect(received).not.toHaveProperty('need_to_know_summary');
  }, 15_000);

  it('drops a Field message published without a site token instead of falling back to an organisation-wide fanout', async () => {
    const clientA1 = connectAs(operativeA1);
    const clientDispatcher = connectAs(dispatcherOrgWide);
    await Promise.all([waitForEvent(clientA1, 'connect'), waitForEvent(clientDispatcher, 'connect')]);

    const noneForA1 = assertNoEvent(clientA1, WS_EVENT_FIELD_UPDATED, 1500);
    const noneForDispatcher = assertNoEvent(clientDispatcher, WS_EVENT_FIELD_UPDATED, 1500);

    nc.publish(`sentinel.field.updated.${orgA}`, jsonCodec.encode({ kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'assignment-no-site' }));

    await Promise.all([noneForA1, noneForDispatcher]);
  }, 15_000);
});
