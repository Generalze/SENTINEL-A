import type { Msg } from 'nats';
import { describe, expect, it, vi } from 'vitest';
import type { NatsProvider } from '../../infra/nats.provider';
import { NATS_SUBJECT_HYPOTHESIS, NATS_SUBJECT_INCIDENT, WS_EVENT_HYPOTHESIS_UPDATED, WS_EVENT_INCIDENT_UPDATED } from './realtime.constants';
import { RealtimeNatsBridgeService } from './realtime-nats-bridge.service';
import type { RealtimeGateway } from './realtime.gateway';

function fakeMsg(subject: string, payload: unknown): Msg {
  return {
    subject,
    data: new Uint8Array(),
    json<T>(): T {
      return payload as T;
    },
  } as unknown as Msg;
}

/** Yields `messages` once, then hangs forever (simulating an open, idle subscription) rather than completing. */
function asyncIterableOf(messages: Msg[]): AsyncIterable<Msg> {
  return {
    [Symbol.asyncIterator]() {
      let i = 0;
      return {
        next: (): Promise<IteratorResult<Msg>> => {
          if (i < messages.length) {
            const value = messages[i];
            i += 1;
            return Promise.resolve({ value, done: false });
          }
          return new Promise<IteratorResult<Msg>>(() => {
            /* never resolves: an open subscription with nothing new to deliver */
          });
        },
      };
    },
  };
}

/** `connectFailures` getConnection() calls (across BOTH routes, since the mock is shared) throw before succeeding permanently. */
function fakeNatsProvider(subscribeBySubject: Readonly<Record<string, AsyncIterable<Msg>>>, connectFailures = 0): NatsProvider & { getConnection: ReturnType<typeof vi.fn> } {
  let calls = 0;
  const nc = {
    subscribe: vi.fn((subject: string) => subscribeBySubject[subject] ?? asyncIterableOf([])),
  };
  const getConnection = vi.fn(async () => {
    calls += 1;
    if (calls <= connectFailures) {
      throw new Error(`simulated connect failure #${calls}`);
    }
    return nc;
  });
  return { isConfigured: () => true, getConnection } as unknown as NatsProvider & { getConnection: ReturnType<typeof vi.fn> };
}

function fakeGateway(): RealtimeGateway & { broadcastToOrg: ReturnType<typeof vi.fn> } {
  return { broadcastToOrg: vi.fn() } as unknown as RealtimeGateway & { broadcastToOrg: ReturnType<typeof vi.fn> };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

describe('RealtimeNatsBridgeService — resubscribe retry/backoff wiring (deliverable #5, NATS-restart criterion)', () => {
  it('retries getConnection with backoff after transient failures, then subscribes and forwards a whitelisted message', async () => {
    const orgId = 'org_bridge_1';
    const msg = fakeMsg(`sentinel.fusion.hypothesis.${orgId}`, {
      hypothesis_id: 'hyp_1',
      state: 3,
      updated_at: '2026-08-14T00:00:00.000Z',
      confidence_explanation: 'must never reach the client',
      supporting_event_ids: ['evt_1', 'evt_2'],
    });
    const nats = fakeNatsProvider(
      { [NATS_SUBJECT_HYPOTHESIS]: asyncIterableOf([msg]), [NATS_SUBJECT_INCIDENT]: asyncIterableOf([]) },
      2, // fails twice before succeeding — proves the retry loop actually retries
    );
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);
    bridge.setBackoffOptionsForTesting({ baseMs: 1, maxMs: 2, factor: 1 });

    bridge.onModuleInit();

    await vi.waitFor(() => {
      expect(gateway.broadcastToOrg).toHaveBeenCalled();
    });

    expect(gateway.broadcastToOrg).toHaveBeenCalledWith(orgId, WS_EVENT_HYPOTHESIS_UPDATED, {
      id: 'hyp_1',
      // Hypothesis's own schema carries no organisation_id — this proves
      // the whitelist util's subject-derived fallback actually kicks in.
      organisation_id: orgId,
      state: 3,
      updated_at: '2026-08-14T00:00:00.000Z',
    });
    expect(nats.getConnection.mock.calls.length).toBeGreaterThanOrEqual(3);

    bridge.onModuleDestroy();
  });

  it('forwards an incident.updated message on the incidents subject, whitelisted', async () => {
    const orgId = 'org_bridge_2';
    const msg = fakeMsg(`sentinel.incidents.updated.${orgId}`, {
      id: 'inc_1',
      organisation_id: orgId,
      severity: 'SEV1',
      status: 'open',
      commander_user_id: 'user_9',
    });
    const nats = fakeNatsProvider({ [NATS_SUBJECT_HYPOTHESIS]: asyncIterableOf([]), [NATS_SUBJECT_INCIDENT]: asyncIterableOf([msg]) });
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);
    bridge.setBackoffOptionsForTesting({ baseMs: 1, maxMs: 2, factor: 1 });

    bridge.onModuleInit();

    await vi.waitFor(() => {
      expect(gateway.broadcastToOrg).toHaveBeenCalled();
    });

    expect(gateway.broadcastToOrg).toHaveBeenCalledWith(orgId, WS_EVENT_INCIDENT_UPDATED, {
      id: 'inc_1',
      organisation_id: orgId,
      severity: 'SEV1',
      status: 'open',
    });

    bridge.onModuleDestroy();
  });

  it('keeps retrying with backoff (never throws/crashes) while NATS is persistently unreachable', async () => {
    const nats = { isConfigured: () => true, getConnection: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) } as unknown as NatsProvider & {
      getConnection: ReturnType<typeof vi.fn>;
    };
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);
    bridge.setBackoffOptionsForTesting({ baseMs: 1, maxMs: 2, factor: 1 });

    expect(() => bridge.onModuleInit()).not.toThrow();

    await vi.waitFor(() => {
      expect(nats.getConnection.mock.calls.length).toBeGreaterThanOrEqual(6);
    });

    expect(gateway.broadcastToOrg).not.toHaveBeenCalled();
    bridge.onModuleDestroy();
  });

  it('does nothing (and never throws) when NATS is not configured', () => {
    const nats = { isConfigured: () => false, getConnection: vi.fn() } as unknown as NatsProvider & { getConnection: ReturnType<typeof vi.fn> };
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);

    expect(() => bridge.onModuleInit()).not.toThrow();
    expect(nats.getConnection).not.toHaveBeenCalled();
  });

  it('drops a message whose subject carries no parseable organisation_id, without throwing', async () => {
    const badMsg = fakeMsg('sentinel.fusion.hypothesis', { hypothesis_id: 'x' }); // too few dot-segments
    const nats = fakeNatsProvider({ [NATS_SUBJECT_HYPOTHESIS]: asyncIterableOf([badMsg]), [NATS_SUBJECT_INCIDENT]: asyncIterableOf([]) });
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);

    bridge.onModuleInit();
    await sleep(50);

    expect(gateway.broadcastToOrg).not.toHaveBeenCalled();
    bridge.onModuleDestroy();
  });

  it('drops a malformed (non-JSON) message without throwing', async () => {
    const badMsg = {
      subject: 'sentinel.incidents.updated.org_x',
      data: new Uint8Array(),
      json: () => {
        throw new Error('not valid JSON');
      },
    } as unknown as Msg;
    const nats = fakeNatsProvider({ [NATS_SUBJECT_HYPOTHESIS]: asyncIterableOf([]), [NATS_SUBJECT_INCIDENT]: asyncIterableOf([badMsg]) });
    const gateway = fakeGateway();
    const bridge = new RealtimeNatsBridgeService(nats, gateway);

    bridge.onModuleInit();
    await sleep(50);

    expect(gateway.broadcastToOrg).not.toHaveBeenCalled();
    bridge.onModuleDestroy();
  });
});
