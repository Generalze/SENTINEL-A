import { Logger } from '@nestjs/common';
import { JSONCodec, type JsMsg } from 'nats';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { NatsProvider } from '../../infra/nats.provider';
import { FusionConsumerService } from './fusion-consumer.service';
import type { FusionService } from './fusion.service';
import { makeEvent } from './test-support';

/**
 * Unit coverage for the consumer's acknowledgement decision — the part that
 * decides whether a message is finished with, poison, or worth retrying.
 * Exercised directly against `handle` with a fake JsMsg so every branch is
 * reachable without arranging a live failure.
 */
const codec = JSONCodec<unknown>();

function fakeMessage(payload: unknown): JsMsg & { ack: ReturnType<typeof vi.fn>; nak: ReturnType<typeof vi.fn>; term: ReturnType<typeof vi.fn> } {
  return {
    subject: 'sentinel.events.org-1.site-1',
    data: codec.encode(payload),
    ack: vi.fn(),
    nak: vi.fn(),
    term: vi.fn(),
  } as unknown as JsMsg & { ack: ReturnType<typeof vi.fn>; nak: ReturnType<typeof vi.fn>; term: ReturnType<typeof vi.fn> };
}

function makeConsumer(applyEvent: FusionService['applyEvent']): FusionConsumerService {
  const nats = { isConfigured: () => true } as unknown as NatsProvider;
  const fusion = { applyEvent } as unknown as FusionService;
  return new FusionConsumerService(nats, fusion);
}

describe('FusionConsumerService.handle', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('acks an event that was applied', async () => {
    const applyEvent = vi.fn().mockResolvedValue({ outcome: 'applied', stateChanged: false });
    const message = fakeMessage(makeEvent());
    await makeConsumer(applyEvent).handle(message);

    expect(applyEvent).toHaveBeenCalledTimes(1);
    expect(message.ack).toHaveBeenCalledTimes(1);
    expect(message.nak).not.toHaveBeenCalled();
    expect(message.term).not.toHaveBeenCalled();
  });

  it('acks a recognised duplicate — fusion is done with it either way', async () => {
    const applyEvent = vi.fn().mockResolvedValue({ outcome: 'duplicate', eventId: 'evt_x' });
    const message = fakeMessage(makeEvent());
    await makeConsumer(applyEvent).handle(message);
    expect(message.ack).toHaveBeenCalledTimes(1);
  });

  it('acks an event the rule table deliberately ignored', async () => {
    const applyEvent = vi.fn().mockResolvedValue({ outcome: 'ignored', reason: 'no_rule' });
    const message = fakeMessage(makeEvent({ event_type: 'unknown.type' }));
    await makeConsumer(applyEvent).handle(message);
    expect(message.ack).toHaveBeenCalledTimes(1);
  });

  it('terminates a payload that is not a Normalised Event, without calling fusion', async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    const applyEvent = vi.fn();
    const message = fakeMessage({ definitely: 'not an event' });
    await makeConsumer(applyEvent).handle(message);

    expect(applyEvent).not.toHaveBeenCalled();
    expect(message.term).toHaveBeenCalledTimes(1);
    expect(message.ack).not.toHaveBeenCalled();
    expect(message.nak).not.toHaveBeenCalled();
  });

  it('naks — not terms — when the failure is transient, so the event is retried', async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    const applyEvent = vi.fn().mockRejectedValue(new Error('connection refused'));
    const message = fakeMessage(makeEvent());
    await makeConsumer(applyEvent).handle(message);

    expect(message.nak).toHaveBeenCalledTimes(1);
    expect(message.term).not.toHaveBeenCalled();
    expect(message.ack).not.toHaveBeenCalled();
  });

  it('does not start when NATS is unconfigured, and stop() is safe on an unstarted consumer', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const nats = { isConfigured: () => false } as unknown as NatsProvider;
    const consumer = new FusionConsumerService(nats, { applyEvent: vi.fn() } as unknown as FusionService);

    await consumer.start();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('NATS is not configured'));
    await expect(consumer.stop()).resolves.toBeUndefined();
  });
});
