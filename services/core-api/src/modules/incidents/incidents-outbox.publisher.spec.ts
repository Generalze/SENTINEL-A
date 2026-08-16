import { afterEach, describe, expect, it, vi } from 'vitest';
import { IncidentsOutboxPublisher } from './incidents-outbox.publisher';

describe('IncidentsOutboxPublisher', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('publishes and marks each durable outbox row, leaving failed rows pending for retry', async () => {
    const rows = [
      { id: 'outbox-a', organisationId: 'org-a', payload: { id: 'incident-a' } },
      { id: 'outbox-b', organisationId: 'org-a', payload: { id: 'incident-b' } },
    ];
    const repository = {
      pendingOutbox: vi.fn().mockResolvedValue(rows),
      markOutboxPublished: vi.fn().mockResolvedValue(true),
    };
    const nc = { publish: vi.fn(), flush: vi.fn().mockRejectedValueOnce(new Error('nats down')) };
    const nats = { isConfigured: vi.fn().mockReturnValue(true), getConnection: vi.fn().mockResolvedValue(nc) };
    const publisher = new IncidentsOutboxPublisher(repository as never, nats as never);

    await expect(publisher.sweep()).resolves.toBe(0);
    expect(repository.markOutboxPublished).not.toHaveBeenCalled();

    nc.flush.mockResolvedValue(undefined);
    await expect(publisher.sweep()).resolves.toBe(2);
    expect(repository.markOutboxPublished).toHaveBeenCalledTimes(2);
    expect(nc.publish).toHaveBeenCalledWith('sentinel.incidents.updated.org-a', expect.any(Uint8Array));
  });

  it('does nothing when NATS is not configured', async () => {
    const repository = { pendingOutbox: vi.fn(), markOutboxPublished: vi.fn() };
    const nats = { isConfigured: vi.fn().mockReturnValue(false), getConnection: vi.fn() };
    const publisher = new IncidentsOutboxPublisher(repository as never, nats as never);

    await expect(publisher.sweep()).resolves.toBe(0);
    expect(repository.pendingOutbox).not.toHaveBeenCalled();
  });

  it('does not overlap in-flight sweep passes', async () => {
    let resolveRows: (value: []) => void = () => {};
    const rowsPending = new Promise<[]>((resolve) => {
      resolveRows = resolve;
    });
    const repository = { pendingOutbox: vi.fn().mockReturnValue(rowsPending), markOutboxPublished: vi.fn() };
    const nats = { isConfigured: vi.fn().mockReturnValue(true), getConnection: vi.fn() };
    const publisher = new IncidentsOutboxPublisher(repository as never, nats as never);

    const first = publisher.sweep();
    await expect(publisher.sweep()).resolves.toBe(0);
    expect(repository.pendingOutbox).toHaveBeenCalledOnce();

    resolveRows([]);
    await expect(first).resolves.toBe(0);
  });

  it('runs periodically and clears its timer at shutdown', async () => {
    vi.useFakeTimers();
    const repository = { pendingOutbox: vi.fn(), markOutboxPublished: vi.fn() };
    const nats = { isConfigured: vi.fn().mockReturnValue(false), getConnection: vi.fn() };
    const publisher = new IncidentsOutboxPublisher(repository as never, nats as never);
    const sweepSpy = vi.spyOn(publisher, 'sweep').mockResolvedValue(0);

    await publisher.onApplicationBootstrap();
    expect(sweepSpy).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(sweepSpy).toHaveBeenCalledTimes(2);

    publisher.onModuleDestroy();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(sweepSpy).toHaveBeenCalledTimes(2);
  });
});
