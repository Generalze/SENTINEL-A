import { describe, expect, it, vi } from 'vitest';
import type { NatsProvider } from '../../infra/nats.provider';
import type { PrismaService } from '../../prisma/prisma.service';
import { FieldOutboxPublisher } from './field-outbox.publisher';
import { fieldUpdatedSubject } from './field.constants';

interface OutboxRow {
  id: string;
  organisationId: string;
  siteId: string;
  payload: Record<string, unknown>;
}

function harness(rows: OutboxRow[]): {
  publisher: FieldOutboxPublisher;
  publish: ReturnType<typeof vi.fn>;
  updateMany: ReturnType<typeof vi.fn>;
} {
  const publish = vi.fn();
  const updateMany = vi.fn().mockResolvedValue({ count: 1 });
  const prisma = { fieldOutbox: { findMany: vi.fn().mockResolvedValue(rows), updateMany } } as unknown as PrismaService;
  const nats = {
    isConfigured: () => true,
    getConnection: vi.fn().mockResolvedValue({ publish, flush: vi.fn().mockResolvedValue(undefined) }),
  } as unknown as NatsProvider;
  return { publisher: new FieldOutboxPublisher(prisma, nats), publish, updateMany };
}

describe('FieldOutboxPublisher (WP-17/D2, D3)', () => {
  it('publishes each row on the site-scoped subject and marks it published', async () => {
    const { publisher, publish, updateMany } = harness([
      { id: 'row-1', organisationId: 'org-1', siteId: 'site-a', payload: { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'a-1' } },
    ]);

    expect(await publisher.sweep()).toBe(1);
    expect(publish).toHaveBeenCalledOnce();
    expect(publish.mock.calls[0]?.[0]).toBe(fieldUpdatedSubject('org-1', 'site-a'));
    expect(publish.mock.calls[0]?.[0]).toBe('sentinel.field.updated.org-1.site-a');
    expect(updateMany).toHaveBeenCalledWith({ where: { id: 'row-1', publishedAt: null }, data: { publishedAt: expect.any(Date) } });
  });

  it('refuses to publish a row whose scope ids are not safe subject tokens, and keeps going for the rest', async () => {
    const { publisher, publish, updateMany } = harness([
      { id: 'poisoned', organisationId: 'org-1', siteId: 'site-a.>', payload: { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'a-bad' } },
      { id: 'row-2', organisationId: 'org-1', siteId: 'site-b', payload: { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'a-2' } },
    ]);

    // One poisoned row must not stall the queue for every other tenant.
    expect(await publisher.sweep()).toBe(1);
    expect(publish).toHaveBeenCalledOnce();
    expect(publish.mock.calls[0]?.[0]).toBe(fieldUpdatedSubject('org-1', 'site-b'));
    // The poisoned row is left unpublished rather than silently marked done.
    expect(updateMany).toHaveBeenCalledOnce();
    expect(updateMany).toHaveBeenCalledWith({ where: { id: 'row-2', publishedAt: null }, data: { publishedAt: expect.any(Date) } });
  });

  it('publishes nothing when NATS is not configured', async () => {
    const prisma = { fieldOutbox: { findMany: vi.fn(), updateMany: vi.fn() } } as unknown as PrismaService;
    const nats = { isConfigured: () => false, getConnection: vi.fn() } as unknown as NatsProvider;
    const publisher = new FieldOutboxPublisher(prisma, nats);

    expect(await publisher.sweep()).toBe(0);
    expect(prisma.fieldOutbox.findMany).not.toHaveBeenCalled();
  });
});
