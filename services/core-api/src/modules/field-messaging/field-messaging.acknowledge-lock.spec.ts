import { Prisma } from '@prisma/client';
import { describe, expect, it, vi } from 'vitest';
import type { PrismaService } from '../../prisma/prisma.service';
import { FieldMessagingRepository } from './field-messaging.repository';

/**
 * WP-25/D25-16 and D25-16A — the acknowledgement composition seam, and the
 * recipient-row lock that makes the EXISTING acknowledgement rule
 * serializable.
 *
 * Nothing about the C8-01 rule changes here: acknowledgement still only
 * advances a row transport evidence already moved to DELIVERED, and the
 * refusal shapes are the same. What changes is that the decision is now taken
 * on state read UNDER a `FOR UPDATE` lock on the recipient row, so two valid
 * acknowledgements carrying DIFFERENT idempotency identities can no longer
 * both observe DELIVERED and both transition.
 */

const at = new Date('2026-09-02T12:00:00.000Z');
const MESSAGE_ID = '00000000-0000-4000-8000-000000000201';
const RECIPIENT_ROW_ID = '00000000-0000-4000-8000-000000000301';
const RECIPIENT = 'user-field';

function recipient(deliveryState: string) {
  return {
    id: RECIPIENT_ROW_ID,
    messageId: MESSAGE_ID,
    organisationId: 'org-1',
    siteId: 'site-1',
    recipientUserId: RECIPIENT,
    deliveryState,
    deliveredAt: deliveryState === 'REQUESTED' ? null : at,
    acknowledgedAt: deliveryState === 'ACKNOWLEDGED' ? at : null,
    createdAt: at,
    updatedAt: at,
  };
}

function message(deliveryState: string) {
  return {
    id: MESSAGE_ID,
    organisationId: 'org-1',
    siteId: 'site-1',
    incidentId: '00000000-0000-4000-8000-000000000401',
    senderUserId: 'user-commander',
    body: 'Proceed to the north gate.',
    mediaRefs: [],
    retentionClass: 'operational-30d',
    idempotencyKey: 'send-1',
    sentAt: at,
    expiresAt: null,
    traceId: 'trace-1',
    createdAt: at,
    updatedAt: at,
    recipients: [recipient(deliveryState)],
  };
}

/**
 * `preLock` is what the first (unlocked) read returns; `postLock` is what the
 * authoritative re-read under the lock returns. Making them DIFFERENT is how
 * these specs prove which one the decision is taken on.
 */
function txDouble(preLock: string, postLock = preLock) {
  return {
    incidentFieldMessage: {
      findFirst: vi.fn().mockResolvedValue(message(preLock)),
      // First call: the re-read under the lock. Second: the final refresh.
      findUniqueOrThrow: vi.fn().mockResolvedValue(message(postLock)),
    },
    incidentFieldMessageActionIdempotency: { findUnique: vi.fn().mockResolvedValue(null), create: vi.fn().mockResolvedValue({}) },
    incidentFieldMessageRecipient: { update: vi.fn().mockResolvedValue(recipient('ACKNOWLEDGED')) },
    incidentTimelineEntry: { create: vi.fn().mockResolvedValue({}) },
    incidentFieldMessageOutbox: { create: vi.fn().mockResolvedValue({}) },
    $queryRaw: vi.fn().mockResolvedValue([]),
  };
}

type TxDouble = ReturnType<typeof txDouble>;

const ARGS = ['org-1', MESSAGE_ID, RECIPIENT, 'ack-1', { orgWide: false, siteIds: ['site-1'] }, 'DELIVERED'] as const;

describe('WP-25/D25-16A FieldMessagingRepository.acknowledge locks the recipient row', () => {
  it('locks the named recipient row FOR UPDATE before it decides anything, and re-reads under that lock', async () => {
    const tx = txDouble('DELIVERED');
    const prisma = { $transaction: vi.fn((callback: (inner: TxDouble) => unknown) => callback(tx)) } as unknown as PrismaService;

    const result = await new FieldMessagingRepository(prisma).acknowledge(...ARGS);
    expect(result.kind).toBe('acknowledged');

    expect(tx.$queryRaw).toHaveBeenCalledOnce();
    const sql = (tx.$queryRaw.mock.calls[0]?.[0] as Prisma.Sql).sql;
    expect(sql).toContain('incident_field_message_recipients');
    expect(sql).toContain('FOR UPDATE');
    expect((tx.$queryRaw.mock.calls[0]?.[0] as Prisma.Sql).values).toContain(RECIPIENT_ROW_ID);

    // Ordering IS the correction. Scoped resolution -> lock -> authoritative
    // re-read -> idempotency -> transition. A lock taken after the state was
    // read would guard nothing.
    const lock = tx.$queryRaw.mock.invocationCallOrder[0] ?? 0;
    expect(lock).toBeGreaterThan(tx.incidentFieldMessage.findFirst.mock.invocationCallOrder[0] ?? 0);
    expect(lock).toBeLessThan(tx.incidentFieldMessage.findUniqueOrThrow.mock.invocationCallOrder[0] ?? 0);
    expect(lock).toBeLessThan(tx.incidentFieldMessageActionIdempotency.findUnique.mock.invocationCallOrder[0] ?? 0);
    expect(lock).toBeLessThan(tx.incidentFieldMessageRecipient.update.mock.invocationCallOrder[0] ?? 0);
  });

  it('decides on the state read AFTER the lock, not the stale pre-lock read', async () => {
    // Exactly the race D25-16A names: this caller observed DELIVERED, then a
    // concurrent acknowledgement committed. Under the lock the row is
    // ACKNOWLEDGED, and this caller must converge rather than transition again.
    const tx = txDouble('DELIVERED', 'ACKNOWLEDGED');
    const prisma = { $transaction: vi.fn((callback: (inner: TxDouble) => unknown) => callback(tx)) } as unknown as PrismaService;

    const result = await new FieldMessagingRepository(prisma).acknowledge(...ARGS);

    expect(result.kind).toBe('duplicate');
    expect(tx.incidentFieldMessageRecipient.update).not.toHaveBeenCalled();
    expect(tx.incidentTimelineEntry.create).not.toHaveBeenCalled();
    expect(tx.incidentFieldMessageOutbox.create).not.toHaveBeenCalled();
    expect(tx.incidentFieldMessageActionIdempotency.create).not.toHaveBeenCalled();
  });

  it('the C8-01 precondition is unchanged: a REQUESTED row is still refused as a conflict, on the locked state', async () => {
    const tx = txDouble('REQUESTED');
    const prisma = { $transaction: vi.fn((callback: (inner: TxDouble) => unknown) => callback(tx)) } as unknown as PrismaService;

    const result = await new FieldMessagingRepository(prisma).acknowledge(...ARGS);

    expect(result).toEqual({ kind: 'conflict', currentState: 'REQUESTED' });
    expect(tx.incidentFieldMessageRecipient.update).not.toHaveBeenCalled();
  });

  it('a caller who is not a named recipient is still refused before any lock is taken', async () => {
    const tx = txDouble('DELIVERED');
    const prisma = { $transaction: vi.fn((callback: (inner: TxDouble) => unknown) => callback(tx)) } as unknown as PrismaService;

    const result = await new FieldMessagingRepository(prisma).acknowledge('org-1', MESSAGE_ID, 'user-stranger', 'ack-1', { orgWide: true, siteIds: [] }, 'DELIVERED');

    // Locking is a concurrency fence, never an entitlement check: a caller
    // with no claim on this row is refused by scope, and never gets as far as
    // holding a lock on someone else's delivery row.
    expect(result).toEqual({ kind: 'not_recipient' });
    expect(tx.$queryRaw).not.toHaveBeenCalled();
  });
});

describe('WP-25/D25-16 FieldMessagingRepository.acknowledge external transaction seam', () => {
  it('uses the supplied transaction and opens NO nested transaction', async () => {
    const tx = txDouble('DELIVERED');
    const prisma = { $transaction: vi.fn() } as unknown as PrismaService & { $transaction: ReturnType<typeof vi.fn> };

    const result = await new FieldMessagingRepository(prisma).acknowledge(...ARGS, tx as unknown as Prisma.TransactionClient);

    expect(result.kind).toBe('acknowledged');
    expect(prisma.$transaction).not.toHaveBeenCalled();
    // The lock, the transition, the timeline entry and the outbox row all land
    // in the orchestrator's transaction, so they commit with it or not at all.
    expect(tx.$queryRaw).toHaveBeenCalledOnce();
    expect(tx.incidentFieldMessageRecipient.update).toHaveBeenCalledOnce();
    expect(tx.incidentTimelineEntry.create).toHaveBeenCalledOnce();
    expect(tx.incidentFieldMessageOutbox.create).toHaveBeenCalledOnce();
  });

  it('the existing human path is unchanged: no tx supplied means Field Messaging opens its own transaction', async () => {
    const tx = txDouble('DELIVERED');
    const prisma = { $transaction: vi.fn((callback: (inner: TxDouble) => unknown) => callback(tx)) } as unknown as PrismaService & {
      $transaction: ReturnType<typeof vi.fn>;
    };

    await new FieldMessagingRepository(prisma).acknowledge(...ARGS);

    expect(prisma.$transaction).toHaveBeenCalledOnce();
  });
});
