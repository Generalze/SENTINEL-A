import { describe, expect, it, vi } from 'vitest';
import type { PrismaService } from '../../prisma/prisma.service';
import { FieldRepository } from './field.repository';

const at = new Date('2026-08-16T10:00:00.000Z');

function assignment(status = 'REQUESTED') {
  return {
    id: '00000000-0000-4000-8000-000000000101',
    organisationId: 'org-1',
    siteId: 'site-1',
    incidentId: null,
    assigneeUserId: 'user-field',
    assignmentType: 'INCIDENT_RESPONSE',
    priority: 'SEV2',
    status,
    deliveryState: status === 'ACCEPTED' ? 'ACKNOWLEDGED' : 'REQUESTED',
    needToKnowSummary: 'Proceed to north gate.',
    idempotencyKey: 'create-1',
    expiresAt: null,
    acceptedAt: status === 'ACCEPTED' ? at : null,
    startedAt: null,
    completedAt: null,
    cancelledAt: null,
    declinedAt: null,
    createdByUserId: 'user-dispatcher',
    updatedByUserId: status === 'ACCEPTED' ? 'user-field' : 'user-dispatcher',
    acceptedByUserId: status === 'ACCEPTED' ? 'user-field' : null,
    createdAt: at,
    updatedAt: at,
  };
}

describe('FieldRepository transaction semantics', () => {
  it('writes assignment transition, idempotency, audit, and outbox in one transaction', async () => {
    const updated = assignment('ACCEPTED');
    const tx = {
      fieldAssignment: {
        findFirst: vi.fn().mockResolvedValue({ id: assignment().id }),
        findUniqueOrThrow: vi.fn().mockResolvedValue(assignment()),
        update: vi.fn().mockResolvedValue(updated),
      },
      fieldAssignmentActionIdempotency: {
        findUnique: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockResolvedValue({}),
      },
      fieldAuditLog: { create: vi.fn().mockResolvedValue({}) },
      fieldOutbox: { create: vi.fn().mockResolvedValue({}) },
      $queryRaw: vi.fn().mockResolvedValue([]),
    };
    const prisma = { $transaction: vi.fn((callback: (inner: typeof tx) => unknown) => callback(tx)) } as unknown as PrismaService;
    const repository = new FieldRepository(prisma);

    const result = await repository.transitionAssignment({
      organisationId: 'org-1',
      assignmentId: assignment().id,
      actorUserId: 'user-field',
      action: 'accept',
      expectedStatus: 'REQUESTED',
      targetStatus: 'ACCEPTED',
      idempotencyKey: 'accept-1',
      siteScope: { orgWide: false, siteIds: ['site-1'] },
      actorMustBeAssignee: true,
    });

    expect(result.kind).toBe('updated');
    expect(prisma.$transaction).toHaveBeenCalledOnce();
    expect(tx.fieldAssignment.update).toHaveBeenCalledOnce();
    expect(tx.fieldAssignmentActionIdempotency.create).toHaveBeenCalledOnce();
    expect(tx.fieldAuditLog.create).toHaveBeenCalledOnce();
    expect(tx.fieldOutbox.create).toHaveBeenCalledOnce();
  });

  it('returns duplicate transitions without appending new audit or outbox rows', async () => {
    const current = assignment('ACCEPTED');
    const tx = {
      fieldAssignment: {
        findFirst: vi.fn().mockResolvedValue({ id: current.id }),
        findUniqueOrThrow: vi.fn().mockResolvedValue(current),
        update: vi.fn(),
      },
      fieldAssignmentActionIdempotency: {
        findUnique: vi.fn().mockResolvedValue({ id: 'idem-1' }),
        create: vi.fn(),
      },
      fieldAuditLog: { create: vi.fn() },
      fieldOutbox: { create: vi.fn() },
      $queryRaw: vi.fn().mockResolvedValue([]),
    };
    const prisma = { $transaction: vi.fn((callback: (inner: typeof tx) => unknown) => callback(tx)) } as unknown as PrismaService;
    const repository = new FieldRepository(prisma);

    const result = await repository.transitionAssignment({
      organisationId: 'org-1',
      assignmentId: current.id,
      actorUserId: 'user-field',
      action: 'accept',
      expectedStatus: 'REQUESTED',
      targetStatus: 'ACCEPTED',
      idempotencyKey: 'accept-1',
      siteScope: { orgWide: false, siteIds: ['site-1'] },
      actorMustBeAssignee: true,
    });

    expect(result.kind).toBe('duplicate');
    expect(tx.fieldAssignment.update).not.toHaveBeenCalled();
    expect(tx.fieldAssignmentActionIdempotency.create).not.toHaveBeenCalled();
    expect(tx.fieldAuditLog.create).not.toHaveBeenCalled();
    expect(tx.fieldOutbox.create).not.toHaveBeenCalled();
  });

  it('returns conflict for stale expected status before appending side effects', async () => {
    const current = assignment('CANCELLED');
    const tx = {
      fieldAssignment: {
        findFirst: vi.fn().mockResolvedValue({ id: current.id }),
        findUniqueOrThrow: vi.fn().mockResolvedValue(current),
        update: vi.fn(),
      },
      fieldAssignmentActionIdempotency: {
        findUnique: vi.fn().mockResolvedValue(null),
        create: vi.fn(),
      },
      fieldAuditLog: { create: vi.fn() },
      fieldOutbox: { create: vi.fn() },
      $queryRaw: vi.fn().mockResolvedValue([]),
    };
    const prisma = { $transaction: vi.fn((callback: (inner: typeof tx) => unknown) => callback(tx)) } as unknown as PrismaService;
    const repository = new FieldRepository(prisma);

    const result = await repository.transitionAssignment({
      organisationId: 'org-1',
      assignmentId: current.id,
      actorUserId: 'user-field',
      action: 'start',
      expectedStatus: 'ACCEPTED',
      targetStatus: 'IN_PROGRESS',
      idempotencyKey: 'start-1',
      siteScope: { orgWide: false, siteIds: ['site-1'] },
      actorMustBeAssignee: true,
    });

    expect(result).toEqual({ kind: 'conflict', currentStatus: 'CANCELLED' });
    expect(tx.fieldAssignment.update).not.toHaveBeenCalled();
    expect(tx.fieldAssignmentActionIdempotency.create).not.toHaveBeenCalled();
    expect(tx.fieldAuditLog.create).not.toHaveBeenCalled();
    expect(tx.fieldOutbox.create).not.toHaveBeenCalled();
  });
});
