import { Prisma } from '@prisma/client';
import { describe, expect, it, vi } from 'vitest';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import type { PrismaService } from '../../prisma/prisma.service';
import { FieldRepository } from './field.repository';
import { FieldService } from './field.service';

/**
 * WP-25/D25-16 — the external transaction-composition seam.
 *
 * These specs assert the seam's PROPERTIES, not the Field rules, which are
 * unchanged and are covered by field.repository.spec.ts, field.service.spec.ts
 * and field.api.integration.spec.ts. What is new is only WHO opens the
 * transaction, so what is tested here is only that:
 *
 *   - a supplied transaction is USED and no second one is opened around it;
 *   - the `SELECT ... FOR UPDATE` fence runs INSIDE the supplied transaction,
 *     because a lock taken in a different transaction from the read-check-write
 *     it guards is decorative;
 *   - `siteExistsInOrganisation` runs in the supplied transaction, closing the
 *     check-to-commit gap D25-16 names;
 *   - the no-`tx` path is byte-identical to what it always was.
 */

const at = new Date('2026-09-02T12:00:00.000Z');

function assignmentRow(overrides: Record<string, unknown> = {}) {
  return {
    id: '00000000-0000-4000-8000-000000000101',
    organisationId: 'org-1',
    siteId: 'site-1',
    incidentId: null,
    assigneeUserId: 'user-field',
    assignmentType: 'INCIDENT_RESPONSE',
    priority: 'SEV2',
    status: 'REQUESTED',
    deliveryState: 'REQUESTED',
    needToKnowSummary: 'Proceed to north gate.',
    idempotencyKey: 'create-1',
    expiresAt: null,
    acceptedAt: null,
    startedAt: null,
    completedAt: null,
    cancelledAt: null,
    declinedAt: null,
    createdByUserId: 'user-dispatcher',
    updatedByUserId: 'user-dispatcher',
    acceptedByUserId: null,
    createdAt: at,
    updatedAt: at,
    ...overrides,
  };
}

function stateRow() {
  return {
    id: 'state-1',
    organisationId: 'org-1',
    siteId: 'site-1',
    userId: 'user-field',
    deviceId: 'device-1',
    state: 'RESPONDING',
    location: null,
    sourceAt: at,
    receivedAt: at,
    clientFreshnessMs: 0,
    authoritativeFreshnessMs: 0,
    traceId: 'trace-1',
    updatedAt: at,
  };
}

/** A stand-in for a transaction an ORCHESTRATOR already owns. */
function externalTx() {
  return {
    site: { findFirst: vi.fn().mockResolvedValue({ id: 'site-1' }) },
    fieldAssignment: {
      findFirst: vi.fn().mockResolvedValue({ id: assignmentRow().id }),
      findUniqueOrThrow: vi.fn().mockResolvedValue(assignmentRow()),
      update: vi.fn().mockResolvedValue(assignmentRow({ status: 'ACCEPTED', acceptedAt: at, acceptedByUserId: 'user-field', deliveryState: 'ACKNOWLEDGED' })),
    },
    fieldAssignmentActionIdempotency: { findUnique: vi.fn().mockResolvedValue(null), create: vi.fn().mockResolvedValue({}) },
    fieldStateUpdateIdempotency: { findUnique: vi.fn().mockResolvedValue(null), create: vi.fn().mockResolvedValue({}) },
    fieldOperativeStateHistory: { create: vi.fn().mockResolvedValue({}) },
    fieldOperativeCurrentState: { upsert: vi.fn().mockResolvedValue(stateRow()), findUniqueOrThrow: vi.fn().mockResolvedValue(stateRow()) },
    fieldAuditLog: { create: vi.fn().mockResolvedValue({}) },
    fieldOutbox: { create: vi.fn().mockResolvedValue({}) },
    $queryRaw: vi.fn().mockResolvedValue([]),
  };
}

type ExternalTx = ReturnType<typeof externalTx>;

/**
 * A PrismaService double whose `$transaction` FAILS the spec if it is reached.
 * `site.findFirst` is present so a leak onto the non-transactional client is
 * observable rather than merely absent.
 */
function prismaDouble(): PrismaService & { $transaction: ReturnType<typeof vi.fn> } {
  return {
    $transaction: vi.fn(),
    site: { findFirst: vi.fn().mockResolvedValue({ id: 'site-1' }) },
  } as unknown as PrismaService & { $transaction: ReturnType<typeof vi.fn> };
}

function principal(userId = 'user-field'): Principal {
  return buildPrincipal({ user: { id: userId, clearance: 5 }, organisation_id: 'org-1', roles: [{ role: 'field.operative', site_id: 'site-1' }] });
}

const siteScope = { orgWide: false, siteIds: ['site-1'] };

const stateInput = {
  organisationId: 'org-1',
  siteId: 'site-1',
  actorUserId: 'user-field',
  deviceId: 'device-1',
  state: 'RESPONDING',
  location: null,
  sourceAt: at,
  receivedAt: at,
  clientFreshnessMs: 0,
  authoritativeFreshnessMs: 0,
  traceId: 'trace-1',
  idempotencyKey: 'state-1',
};

const transitionInput = {
  organisationId: 'org-1',
  assignmentId: assignmentRow().id,
  actorUserId: 'user-field',
  action: 'accept' as const,
  expectedStatus: 'REQUESTED' as const,
  targetStatus: 'ACCEPTED' as const,
  idempotencyKey: 'accept-1',
  siteScope,
  actorMustBeAssignee: true,
};

describe('WP-25/D25-16 FieldRepository external transaction seam', () => {
  it('recordState uses the supplied transaction and opens NO nested transaction', async () => {
    const prisma = prismaDouble();
    const tx = externalTx();
    const result = await new FieldRepository(prisma).recordState(stateInput, tx as unknown as Prisma.TransactionClient);

    expect(result.created).toBe(true);
    // The whole point: an orchestrator's transaction is not silently wrapped
    // in a second one, which would commit the Field rows independently of the
    // caller's and defeat D25-02's COMMIT TOGETHER.
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(tx.fieldStateUpdateIdempotency.create).toHaveBeenCalledOnce();
    expect(tx.fieldOperativeStateHistory.create).toHaveBeenCalledOnce();
    expect(tx.fieldOperativeCurrentState.upsert).toHaveBeenCalledOnce();
    expect(tx.fieldAuditLog.create).toHaveBeenCalledOnce();
    expect(tx.fieldOutbox.create).toHaveBeenCalledOnce();
  });

  it('transitionAssignment uses the supplied transaction, opens NO nested transaction, and keeps the FOR UPDATE fence inside it', async () => {
    const prisma = prismaDouble();
    const tx = externalTx();
    const result = await new FieldRepository(prisma).transitionAssignment(transitionInput, tx as unknown as Prisma.TransactionClient);

    expect(result.kind).toBe('updated');
    expect(prisma.$transaction).not.toHaveBeenCalled();

    // The lock is taken on the SUPPLIED client, so it is held by the
    // orchestrator's transaction and released at ITS commit — not by a
    // short-lived inner transaction that would drop the fence before the
    // caller's own rows were written.
    expect(tx.$queryRaw).toHaveBeenCalledOnce();
    const sql = (tx.$queryRaw.mock.calls[0]?.[0] as Prisma.Sql).sql;
    expect(sql).toContain('FOR UPDATE');
    expect(sql).toContain('field_assignments');

    // ... and it is taken BEFORE the status is read and before anything is
    // written. A fence after the read is not a fence.
    const lockOrder = tx.$queryRaw.mock.invocationCallOrder[0] ?? 0;
    expect(lockOrder).toBeGreaterThan(tx.fieldAssignment.findFirst.mock.invocationCallOrder[0] ?? 0);
    expect(lockOrder).toBeLessThan(tx.fieldAssignment.findUniqueOrThrow.mock.invocationCallOrder[0] ?? 0);
    expect(lockOrder).toBeLessThan(tx.fieldAssignment.update.mock.invocationCallOrder[0] ?? 0);
  });

  it('siteExistsInOrganisation reads inside the supplied transaction, not on the base client', async () => {
    const prisma = prismaDouble();
    const tx = externalTx();
    const repository = new FieldRepository(prisma);

    await expect(repository.siteExistsInOrganisation('org-1', 'site-1', tx as unknown as Prisma.TransactionClient)).resolves.toBe(true);

    // D25-16: on the gateway path this check MUST see, and hold, the same
    // snapshot as the write. Reading it on the base client would leave the
    // check-to-commit race the seam exists to close.
    expect(tx.site.findFirst).toHaveBeenCalledOnce();
    expect(tx.site.findFirst).toHaveBeenCalledWith({ where: { id: 'site-1', organisationId: 'org-1' }, select: { id: true } });
    expect((prisma.site.findFirst as unknown as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled();
  });

  it('the existing human path is unchanged: no tx supplied means Field opens its own transaction, and the site check stays a plain read', async () => {
    const tx = externalTx();
    const prisma = {
      $transaction: vi.fn((callback: (inner: ExternalTx) => unknown) => callback(tx)),
      site: { findFirst: vi.fn().mockResolvedValue({ id: 'site-1' }) },
    } as unknown as PrismaService & { $transaction: ReturnType<typeof vi.fn> };
    const repository = new FieldRepository(prisma);

    await repository.recordState(stateInput);
    await repository.transitionAssignment(transitionInput);
    await repository.siteExistsInOrganisation('org-1', 'site-1');

    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    // siteExistsInOrganisation has never opened a transaction and still does
    // not: the seam adds a parameter, it does not change the human path.
    expect(prisma.site.findFirst).toHaveBeenCalledOnce();
    expect(tx.site.findFirst).not.toHaveBeenCalled();
  });
});

describe('WP-25/D25-16 FieldService external transaction seam', () => {
  it('recordState threads the supplied transaction to BOTH the site check and the write', async () => {
    const tx = externalTx() as unknown as Prisma.TransactionClient;
    const repository = {
      siteExistsInOrganisation: vi.fn().mockResolvedValue(true),
      validateStateContract: vi.fn(),
      recordState: vi.fn().mockResolvedValue({ state: stateRow(), created: true }),
    } as unknown as FieldRepository;

    await new FieldService(repository).recordState(
      principal(),
      siteScope,
      {
        site_id: 'site-1',
        device_id: 'device-1',
        state: 'RESPONDING',
        location: null,
        source_at: at.toISOString(),
        freshness_ms: 0,
        idempotency_key: 'state-1',
        trace_id: 'trace-1',
      },
      tx,
    );

    // Both, not one: the site check runs BEFORE the repository transaction, so
    // if only the write joined the caller's transaction the gateway would keep
    // the check-to-commit race D25-16 exists to remove.
    expect(repository.siteExistsInOrganisation).toHaveBeenCalledWith('org-1', 'site-1', tx);
    expect((repository.recordState as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[1]).toBe(tx);
  });

  it('transitionAssignment threads the supplied transaction to the repository', async () => {
    const tx = externalTx() as unknown as Prisma.TransactionClient;
    const repository = {
      transitionAssignment: vi
        .fn()
        .mockResolvedValue({ kind: 'updated', assignment: assignmentRow({ status: 'ACCEPTED', acceptedAt: at, acceptedByUserId: 'user-field' }) }),
    } as unknown as FieldRepository;

    await new FieldService(repository).transitionAssignment(principal(), siteScope, assignmentRow().id, 'accept', {
      expected_status: 'REQUESTED',
      idempotency_key: 'accept-1',
    }, tx);

    expect((repository.transitionAssignment as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[1]).toBe(tx);
  });

  it('existing human callers reach the repository with EXACTLY the arguments they always did — the seam adds no trailing undefined', async () => {
    const repository = {
      siteExistsInOrganisation: vi.fn().mockResolvedValue(true),
      validateStateContract: vi.fn(),
      recordState: vi.fn().mockResolvedValue({ state: stateRow(), created: true }),
      transitionAssignment: vi.fn().mockResolvedValue({ kind: 'updated', assignment: assignmentRow({ status: 'ACCEPTED' }) }),
    } as unknown as FieldRepository;
    const service = new FieldService(repository);

    await service.recordState(principal(), siteScope, {
      site_id: 'site-1',
      device_id: 'device-1',
      state: 'RESPONDING',
      location: null,
      source_at: at.toISOString(),
      freshness_ms: 0,
      idempotency_key: 'state-1',
      trace_id: 'trace-1',
    });
    await service.transitionAssignment(principal(), siteScope, assignmentRow().id, 'accept', {
      expected_status: 'REQUESTED',
      idempotency_key: 'accept-1',
    });

    // Not `toHaveBeenCalledWith(..., undefined)`: an explicit trailing
    // `undefined` is semantically identical but OBSERVABLY different, and
    // every pre-WP-25 spec that asserts on these call shapes must keep
    // passing untouched. The argument arity itself is the assertion.
    expect(repository.siteExistsInOrganisation).toHaveBeenCalledWith('org-1', 'site-1');
    expect((repository.siteExistsInOrganisation as unknown as ReturnType<typeof vi.fn>).mock.calls[0]).toHaveLength(2);
    expect((repository.recordState as unknown as ReturnType<typeof vi.fn>).mock.calls[0]).toHaveLength(1);
    expect((repository.transitionAssignment as unknown as ReturnType<typeof vi.fn>).mock.calls[0]).toHaveLength(1);
  });
});
