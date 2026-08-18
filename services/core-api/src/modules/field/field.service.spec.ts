import { BadRequestException, ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import type { FieldRepository } from './field.repository';
import { FieldService } from './field.service';

const siteScope = { orgWide: false, siteIds: ['site-1'] };
const createdAt = new Date('2026-08-16T10:00:00.000Z');

function principal(userId = 'user-dispatcher', role = 'dispatcher'): Principal {
  return buildPrincipal({
    user: { id: userId, clearance: 5 },
    organisation_id: 'org-1',
    roles: [{ role, site_id: 'site-1' }],
  });
}

function assignment(overrides: Partial<Parameters<FieldService['createAssignment']>[2]> = {}) {
  return {
    site_id: 'site-1',
    incident_id: null,
    assignee_user_id: 'user-field',
    assignment_type: 'INCIDENT_RESPONSE',
    priority: 'SEV2' as const,
    need_to_know_summary: 'Proceed to north gate.',
    expires_at: null,
    idempotency_key: 'create-1',
    ...overrides,
  };
}

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
    expiresAt: null,
    acceptedAt: null,
    startedAt: null,
    completedAt: null,
    cancelledAt: null,
    declinedAt: null,
    createdByUserId: 'user-dispatcher',
    updatedByUserId: 'user-dispatcher',
    acceptedByUserId: null,
    idempotencyKey: 'create-1',
    createdAt,
    updatedAt: createdAt,
    ...overrides,
  };
}

function repositoryDouble(overrides: Partial<FieldRepository> = {}): FieldRepository {
  return {
    assigneeCanReceive: vi.fn().mockResolvedValue(true),
    incidentExists: vi.fn().mockResolvedValue(true),
    createAssignment: vi.fn().mockResolvedValue({ assignment: assignmentRow(), created: true }),
    listAssignments: vi.fn().mockResolvedValue([]),
    transitionAssignment: vi.fn().mockResolvedValue({ kind: 'updated', assignment: assignmentRow({ status: 'ACCEPTED', acceptedAt: createdAt, acceptedByUserId: 'user-field' }) }),
    recordState: vi.fn().mockResolvedValue({
      state: {
        id: 'state-1',
        organisationId: 'org-1',
        siteId: 'site-1',
        userId: 'user-field',
        deviceId: 'device-1',
        state: 'RESPONDING',
        location: null,
        sourceAt: new Date('2026-08-16T09:59:30.000Z'),
        receivedAt: createdAt,
        clientFreshnessMs: 0,
        authoritativeFreshnessMs: 30_000,
        traceId: 'trace-state',
        updatedAt: createdAt,
      },
      created: true,
    }),
    getCurrentState: vi.fn().mockResolvedValue(null),
    getAssignment: vi.fn(),
    auditCount: vi.fn(),
    outboxCountForAssignment: vi.fn(),
    validateStateContract: vi.fn(),
    ...overrides,
  } as unknown as FieldRepository;
}

describe('FieldService', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(createdAt);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates a scoped assignment only after assignee and incident checks pass', async () => {
    const repository = repositoryDouble();
    const service = new FieldService(repository);

    const result = await service.createAssignment(principal(), siteScope, assignment({ incident_id: '00000000-0000-4000-8000-000000000001' }));

    expect(result.status).toBe('REQUESTED');
    expect(repository.assigneeCanReceive).toHaveBeenCalledWith('org-1', 'site-1', 'user-field');
    expect(repository.incidentExists).toHaveBeenCalledWith('org-1', 'site-1', '00000000-0000-4000-8000-000000000001');
    expect(repository.createAssignment).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-1', siteId: 'site-1', actorUserId: 'user-dispatcher' }));
  });

  it('rejects assignment creation outside the principal site scope', async () => {
    const service = new FieldService(repositoryDouble());
    await expect(service.createAssignment(principal(), siteScope, assignment({ site_id: 'site-2' }))).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('rejects assignment creation for a non-field assignee at the site', async () => {
    const repository = repositoryDouble({ assigneeCanReceive: vi.fn().mockResolvedValue(false) } as Partial<FieldRepository>);
    const service = new FieldService(repository);
    await expect(service.createAssignment(principal(), siteScope, assignment())).rejects.toBeInstanceOf(BadRequestException);
  });

  it('maps duplicate transition results to the established assignment without conflict', async () => {
    const row = assignmentRow({ status: 'ACCEPTED', acceptedAt: createdAt, acceptedByUserId: 'user-field' });
    const repository = repositoryDouble({ transitionAssignment: vi.fn().mockResolvedValue({ kind: 'duplicate', assignment: row }) } as Partial<FieldRepository>);
    const service = new FieldService(repository);

    const result = await service.transitionAssignment(principal('user-field', 'field.operative'), siteScope, row.id, 'accept', {
      expected_status: 'REQUESTED',
      idempotency_key: 'accept-1',
    });

    expect(result.status).toBe('ACCEPTED');
  });

  it('turns CAS conflicts into ConflictException for racing assignment actions', async () => {
    const repository = repositoryDouble({ transitionAssignment: vi.fn().mockResolvedValue({ kind: 'conflict', currentStatus: 'CANCELLED' }) } as Partial<FieldRepository>);
    const service = new FieldService(repository);

    await expect(
      service.transitionAssignment(principal('user-field', 'field.operative'), siteScope, 'assignment-1', 'start', {
        expected_status: 'ACCEPTED',
        idempotency_key: 'start-1',
      }),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('rejects a site_id that is not a safe NATS subject token before any repository call (WP-17/D3)', () => {
    const repository = repositoryDouble();
    const service = new FieldService(repository);

    for (const unsafe of ['site.a1', 'site-a1.>', 'site *', '']) {
      expect(() => service.parseCreateAssignment(assignment({ site_id: unsafe }))).toThrow(BadRequestException);
      expect(() =>
        service.parseStateUpdate({
          site_id: unsafe,
          device_id: 'device-1',
          state: 'RESPONDING',
          location: null,
          source_at: '2026-08-16T09:59:30.000Z',
          freshness_ms: 0,
          idempotency_key: 'state-1',
          trace_id: 'trace-state',
        }),
      ).toThrow(BadRequestException);
    }

    expect(repository.createAssignment).not.toHaveBeenCalled();
    expect(repository.recordState).not.toHaveBeenCalled();
  });

  it('lists only the caller own assignments for the operative refetch route (WP-17/D5)', async () => {
    const repository = repositoryDouble();
    const service = new FieldService(repository);

    await service.listOwnAssignments(principal('user-field', 'field.operative'), siteScope);

    expect(repository.listAssignments).toHaveBeenCalledWith('org-1', siteScope, 'user-field');
  });

  it('hides another operative assignment behind 404 rather than 403 (WP-17/D5)', async () => {
    const repository = repositoryDouble({
      getAssignment: vi.fn().mockResolvedValue(assignmentRow({ assigneeUserId: 'someone-else' })),
    } as Partial<FieldRepository>);
    const service = new FieldService(repository);

    await expect(service.getOwnAssignment(principal('user-field', 'field.operative'), siteScope, assignmentRow().id)).rejects.toBeInstanceOf(NotFoundException);
  });

  it('returns the caller own assignment when they are the assignee', async () => {
    const repository = repositoryDouble({ getAssignment: vi.fn().mockResolvedValue(assignmentRow()) } as Partial<FieldRepository>);
    const service = new FieldService(repository);

    const result = await service.getOwnAssignment(principal('user-field', 'field.operative'), siteScope, assignmentRow().id);

    expect(result.assignee_user_id).toBe('user-field');
  });

  it('computes authoritative freshness server-side and preserves client freshness as telemetry', async () => {
    const repository = repositoryDouble();
    const service = new FieldService(repository);

    const result = await service.recordState(principal('user-field', 'field.operative'), siteScope, {
      site_id: 'site-1',
      device_id: 'device-1',
      state: 'RESPONDING',
      location: null,
      source_at: '2026-08-16T09:59:30.000Z',
      freshness_ms: 0,
      idempotency_key: 'state-1',
      trace_id: 'trace-state',
    });

    expect(result.client_freshness_ms).toBe(0);
    expect(result.authoritative_freshness_ms).toBe(30_000);
    expect(repository.validateStateContract).toHaveBeenCalledWith(expect.objectContaining({ clientFreshnessMs: 0, authoritativeFreshnessMs: 30_000 }));
    expect(repository.recordState).toHaveBeenCalledWith(expect.objectContaining({ clientFreshnessMs: 0, authoritativeFreshnessMs: 30_000 }));
  });
});
