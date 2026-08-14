import { BadRequestException, Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LedgerController } from './ledger.controller';
import type { LedgerService } from './ledger.service';
import { buildPrincipal, type Principal, type RequestWithPrincipal as RequestWithLedgerPrincipal } from '../../common/security/principal';

function principalFor(org: string): Principal {
  return buildPrincipal({ user: { id: `u_${org}`, clearance: 5 }, organisation_id: org, roles: [{ role: 'investigator', site_id: null }] });
}

function makeReq(overrides: Partial<RequestWithLedgerPrincipal> = {}): RequestWithLedgerPrincipal {
  return { traceId: 'trace-abc', ...overrides } as RequestWithLedgerPrincipal;
}

function makeService(): LedgerService {
  return { query: vi.fn(), verifyChain: vi.fn() } as unknown as LedgerService;
}

describe('LedgerController#list (GET /api/v1/ledger)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('scopes the query by the principal organisation, ignoring any client-supplied organisation_id', async () => {
    const service = makeService();
    vi.mocked(service.query).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-principal') });

    await controller.list(req, { organisation_id: 'org-attacker-supplied', decision_type: 'constitution.evaluate' });

    expect(service.query).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-principal', decisionType: 'constitution.evaluate' }));
  });

  it('requires an explicit organisation_id query param when no principal is present', async () => {
    const service = makeService();
    const controller = new LedgerController(service);
    const req = makeReq();

    await expect(controller.list(req, {})).rejects.toThrow(BadRequestException);
    expect(service.query).not.toHaveBeenCalled();
  });

  it('uses the dev-bypass organisation_id query param when no principal is present', async () => {
    const service = makeService();
    vi.mocked(service.query).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new LedgerController(service);
    const req = makeReq();

    await controller.list(req, { organisation_id: 'org-dev' });

    expect(service.query).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-dev' }));
  });

  it('rejects an out-of-range limit with a 400, without calling the service', async () => {
    const service = makeService();
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    await expect(controller.list(req, { limit: '99999' })).rejects.toThrow(BadRequestException);
    expect(service.query).not.toHaveBeenCalled();
  });

  it('rejects an invalid cursor / decision_type / date filter with a 400', async () => {
    const service = makeService();
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    await expect(controller.list(req, { decided_from: 'not-a-date' })).rejects.toThrow(BadRequestException);
  });

  it('forwards decided_from/decided_to as Date objects and the requested limit/cursor', async () => {
    const service = makeService();
    vi.mocked(service.query).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    await controller.list(req, {
      decided_from: '2026-01-01T00:00:00.000Z',
      decided_to: '2026-02-01T00:00:00.000Z',
      limit: '10',
    });

    expect(service.query).toHaveBeenCalledWith(
      expect.objectContaining({
        organisationId: 'org-1',
        decidedFrom: new Date('2026-01-01T00:00:00.000Z'),
        decidedTo: new Date('2026-02-01T00:00:00.000Z'),
        limit: 10,
      }),
    );
  });

  it('logs every read that reaches the service: who, organisation, filters and trace id', async () => {
    const service = makeService();
    vi.mocked(service.query).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1'), traceId: 'trace-xyz' });

    await controller.list(req, { decision_type: 'constitution.evaluate' });

    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = logSpy.mock.calls[0]?.[0] as string;
    expect(logged).toContain('org-1');
    expect(logged).toContain('constitution.evaluate');
    expect(logged).toContain('trace-xyz');
  });
});

describe('LedgerController#verify (GET /api/v1/ledger/verify)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('verifies the principal\'s own organisation, ignoring any client-supplied organisation_id', async () => {
    const service = makeService();
    vi.mocked(service.verifyChain).mockResolvedValue({ valid: true, organisation_id: 'org-principal', entries_checked: 0 });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-principal') });

    await controller.verify(req, { organisation_id: 'org-attacker-supplied' });

    expect(service.verifyChain).toHaveBeenCalledWith('org-principal');
  });

  it('requires an explicit organisation_id query param when no principal is present', async () => {
    const service = makeService();
    const controller = new LedgerController(service);
    const req = makeReq();

    await expect(controller.verify(req, {})).rejects.toThrow(BadRequestException);
    expect(service.verifyChain).not.toHaveBeenCalled();
  });

  it('logs every verify call', async () => {
    const service = makeService();
    vi.mocked(service.verifyChain).mockResolvedValue({ valid: true, organisation_id: 'org-1', entries_checked: 3 });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    await controller.verify(req, {});

    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0]?.[0]).toContain('org-1');
  });

  it('returns the broken-chain result verbatim when the chain is invalid', async () => {
    const service = makeService();
    vi.mocked(service.verifyChain).mockResolvedValue({
      valid: false,
      organisation_id: 'org-1',
      entries_checked: 2,
      broken_entry_id: 'e2',
      reason: 'content_hash does not match',
    });
    const controller = new LedgerController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    const result = await controller.verify(req, {});
    expect(result).toEqual({
      valid: false,
      organisation_id: 'org-1',
      entries_checked: 2,
      broken_entry_id: 'e2',
      reason: 'content_hash does not match',
    });
  });
});
