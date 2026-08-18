import { describe, expect, it, vi } from 'vitest';
import type { PrismaService } from '../../prisma/prisma.service';
import { loadRealtimePrincipal } from './realtime-principal.loader';

function fakePrisma(findUnique: ReturnType<typeof vi.fn>): PrismaService {
  return { user: { findUnique } } as unknown as PrismaService;
}

describe('loadRealtimePrincipal', () => {
  it('returns null for an unknown user id (never throws)', async () => {
    const findUnique = vi.fn().mockResolvedValue(null);
    const result = await loadRealtimePrincipal(fakePrisma(findUnique), 'nonexistent');

    expect(result).toBeNull();
    expect(findUnique).toHaveBeenCalledWith({ where: { id: 'nonexistent' }, include: { roles: true } });
  });

  it('maps a found user + role assignments to a RealtimePrincipal', async () => {
    const findUnique = vi.fn().mockResolvedValue({
      id: 'user_1',
      organisationId: 'org_1',
      email: 'a@example.com',
      roles: [
        { id: 'ur_1', userId: 'user_1', role: 'operator', siteId: null },
        { id: 'ur_2', userId: 'user_1', role: 'dispatcher', siteId: 'site_1' },
      ],
    });

    const result = await loadRealtimePrincipal(fakePrisma(findUnique), 'user_1');

    // WP-17/D1: site_id is carried through, not discarded — Field room
    // membership is derived from it.
    expect(result).toEqual({
      user_id: 'user_1',
      organisation_id: 'org_1',
      roles: [
        { role: 'operator', site_id: null },
        { role: 'dispatcher', site_id: 'site_1' },
      ],
    });
  });

  it('returns a user with an empty roles array unchanged (no roles assigned yet)', async () => {
    const findUnique = vi.fn().mockResolvedValue({ id: 'user_2', organisationId: 'org_2', roles: [] });
    const result = await loadRealtimePrincipal(fakePrisma(findUnique), 'user_2');
    expect(result).toEqual({ user_id: 'user_2', organisation_id: 'org_2', roles: [] });
  });
});
