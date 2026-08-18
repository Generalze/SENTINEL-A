import type { PrismaService } from '../../prisma/prisma.service';
import type { RealtimePrincipal } from './realtime.types';

/**
 * Development-only loader used by the Socket.IO handshake until production
 * identity-provider integration is enabled.
 * ---------------------
 * Defensive local principal loader for the realtime gateway's WS handshake
 * auth (WP-12 deliverable #2). Deliberately duplicates — rather than
 * imports — the query shape of identity's `DevAuthGuard`
 * (`src/modules/identity/dev-auth.guard.ts`): WP-03 is concurrent work in
 * this same tree and this module's coordination lane forbids taking a
 * build-time dependency on `src/modules/identity`. This is a small,
 * direct Prisma query, not a re-implementation of any real auth policy.
 *
 * Unlike the events/constitution modules' guards (which fall back to an
 * "allow through, no principal" dev bypass), the WS gateway needs a real
 * per-connection identity to pick the org room — so this loader is not
 * deferred/stubbed, it actually queries the DB. The lead replaces this
 * with a call into the real identity principal loader once WS auth is
 * wired through the real guard chain; nothing else in this module should
 * need to change (see `realtime.gateway.ts`'s `authenticate`).
 */
export async function loadRealtimePrincipal(prisma: PrismaService, userId: string): Promise<RealtimePrincipal | null> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { roles: true },
  });
  if (!user) {
    return null;
  }
  return {
    user_id: user.id,
    organisation_id: user.organisationId,
    // WP-17/D1: `site_id` is carried through, not discarded — Field room
    // membership is derived from it.
    roles: user.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId ?? null })),
  };
}
