/**
 * Milestone-1 fixture seed for the Identity & Organisation domain
 * (WP-03 acceptance criterion #5). This is a standalone script, not
 * wired through Prisma's `prisma db seed` / package.json "prisma.seed"
 * (that config is owned by the lead). It has no NestJS DI dependency —
 * just PrismaClient directly — and compiles through the service's normal
 * `tsc` build since it lives under `src/`.
 *
 * Run:
 *   pnpm --filter core-api build
 *   node dist/modules/identity/seed.js
 *
 * Idempotent: every row is upserted by a deterministic id (not by the
 * DB-level compound unique on UserRole, which does not de-duplicate
 * organisation-wide/null-scoped rows under Postgres — see identity.prisma),
 * so running this script any number of times converges on the same state.
 */
import { PrismaClient } from '@prisma/client';
import type { Role } from './roles';

export interface IdentitySeedFixture {
  readonly organisation: { readonly id: string; readonly name: string };
  readonly site: { readonly id: string; readonly name: string };
  readonly zones: ReadonlyArray<{ readonly id: string; readonly name: string }>;
  readonly users: ReadonlyArray<SeedUser>;
}

export interface SeedUser {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly clearance: number;
  readonly role: Role;
  /** Operational roles are scoped to the fixture site; oversight roles are organisation-wide. */
  readonly siteScoped: boolean;
}

export const DEFAULT_IDENTITY_SEED: IdentitySeedFixture = {
  organisation: { id: 'org_alpha', name: 'Alpha Site Security' },
  site: { id: 'site_hq', name: 'HQ' },
  zones: [
  { id: 'zone_lobby', name: 'Lobby' },
  { id: 'zone_vault_corridor', name: 'Vault Corridor' },
  { id: 'zone_perimeter', name: 'Perimeter' },
  ],
  users: [
  { id: 'user_site_commander', email: 'site.commander@alpha.test', displayName: 'Site Commander', clearance: 4, role: 'site.commander', siteScoped: true },
  { id: 'user_operator', email: 'operator@alpha.test', displayName: 'Control-Room Operator', clearance: 3, role: 'operator', siteScoped: true },
  { id: 'user_dispatcher', email: 'dispatcher@alpha.test', displayName: 'Dispatcher', clearance: 3, role: 'dispatcher', siteScoped: true },
  { id: 'user_field_operative', email: 'field.operative@alpha.test', displayName: 'Field Operative', clearance: 3, role: 'field.operative', siteScoped: true },
  { id: 'user_investigator', email: 'investigator@alpha.test', displayName: 'Investigator', clearance: 3, role: 'investigator', siteScoped: false },
  { id: 'user_evidence_custodian', email: 'evidence.custodian@alpha.test', displayName: 'Evidence Custodian', clearance: 4, role: 'evidence.custodian', siteScoped: false },
  { id: 'user_admin', email: 'admin@alpha.test', displayName: 'Administrator', clearance: 5, role: 'admin', siteScoped: false },
  ],
};

/** Seed one deterministic identity fixture. Safe for both the standalone seed and live tests. */
export async function seedIdentity(prismaClient: PrismaClient, fixture: IdentitySeedFixture = DEFAULT_IDENTITY_SEED): Promise<void> {
  await prismaClient.organisation.upsert({
    where: { id: fixture.organisation.id },
    create: { id: fixture.organisation.id, name: fixture.organisation.name },
    update: { name: fixture.organisation.name },
  });

  await prismaClient.site.upsert({
    where: { id: fixture.site.id },
    create: { id: fixture.site.id, organisationId: fixture.organisation.id, name: fixture.site.name },
    update: { organisationId: fixture.organisation.id, name: fixture.site.name },
  });

  for (const zone of fixture.zones) {
    await prismaClient.zone.upsert({
      where: { id: zone.id },
      create: { id: zone.id, siteId: fixture.site.id, name: zone.name },
      update: { siteId: fixture.site.id, name: zone.name },
    });
  }

  for (const seedUser of fixture.users) {
    await prismaClient.user.upsert({
      where: { id: seedUser.id },
      create: {
        id: seedUser.id,
        organisationId: fixture.organisation.id,
        email: seedUser.email,
        displayName: seedUser.displayName,
        clearance: seedUser.clearance,
      },
      update: {
        organisationId: fixture.organisation.id,
        email: seedUser.email,
        displayName: seedUser.displayName,
        clearance: seedUser.clearance,
      },
    });

    const roleAssignmentId = `${seedUser.id}__${seedUser.role}`;
    const siteId = seedUser.siteScoped ? fixture.site.id : null;
    await prismaClient.userRole.upsert({
      where: { id: roleAssignmentId },
      create: { id: roleAssignmentId, userId: seedUser.id, role: seedUser.role, siteId },
      update: { role: seedUser.role, siteId },
    });
  }
}

async function main(): Promise<void> {
  const prisma = new PrismaClient();
  try {
    await seedIdentity(prisma);
    console.log(`Seed complete: 1 org, 1 site, ${DEFAULT_IDENTITY_SEED.zones.length} zones, ${DEFAULT_IDENTITY_SEED.users.length} users.`);
  } finally {
    await prisma.$disconnect();
  }
}

// Keep imports side-effect free so live integration tests can reuse the
// fixture function without opening a second Prisma connection or seeding the
// default tenant. The compiled standalone path remains deterministic.
const invokedFile = process.argv[1] ?? '';
if (invokedFile.endsWith('/seed.js') || invokedFile.endsWith('\\seed.js')) {
  void main().catch((error: unknown) => {
    console.error('Seed failed:', error);
    process.exitCode = 1;
  });
}
