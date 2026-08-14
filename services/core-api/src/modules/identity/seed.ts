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

const prisma = new PrismaClient();

const ORG_ID = 'org_alpha';
const ORG_NAME = 'Alpha Site Security';
const SITE_ID = 'site_hq';
const SITE_NAME = 'HQ';

const ZONES: ReadonlyArray<{ id: string; name: string }> = [
  { id: 'zone_lobby', name: 'Lobby' },
  { id: 'zone_vault_corridor', name: 'Vault Corridor' },
  { id: 'zone_perimeter', name: 'Perimeter' },
];

interface SeedUser {
  id: string;
  email: string;
  displayName: string;
  clearance: number;
  role: Role;
  /** Operational roles are scoped to SITE_HQ; oversight roles are organisation-wide (site_id null). */
  siteScoped: boolean;
}

const SEED_USERS: ReadonlyArray<SeedUser> = [
  { id: 'user_site_commander', email: 'site.commander@alpha.test', displayName: 'Site Commander', clearance: 4, role: 'site.commander', siteScoped: true },
  { id: 'user_operator', email: 'operator@alpha.test', displayName: 'Control-Room Operator', clearance: 3, role: 'operator', siteScoped: true },
  { id: 'user_dispatcher', email: 'dispatcher@alpha.test', displayName: 'Dispatcher', clearance: 3, role: 'dispatcher', siteScoped: true },
  { id: 'user_field_operative', email: 'field.operative@alpha.test', displayName: 'Field Operative', clearance: 3, role: 'field.operative', siteScoped: true },
  { id: 'user_investigator', email: 'investigator@alpha.test', displayName: 'Investigator', clearance: 3, role: 'investigator', siteScoped: false },
  { id: 'user_evidence_custodian', email: 'evidence.custodian@alpha.test', displayName: 'Evidence Custodian', clearance: 4, role: 'evidence.custodian', siteScoped: false },
  { id: 'user_admin', email: 'admin@alpha.test', displayName: 'Administrator', clearance: 5, role: 'admin', siteScoped: false },
];

async function main(): Promise<void> {
  await prisma.organisation.upsert({
    where: { id: ORG_ID },
    create: { id: ORG_ID, name: ORG_NAME },
    update: { name: ORG_NAME },
  });

  await prisma.site.upsert({
    where: { id: SITE_ID },
    create: { id: SITE_ID, organisationId: ORG_ID, name: SITE_NAME },
    update: { organisationId: ORG_ID, name: SITE_NAME },
  });

  for (const zone of ZONES) {
    await prisma.zone.upsert({
      where: { id: zone.id },
      create: { id: zone.id, siteId: SITE_ID, name: zone.name },
      update: { siteId: SITE_ID, name: zone.name },
    });
  }

  for (const seedUser of SEED_USERS) {
    await prisma.user.upsert({
      where: { id: seedUser.id },
      create: {
        id: seedUser.id,
        organisationId: ORG_ID,
        email: seedUser.email,
        displayName: seedUser.displayName,
        clearance: seedUser.clearance,
      },
      update: {
        organisationId: ORG_ID,
        email: seedUser.email,
        displayName: seedUser.displayName,
        clearance: seedUser.clearance,
      },
    });

    const roleAssignmentId = `${seedUser.id}__${seedUser.role}`;
    const siteId = seedUser.siteScoped ? SITE_ID : null;
    await prisma.userRole.upsert({
      where: { id: roleAssignmentId },
      create: { id: roleAssignmentId, userId: seedUser.id, role: seedUser.role, siteId },
      update: { role: seedUser.role, siteId },
    });
  }

  console.log(`Seed complete: 1 org, 1 site, ${ZONES.length} zones, ${SEED_USERS.length} users.`);
}

main()
  .catch((error: unknown) => {
    console.error('Seed failed:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
