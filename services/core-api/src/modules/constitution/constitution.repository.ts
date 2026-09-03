/**
 * SENTINEL — versioned constitution policy storage (WP-06 mandatory addition 3).
 *
 * Architecture reference: §5.1 — the Constitution is versioned and audited; no version is ever
 * overwritten, and exactly one version is active at a time.
 *
 * SINGLE-ACTIVE INVARIANT
 * -----------------------
 * The natural expression of "exactly one active version" is a partial unique index
 * (`... UNIQUE (status) WHERE status = 'active'`). Prisma's schema DSL cannot express a
 * filtered unique index, so this repository enforces it transactionally instead:
 * `activate()` runs at Serializable isolation, retires the incumbent, activates the successor
 * and re-counts the active rows inside the same transaction, aborting if the count is not
 * exactly 1. Serializable isolation is what makes the read-then-write safe against a
 * concurrent activation — the loser of the race aborts rather than producing a second active
 * row. The lead adds the raw-SQL partial index in the consolidated migration, at which point
 * the database enforces the same invariant independently; the transactional guard is kept
 * because it also produces a diagnosable error rather than a bare constraint violation.
 *
 * The column set is exactly the directive's: there is deliberately no `activated_by`. Who
 * approved an activation, and on what evidence, is recorded in the Decision Ledger entry that
 * the gating evaluation emits — duplicating it here would create a second, unaudited record
 * of the same fact.
 */

import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { Policy } from './constitution.engine';
import { policyContentSha256 } from './constitution.hash';
import { SENTINEL_BASELINE_POLICY, policyBody } from './constitution.policy';
import { assertValidPolicy } from './constitution.validation';

export type PolicyStatus = 'draft' | 'active' | 'retired';

export interface StoredPolicy {
  readonly id: string;
  readonly version: string;
  readonly body: unknown;
  readonly contentSha256: string;
  readonly status: PolicyStatus;
  readonly createdBy: string;
  readonly createdAt: Date;
  readonly activatedAt: Date | null;
}

/** How many times a losing boot re-attempts the baseline seed before failing loudly. */
const BASELINE_SEED_ATTEMPTS = 5;

/** `created_by` marker for the baseline seeded at first boot (the bootstrap exemption). */
export const BOOTSTRAP_AUTHOR = 'system.bootstrap';

export class PolicyNotFoundError extends Error {
  constructor(readonly version: string) {
    super(`Constitution policy version '${version}' does not exist.`);
    this.name = 'PolicyNotFoundError';
  }
}

export class PolicyNotActivatableError extends Error {
  constructor(
    readonly version: string,
    readonly status: PolicyStatus,
  ) {
    super(
      `Constitution policy version '${version}' has status '${status}' and cannot be ` +
        `activated; a retired version must be re-issued under a new version.`,
    );
    this.name = 'PolicyNotActivatableError';
  }
}

export class SingleActivePolicyError extends Error {
  constructor(readonly activeCount: number) {
    super(
      `Constitution policy store would hold ${activeCount} active versions; exactly one is ` +
        `permitted. The activation was aborted.`,
    );
    this.name = 'SingleActivePolicyError';
  }
}

export class NoActivePolicyError extends Error {
  constructor() {
    super(
      'Constitution policy store holds no active version; the service cannot evaluate any ' +
        'action without an active constitution.',
    );
    this.name = 'NoActivePolicyError';
  }
}

interface StoredRow {
  id: string;
  version: string;
  body: Prisma.JsonValue;
  contentSha256: string;
  status: PolicyStatus;
  createdBy: string;
  createdAt: Date;
  activatedAt: Date | null;
}

function toStoredPolicy(row: StoredRow): StoredPolicy {
  return {
    id: row.id,
    version: row.version,
    body: row.body,
    contentSha256: row.contentSha256,
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    activatedAt: row.activatedAt,
  };
}

/** A concurrent boot won the seed race (unique version) or lost a serialisable transaction. */
function isConcurrentWriteConflict(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  // P2002 unique constraint, P2034 transaction write conflict / deadlock.
  return error.code === 'P2002' || error.code === 'P2034';
}

@Injectable()
export class ConstitutionPolicyRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async findActive(): Promise<StoredPolicy | null> {
    const row = await this.prisma.constitutionPolicy.findFirst({ where: { status: 'active' } });
    return row === null ? null : toStoredPolicy(row);
  }

  async findByVersion(version: string): Promise<StoredPolicy | null> {
    const row = await this.prisma.constitutionPolicy.findUnique({ where: { version } });
    return row === null ? null : toStoredPolicy(row);
  }

  async count(): Promise<number> {
    return this.prisma.constitutionPolicy.count();
  }

  /**
   * Stores a new policy version as a draft. Never activates it: activation is a
   * Constitution-gated action (see `ConstitutionService.activatePolicy`).
   *
   * The policy is validated before it is written, so an incoherent constitution cannot even
   * reach the store, let alone be activated later.
   */
  async createDraft(policy: Policy, createdBy: string): Promise<StoredPolicy> {
    assertValidPolicy(policy);
    const row = await this.prisma.constitutionPolicy.create({
      data: {
        version: policy.version,
        body: policyBody(policy) as Prisma.InputJsonObject,
        contentSha256: policyContentSha256(policy),
        status: 'draft',
        createdBy,
      },
    });
    return toStoredPolicy(row);
  }

  /**
   * Makes `version` the single active policy, retiring whichever version was active.
   *
   * Idempotent: activating the already-active version is a no-op that still re-asserts the
   * single-active invariant.
   */
  async activate(version: string): Promise<StoredPolicy> {
    return this.prisma.$transaction(
      async (tx) => {
        const target = await tx.constitutionPolicy.findUnique({ where: { version } });
        if (target === null) throw new PolicyNotFoundError(version);
        if (target.status === 'retired') {
          throw new PolicyNotActivatableError(version, target.status);
        }

        if (target.status !== 'active') {
          await tx.constitutionPolicy.updateMany({
            where: { status: 'active', version: { not: version } },
            data: { status: 'retired' },
          });
          await tx.constitutionPolicy.update({
            where: { version },
            data: { status: 'active', activatedAt: new Date() },
          });
        }

        const activeCount = await tx.constitutionPolicy.count({ where: { status: 'active' } });
        if (activeCount !== 1) throw new SingleActivePolicyError(activeCount);

        const activated = await tx.constitutionPolicy.findUniqueOrThrow({ where: { version } });
        return toStoredPolicy(activated);
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    );
  }

  /**
   * BOOTSTRAP EXEMPTION (documented, deliberate).
   *
   * Every change to the constitution is gated by the constitution itself — except the very
   * first one, which cannot be: there is no policy to evaluate against, and no approver could
   * hold authority granted by a policy that does not exist yet. So when the table is empty,
   * and only then, the certified baseline is inserted directly as the active version, authored
   * by `system.bootstrap`. From that moment on every further activation goes through
   * `constitution.rules.alter.core` (two-person). The exemption is visible in the audit trail:
   * exactly one row can ever carry `created_by = 'system.bootstrap'` with no gating decision.
   *
   * Safe under concurrent boots: the insert races on the unique `version`, and the loser
   * treats the conflict as "already seeded".
   */
  async ensureBaselineSeeded(): Promise<void> {
    // WP-26: RETRY, RATHER THAN ASSUME THE WINNER HAS COMMITTED.
    //
    // This used to swallow a concurrent-write conflict once and return,
    // reasoning that "another instance seeded the baseline first; its row is
    // the one we will load". That reasoning has a gap. A serialization failure
    // aborts THIS transaction at the moment the conflict is detected, which is
    // not the moment the other transaction COMMITS — so a caller that returns
    // immediately can go on to `findActive()` and legitimately see nothing,
    // and `reload()` then throws `NoActivePolicyError` on a database that is
    // about to be perfectly well seeded.
    //
    // It is not a test artefact. Any fresh deployment whose API replicas boot
    // simultaneously against an empty database can lose this race, and the
    // symptom is a crash in `onModuleInit` rather than a retryable error.
    //
    // Re-running is both safe and sufficient: the transaction's first act is a
    // count, so a later attempt either OBSERVES the committed baseline and
    // returns, or finds the table still empty and inserts it. The final attempt
    // deliberately does not swallow — if we genuinely cannot make progress, a
    // loud failure is better than a service that believes it has a
    // constitution and does not.
    for (let attempt = 1; attempt <= BASELINE_SEED_ATTEMPTS; attempt += 1) {
      try {
        await this.seedBaselineOnce();
        return;
      } catch (error: unknown) {
        if (!isConcurrentWriteConflict(error)) throw error;
        if (attempt === BASELINE_SEED_ATTEMPTS) throw error;
      }
    }
  }

  private async seedBaselineOnce(): Promise<void> {
    await this.prisma.$transaction(
      async (tx) => {
        const existing = await tx.constitutionPolicy.count();
        if (existing > 0) return;

        assertValidPolicy(SENTINEL_BASELINE_POLICY);
        await tx.constitutionPolicy.create({
          data: {
            version: SENTINEL_BASELINE_POLICY.version,
            body: policyBody(SENTINEL_BASELINE_POLICY) as Prisma.InputJsonObject,
            contentSha256: policyContentSha256(SENTINEL_BASELINE_POLICY),
            status: 'active',
            createdBy: BOOTSTRAP_AUTHOR,
            activatedAt: new Date(),
          },
        });
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    );
  }
}
