/**
 * SENTINEL — versioned policy storage invariants (WP-06 mandatory addition 3).
 *
 * Prisma is faked in memory: these tests pin the *repository's* contract — the bootstrap
 * exemption, the single-active invariant and its transactional enforcement — without needing a
 * live database in unit tests. The transaction boundary and isolation level are asserted
 * explicitly, because they are what makes the read-then-write safe.
 */

import { Prisma } from '@prisma/client';
import { beforeEach, describe, expect, it } from 'vitest';

import type { PrismaService } from '../../prisma/prisma.service';
import type { Policy } from './constitution.engine';
import { policyContentSha256 } from './constitution.hash';
import { SENTINEL_BASELINE_POLICY } from './constitution.policy';
import {
  BOOTSTRAP_AUTHOR,
  ConstitutionPolicyRepository,
  PolicyNotActivatableError,
  PolicyNotFoundError,
  SingleActivePolicyError,
  type PolicyStatus,
} from './constitution.repository';
import { PolicyValidationError } from './constitution.validation';

interface Row {
  id: string;
  version: string;
  body: unknown;
  contentSha256: string;
  status: PolicyStatus;
  createdBy: string;
  createdAt: Date;
  activatedAt: Date | null;
}

interface Where {
  version?: string | { not?: string };
  status?: PolicyStatus;
}

function matches(row: Row, where: Where | undefined): boolean {
  if (where === undefined) return true;
  if (where.status !== undefined && row.status !== where.status) return false;
  if (typeof where.version === 'string' && row.version !== where.version) return false;
  if (
    typeof where.version === 'object' &&
    where.version !== null &&
    where.version.not !== undefined &&
    row.version === where.version.not
  ) {
    return false;
  }
  return true;
}

class FakePrisma {
  rows: Row[] = [];
  isolationLevels: unknown[] = [];
  transactionDepth = 0;
  sabotageUpdateMany = false;
  createError: unknown = null;
  /** WP-26: lets a spec model a conflict that CLEARS on the retry, as a real competing boot does. */
  beforeCreate: (() => void) | null = null;
  private nextId = 0;

  readonly constitutionPolicy = {
    count: (args?: { where?: Where }): Promise<number> =>
      Promise.resolve(this.rows.filter((row) => matches(row, args?.where)).length),

    findFirst: (args?: { where?: Where }): Promise<Row | null> =>
      Promise.resolve(this.rows.find((row) => matches(row, args?.where)) ?? null),

    findUnique: (args: { where: Where }): Promise<Row | null> =>
      Promise.resolve(this.rows.find((row) => matches(row, args.where)) ?? null),

    findUniqueOrThrow: (args: { where: Where }): Promise<Row> => {
      const found = this.rows.find((row) => matches(row, args.where));
      if (found === undefined) return Promise.reject(new Error('row not found'));
      return Promise.resolve(found);
    },

    create: (args: { data: Omit<Row, 'id' | 'createdAt' | 'activatedAt'> & Partial<Row> }): Promise<Row> => {
      this.beforeCreate?.();
      if (this.createError !== null) return Promise.reject(this.createError);
      this.nextId += 1;
      const row: Row = {
        id: `row-${this.nextId}`,
        version: args.data.version,
        body: args.data.body,
        contentSha256: args.data.contentSha256,
        status: args.data.status ?? 'draft',
        createdBy: args.data.createdBy,
        createdAt: new Date('2026-08-14T09:00:00.000Z'),
        activatedAt: args.data.activatedAt ?? null,
      };
      this.rows.push(row);
      return Promise.resolve(row);
    },

    update: (args: { where: Where; data: Partial<Row> }): Promise<Row> => {
      const found = this.rows.find((row) => matches(row, args.where));
      if (found === undefined) return Promise.reject(new Error('row not found'));
      Object.assign(found, args.data);
      return Promise.resolve(found);
    },

    updateMany: (args: { where: Where; data: Partial<Row> }): Promise<{ count: number }> => {
      if (this.sabotageUpdateMany) return Promise.resolve({ count: 0 });
      const affected = this.rows.filter((row) => matches(row, args.where));
      for (const row of affected) Object.assign(row, args.data);
      return Promise.resolve({ count: affected.length });
    },
  };

  async $transaction<T>(
    fn: (tx: FakePrisma) => Promise<T>,
    options?: { isolationLevel?: unknown },
  ): Promise<T> {
    this.isolationLevels.push(options?.isolationLevel);
    this.transactionDepth += 1;
    try {
      return await fn(this);
    } finally {
      this.transactionDepth -= 1;
    }
  }
}

function makeRow(version: string, status: PolicyStatus, id: string): Row {
  return {
    id,
    version,
    body: {},
    contentSha256: 'x'.repeat(64),
    status,
    createdBy: 'u-1',
    createdAt: new Date('2026-08-14T09:00:00.000Z'),
    activatedAt: status === 'active' ? new Date('2026-08-14T09:00:00.000Z') : null,
  };
}

function draftPolicy(version: string): Policy {
  const copy = JSON.parse(JSON.stringify(SENTINEL_BASELINE_POLICY)) as Policy;
  return { ...copy, version };
}

let prisma: FakePrisma;
let repository: ConstitutionPolicyRepository;

beforeEach(() => {
  prisma = new FakePrisma();
  repository = new ConstitutionPolicyRepository(prisma as unknown as PrismaService);
});

describe('ensureBaselineSeeded: the bootstrap exemption', () => {
  it('seeds the certified baseline as the active version when the store is empty', async () => {
    await repository.ensureBaselineSeeded();

    expect(prisma.rows).toHaveLength(1);
    expect(prisma.rows[0]).toMatchObject({
      version: SENTINEL_BASELINE_POLICY.version,
      contentSha256: policyContentSha256(SENTINEL_BASELINE_POLICY),
      status: 'active',
      createdBy: BOOTSTRAP_AUTHOR,
    });
    expect(prisma.rows[0]?.activatedAt).toBeInstanceOf(Date);
  });

  it('seeds inside a serializable transaction', async () => {
    await repository.ensureBaselineSeeded();
    expect(prisma.isolationLevels).toEqual([Prisma.TransactionIsolationLevel.Serializable]);
  });

  it('does nothing when any version already exists', async () => {
    prisma.rows.push(makeRow('sentinel-constitution-9.9.9', 'active', 'row-existing'));
    await repository.ensureBaselineSeeded();

    expect(prisma.rows).toHaveLength(1);
    expect(prisma.rows[0]?.version).toBe('sentinel-constitution-9.9.9');
  });

  it('WP-26: retries a concurrent seed (unique violation) and succeeds once the winner is visible', async () => {
    // A unique violation means the winner's row really is committed, so the
    // retry's opening count observes it and returns without inserting again.
    prisma.createError = new Prisma.PrismaClientKnownRequestError('duplicate version', {
      code: 'P2002',
      clientVersion: 'test',
    });
    prisma.beforeCreate = () => {
      prisma.rows.push({
        id: 'winner',
        version: 'sentinel-constitution-1.0.0',
        body: {},
        contentSha256: 'x'.repeat(64),
        status: 'active',
        createdBy: 'system.bootstrap',
        createdAt: new Date('2026-08-14T09:00:00.000Z'),
        activatedAt: new Date('2026-08-14T09:00:00.000Z'),
      } as never);
    };

    await expect(repository.ensureBaselineSeeded()).resolves.toBeUndefined();
    expect(prisma.rows).toHaveLength(1);
  });

  it('WP-26: RETRIES a serialisation conflict rather than assuming the winner has committed', async () => {
    // The old behaviour swallowed the conflict once and returned, reasoning
    // that another instance had seeded the baseline. A serialization failure
    // aborts THIS transaction when the conflict is DETECTED, which is not when
    // the other transaction COMMITS - so returning immediately let `reload()`
    // read an empty store and throw NoActivePolicyError on a database that was
    // about to be perfectly well seeded. Any fresh deployment whose replicas
    // boot together could lose that race.
    let attempts = 0;
    prisma.beforeCreate = () => {
      attempts += 1;
      // Conflict once, as a competing boot would, then let the retry through.
      prisma.createError =
        attempts === 1
          ? new Prisma.PrismaClientKnownRequestError('write conflict', { code: 'P2034', clientVersion: 'test' })
          : null;
    };

    await expect(repository.ensureBaselineSeeded()).resolves.toBeUndefined();
    expect(attempts).toBeGreaterThan(1);
  });

  it('WP-26: fails LOUDLY when it cannot make progress, rather than booting unseeded', async () => {
    // A service that believes it has a constitution and does not is worse than
    // one that refuses to start.
    prisma.createError = new Prisma.PrismaClientKnownRequestError('write conflict', {
      code: 'P2034',
      clientVersion: 'test',
    });

    await expect(repository.ensureBaselineSeeded()).rejects.toThrow('write conflict');
  });

  it('propagates any other failure rather than booting on an unseeded store', async () => {
    prisma.createError = new Error('disk on fire');
    await expect(repository.ensureBaselineSeeded()).rejects.toThrow('disk on fire');
  });
});

describe('createDraft', () => {
  it('stores a validated policy as a draft with its content hash', async () => {
    const policy = draftPolicy('sentinel-constitution-1.2.0');
    const stored = await repository.createDraft(policy, 'u-steward');

    expect(stored.status).toBe('draft');
    expect(stored.createdBy).toBe('u-steward');
    expect(stored.contentSha256).toBe(policyContentSha256(policy));
    expect(stored.activatedAt).toBeNull();
  });

  it('refuses to store an invalid policy at all', async () => {
    const policy = draftPolicy('sentinel-constitution-bad');
    policy.categories['alter_core_constitution_rules'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Alteration of core Constitution rules.',
      approval_roles: [],
    };

    await expect(repository.createDraft(policy, 'u-steward')).rejects.toBeInstanceOf(
      PolicyValidationError,
    );
    expect(prisma.rows).toHaveLength(0);
  });
});

describe('activate: the single-active invariant', () => {
  beforeEach(() => {
    prisma.rows.push(makeRow('v1', 'active', 'row-1'));
    prisma.rows.push(makeRow('v2', 'draft', 'row-2'));
  });

  it('retires the incumbent and activates the successor, leaving exactly one active', async () => {
    const activated = await repository.activate('v2');

    expect(activated.status).toBe('active');
    expect(activated.activatedAt).toBeInstanceOf(Date);
    expect(prisma.rows.filter((row) => row.status === 'active').map((r) => r.version)).toEqual([
      'v2',
    ]);
    expect(prisma.rows.find((row) => row.version === 'v1')?.status).toBe('retired');
  });

  it('runs the whole switch in one serializable transaction', async () => {
    await repository.activate('v2');
    expect(prisma.isolationLevels).toEqual([Prisma.TransactionIsolationLevel.Serializable]);
  });

  it('is idempotent for the already-active version', async () => {
    const before = prisma.rows.find((row) => row.version === 'v1')?.activatedAt;
    const activated = await repository.activate('v1');

    expect(activated.status).toBe('active');
    expect(activated.activatedAt).toEqual(before);
    expect(prisma.rows.filter((row) => row.status === 'active')).toHaveLength(1);
  });

  it('rejects an unknown version', async () => {
    await expect(repository.activate('v-nope')).rejects.toBeInstanceOf(PolicyNotFoundError);
    expect(prisma.rows.find((row) => row.version === 'v1')?.status).toBe('active');
  });

  it('refuses to resurrect a retired version', async () => {
    prisma.rows.push(makeRow('v0', 'retired', 'row-0'));
    await expect(repository.activate('v0')).rejects.toBeInstanceOf(PolicyNotActivatableError);
    expect(prisma.rows.filter((row) => row.status === 'active').map((r) => r.version)).toEqual([
      'v1',
    ]);
  });

  it('aborts when the transaction would leave more than one active version', async () => {
    // Simulates the retirement failing to take effect (e.g. a concurrent writer re-activating
    // a row). The in-transaction re-count is the backstop until the partial unique index exists.
    prisma.sabotageUpdateMany = true;

    await expect(repository.activate('v2')).rejects.toBeInstanceOf(SingleActivePolicyError);
  });
});

describe('reads', () => {
  it('finds the active version and looks versions up by name', async () => {
    prisma.rows.push(makeRow('v1', 'retired', 'row-1'));
    prisma.rows.push(makeRow('v2', 'active', 'row-2'));

    expect((await repository.findActive())?.version).toBe('v2');
    expect((await repository.findByVersion('v1'))?.status).toBe('retired');
    expect(await repository.findByVersion('v-nope')).toBeNull();
    expect(await repository.count()).toBe(2);
  });

  it('returns null when there is no active version', async () => {
    prisma.rows.push(makeRow('v1', 'draft', 'row-1'));
    expect(await repository.findActive()).toBeNull();
  });
});
