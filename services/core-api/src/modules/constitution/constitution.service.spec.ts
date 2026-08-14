/**
 * SENTINEL — ConstitutionService: boot gate, ledger guarantee and the self-gated activation
 * flow (WP-06 mandatory additions 2, 3 and 4).
 *
 * The repository is faked in memory so these tests assert the *service's* behaviour without a
 * database; `constitution.repository.spec.ts` covers the storage invariants separately.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import type { Actor, ConstitutionRequest, Policy } from './constitution.engine';
import { policyContentSha256 } from './constitution.hash';
import { SENTINEL_BASELINE_POLICY, policyBody } from './constitution.policy';
import {
  BOOTSTRAP_AUTHOR,
  ConstitutionPolicyRepository,
  NoActivePolicyError,
  PolicyNotFoundError,
  type PolicyStatus,
  type StoredPolicy,
} from './constitution.repository';
import {
  ConstitutionNotLoadedError,
  ConstitutionService,
  PLATFORM_ORGANISATION_ID,
  PolicyIntegrityError,
} from './constitution.service';
import { PolicyShapeError } from './constitution.policy';
import { PolicyValidationError } from './constitution.validation';
import type { DecisionRecord } from './decision-record';
import type { LedgerSink } from './ledger.sink';

const ORG = 'org-sentinel-1';

/* -------------------------------------------------------------------------- */
/* Doubles                                                                    */
/* -------------------------------------------------------------------------- */

let rowCounter = 0;

function makeRow(
  body: unknown,
  version: string,
  status: PolicyStatus,
  createdBy: string,
  contentSha256?: string,
): StoredPolicy {
  rowCounter += 1;
  return {
    id: `row-${rowCounter}`,
    version,
    body,
    contentSha256: contentSha256 ?? policyContentSha256(body as Policy),
    status,
    createdBy,
    createdAt: new Date('2026-08-14T09:00:00.000Z'),
    activatedAt: status === 'active' ? new Date('2026-08-14T09:00:00.000Z') : null,
  };
}

function storedFrom(policy: Policy, status: PolicyStatus, createdBy: string): StoredPolicy {
  return makeRow(policyBody(policy), policy.version, status, createdBy);
}

class FakeRepository {
  rows: StoredPolicy[] = [];
  seedCalls = 0;

  ensureBaselineSeeded(): Promise<void> {
    this.seedCalls += 1;
    if (this.rows.length === 0) {
      this.rows.push(storedFrom(SENTINEL_BASELINE_POLICY, 'active', BOOTSTRAP_AUTHOR));
    }
    return Promise.resolve();
  }

  findActive(): Promise<StoredPolicy | null> {
    return Promise.resolve(this.rows.find((row) => row.status === 'active') ?? null);
  }

  findByVersion(version: string): Promise<StoredPolicy | null> {
    return Promise.resolve(this.rows.find((row) => row.version === version) ?? null);
  }

  count(): Promise<number> {
    return Promise.resolve(this.rows.length);
  }

  createDraft(policy: Policy, createdBy: string): Promise<StoredPolicy> {
    const row = storedFrom(policy, 'draft', createdBy);
    this.rows.push(row);
    return Promise.resolve(row);
  }

  activate(version: string): Promise<StoredPolicy> {
    const target = this.rows.find((row) => row.version === version);
    if (target === undefined) return Promise.reject(new PolicyNotFoundError(version));
    this.rows = this.rows.map((row) => {
      if (row.version === version) {
        return { ...row, status: 'active', activatedAt: new Date('2026-08-14T12:00:00.000Z') };
      }
      return row.status === 'active' ? { ...row, status: 'retired' } : row;
    });
    return Promise.resolve(this.rows.find((row) => row.version === version) as StoredPolicy);
  }
}

class RecordingSink implements LedgerSink {
  readonly entries: DecisionRecord[] = [];
  failNext = false;

  append(entry: DecisionRecord): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error('ledger unavailable'));
    }
    this.entries.push(entry);
    return Promise.resolve();
  }
}

function makeService(repository: FakeRepository, sink: RecordingSink): ConstitutionService {
  return new ConstitutionService(
    repository as unknown as ConstitutionPolicyRepository,
    sink,
  );
}

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

function baselineCopy(version: string): Policy {
  const copy = JSON.parse(JSON.stringify(SENTINEL_BASELINE_POLICY)) as Policy;
  return { ...copy, version };
}

// WP-14/M3: altering the constitution requires PLATFORM authority, so the
// steward acts in the platform organisation (target is the platform singleton).
const steward = (overrides: Partial<Actor> = {}): Actor => ({
  userId: 'u-steward',
  roles: ['constitution.steward'],
  organisationId: PLATFORM_ORGANISATION_ID,
  clearance: 4,
  deviceTrust: 'TRUSTED',
  purpose: 'Adopt constitution 1.2.0 per change board CR-118',
  ...overrides,
});

const TWO_AUTHORISED_APPROVERS = {
  approvals: [
    { userId: 'u-director', role: 'org.security.director', at: '2026-08-14T11:00:00.000Z' },
    { userId: 'u-admin', role: 'platform.admin', at: '2026-08-14T11:05:00.000Z' },
  ],
  approver_roles: {
    'u-director': ['org.security.director'],
    'u-admin': ['platform.admin'],
  },
};

function readRequest(): ConstitutionRequest {
  return {
    action: 'incident.view',
    actor: {
      userId: 'u-analyst',
      roles: ['analyst'],
      organisationId: ORG,
      clearance: 1,
      deviceTrust: 'TRUSTED',
    },
    target: { organisationId: ORG, classification: 'INTERNAL', classificationLevel: 1 },
  };
}

/* -------------------------------------------------------------------------- */
/* Tests                                                                      */
/* -------------------------------------------------------------------------- */

let repository: FakeRepository;
let sink: RecordingSink;
let service: ConstitutionService;

beforeEach(() => {
  repository = new FakeRepository();
  sink = new RecordingSink();
  service = makeService(repository, sink);
});

describe('boot: seeding and loading the active policy', () => {
  it('seeds the certified baseline on an empty store (the bootstrap exemption)', async () => {
    await service.onModuleInit();

    expect(repository.rows).toHaveLength(1);
    expect(repository.rows[0]?.createdBy).toBe(BOOTSTRAP_AUTHOR);
    expect(repository.rows[0]?.status).toBe('active');
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
    expect(service.activePolicy.policy).toEqual(SENTINEL_BASELINE_POLICY);
  });

  it('does not re-seed when a policy is already stored', async () => {
    repository.rows.push(storedFrom(baselineCopy('sentinel-constitution-9.9.9'), 'active', 'u-1'));
    await service.onModuleInit();

    expect(repository.rows).toHaveLength(1);
    expect(service.activePolicy.version).toBe('sentinel-constitution-9.9.9');
  });

  it('exposes the active version and content hash as metadata', async () => {
    await service.onModuleInit();

    expect(service.activePolicyMetadata).toMatchObject({
      version: SENTINEL_BASELINE_POLICY.version,
      content_sha256: policyContentSha256(SENTINEL_BASELINE_POLICY),
      status: 'active',
    });
    expect(service.activePolicyMetadata.activated_at).toBe('2026-08-14T09:00:00.000Z');
  });

  it('refuses to boot when the active policy breaks a validation rule', async () => {
    const broken = baselineCopy('sentinel-constitution-broken');
    broken.categories['exceptional_tracking_powers'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
      approval_roles: [],
    };
    repository.rows.push(storedFrom(broken, 'active', 'u-1'));

    await expect(service.onModuleInit()).rejects.toBeInstanceOf(PolicyValidationError);
  });

  it('refuses to boot when the active policy body is not a policy at all', async () => {
    repository.rows.push(makeRow({ nonsense: true }, 'sentinel-constitution-junk', 'active', 'u-1'));

    await expect(service.onModuleInit()).rejects.toBeInstanceOf(PolicyShapeError);
  });

  it('refuses to boot when the stored hash does not match the stored body', async () => {
    const policy = baselineCopy('sentinel-constitution-tampered');
    repository.rows.push(
      makeRow(policyBody(policy), policy.version, 'active', 'u-1', 'deadbeef'.repeat(8)),
    );

    await expect(service.onModuleInit()).rejects.toBeInstanceOf(PolicyIntegrityError);
  });

  it('refuses to boot when the row version disagrees with the body version', async () => {
    const policy = baselineCopy('sentinel-constitution-body');
    repository.rows.push(
      makeRow(policyBody(policy), 'sentinel-constitution-row', 'active', 'u-1'),
    );

    await expect(service.onModuleInit()).rejects.toBeInstanceOf(PolicyIntegrityError);
  });

  it('refuses to boot when versions exist but none is active', async () => {
    repository.rows.push(storedFrom(baselineCopy('sentinel-constitution-draft'), 'draft', 'u-1'));

    await expect(service.onModuleInit()).rejects.toBeInstanceOf(NoActivePolicyError);
  });

  it('refuses to evaluate before the constitution is loaded', async () => {
    await expect(service.evaluate(readRequest())).rejects.toBeInstanceOf(
      ConstitutionNotLoadedError,
    );
    expect(sink.entries).toHaveLength(0);
  });
});

describe('ledger: every evaluation emits exactly one record', () => {
  beforeEach(async () => {
    await service.onModuleInit();
  });

  it('emits one record per call, whatever the decision is', async () => {
    const requests: readonly ConstitutionRequest[] = [
      // ALLOW
      readRequest(),
      // DENY (unregistered action)
      { ...readRequest(), action: 'incident.teleport' },
      // DENY (prohibited action)
      { ...readRequest(), action: 'audit.ledger.delete' },
      // REQUIRE_APPROVAL
      {
        action: 'report.export.summary',
        actor: {
          userId: 'u-analyst',
          roles: ['analyst'],
          organisationId: ORG,
          clearance: 2,
          deviceTrust: 'TRUSTED',
          purpose: 'Quarterly regulator submission',
        },
        target: { organisationId: ORG, classification: 'SENSITIVE', classificationLevel: 2 },
      },
      // REQUIRE_TWO_PERSON
      {
        action: 'tracking.exceptional.enable',
        actor: {
          userId: 'u-officer',
          roles: ['security.officer'],
          organisationId: ORG,
          clearance: 4,
          deviceTrust: 'TRUSTED',
          purpose: 'Warrant 2026-118',
        },
        target: { organisationId: ORG, classification: 'RESTRICTED', classificationLevel: 3 },
      },
    ];

    const decisions = [];
    for (const request of requests) decisions.push(await service.evaluate(request));

    expect(decisions.map((d) => d.decision)).toEqual([
      'ALLOW',
      'DENY',
      'DENY',
      'REQUIRE_APPROVAL',
      'REQUIRE_TWO_PERSON',
    ]);
    expect(sink.entries).toHaveLength(requests.length);
    expect(sink.entries.map((e) => e.action_taken)).toEqual(decisions.map((d) => d.decision));
    // Every entry is individually identifiable and correlated.
    expect(new Set(sink.entries.map((e) => e.entry_id)).size).toBe(requests.length);
  });

  it('stamps the record with the active policy version and hash', async () => {
    await service.evaluate(readRequest());

    const entry = sink.entries[0];
    expect(entry?.policy_version).toBe(SENTINEL_BASELINE_POLICY.version);
    expect(entry?.inputs_snapshot['policy_content_sha256']).toBe(
      policyContentSha256(SENTINEL_BASELINE_POLICY),
    );
  });

  it('uses the supplied trace id so the entry correlates with the calling request', async () => {
    await service.evaluate(readRequest(), { traceId: 'trace-abc' });
    expect(sink.entries[0]?.trace_id).toBe('trace-abc');
  });

  it('fails the evaluation when the ledger rejects, rather than returning an unrecorded decision', async () => {
    sink.failNext = true;
    await expect(service.evaluate(readRequest())).rejects.toThrow('ledger unavailable');
    expect(sink.entries).toHaveLength(0);

    // The service is still usable afterwards.
    await service.evaluate(readRequest());
    expect(sink.entries).toHaveLength(1);
  });
});

describe('activation is gated by the constitution itself (§58.2)', () => {
  const NEXT_VERSION = 'sentinel-constitution-1.2.0';

  beforeEach(async () => {
    await service.onModuleInit();
    await service.createDraft(baselineCopy(NEXT_VERSION), 'u-steward');
  });

  it('refuses activation without two-person approval and changes nothing', async () => {
    const result = await service.activatePolicy({ version: NEXT_VERSION, actor: steward() });

    expect(result.activated).toBe(false);
    expect(result.decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
    expect(repository.rows.find((r) => r.version === NEXT_VERSION)?.status).toBe('draft');
    expect(repository.rows.find((r) => r.version === SENTINEL_BASELINE_POLICY.version)?.status)
      .toBe('active');
  });

  it('audits the refused attempt with exactly one ledger record', async () => {
    await service.activatePolicy({ version: NEXT_VERSION, actor: steward(), traceId: 'trace-1' });

    expect(sink.entries).toHaveLength(1);
    expect(sink.entries[0]?.action_taken).toBe('REQUIRE_TWO_PERSON');
    expect(sink.entries[0]?.inputs_snapshot['action']).toBe('constitution.rules.alter.core');
    expect(sink.entries[0]?.trace_id).toBe('trace-1');
  });

  it('refuses activation when only one approver is role-authorised', async () => {
    const result = await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward(),
      approvals: [
        ...TWO_AUTHORISED_APPROVERS.approvals,
      ],
      approver_roles: {
        'u-director': ['org.security.director'],
        // Claims platform.admin on the approval, but Identity resolved only 'viewer'.
        'u-admin': ['viewer'],
      },
    });

    expect(result.activated).toBe(false);
    expect(result.decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
  });

  it('refuses activation when the actor self-approves', async () => {
    const result = await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward(),
      approvals: [
        { userId: 'u-steward', role: 'constitution.steward', at: '2026-08-14T11:00:00.000Z' },
        { userId: 'u-director', role: 'org.security.director', at: '2026-08-14T11:00:00.000Z' },
      ],
      approver_roles: {
        'u-steward': ['constitution.steward'],
        'u-director': ['org.security.director'],
      },
    });

    expect(result.activated).toBe(false);
    expect(result.decision.decision).toBe('REQUIRE_TWO_PERSON');
  });

  it('refuses activation for an actor whose role does not grant the action', async () => {
    const result = await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward({ roles: ['analyst'] }),
      ...TWO_AUTHORISED_APPROVERS,
    });

    expect(result.activated).toBe(false);
    expect(result.decision.decision).toBe('DENY');
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
  });

  // M3 regression (WP-14): the constitution is a PLATFORM singleton. A tenant
  // actor (organisation != platform) fails ORGANISATION_MATCH, so no tenant can
  // alter the one global constitution — even with two authorised approvers.
  // Before the fix the target org was the actor's own org, so this self-matched.
  it('M3: a tenant actor (organisation != platform) is DENIED on ORGANISATION_MATCH and changes nothing', async () => {
    const result = await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward({ organisationId: 'org-tenant-x' }),
      ...TWO_AUTHORISED_APPROVERS,
    });

    expect(result.activated).toBe(false);
    expect(result.decision.decision).toBe('DENY');
    const orgCheck = result.decision.trace.find((e) => e.check === 'ORGANISATION_MATCH');
    expect(orgCheck?.outcome).toBe('FAIL');
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
  });

  it('activates with two distinct, role-authorised approvers and reloads the new policy', async () => {
    const result = await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward(),
      ...TWO_AUTHORISED_APPROVERS,
    });

    expect(result.decision.decision).toBe('ALLOW');
    expect(result.activated).toBe(true);
    expect(result.active.version).toBe(NEXT_VERSION);
    expect(service.activePolicy.version).toBe(NEXT_VERSION);
    expect(service.activePolicyMetadata.version).toBe(NEXT_VERSION);
    expect(repository.rows.find((r) => r.version === SENTINEL_BASELINE_POLICY.version)?.status)
      .toBe('retired');
    // One record: the gating evaluation. Activation itself is not a second evaluation.
    expect(sink.entries).toHaveLength(1);
    expect(sink.entries[0]?.action_taken).toBe('ALLOW');
  });

  it('subsequent evaluations use the newly activated policy version', async () => {
    await service.activatePolicy({
      version: NEXT_VERSION,
      actor: steward(),
      ...TWO_AUTHORISED_APPROVERS,
    });
    const decision = await service.evaluate(readRequest());

    expect(decision.policyVersion).toBe(NEXT_VERSION);
  });

  it('audits the attempt before revealing whether the version exists', async () => {
    await expect(
      service.activatePolicy({
        version: 'sentinel-constitution-does-not-exist',
        actor: steward(),
        ...TWO_AUTHORISED_APPROVERS,
      }),
    ).rejects.toBeInstanceOf(PolicyNotFoundError);

    expect(sink.entries).toHaveLength(1);
    expect(sink.entries[0]?.action_taken).toBe('ALLOW');
  });

  it('will not activate a stored version that fails validation', async () => {
    const broken = baselineCopy('sentinel-constitution-broken');
    broken.categories['alter_core_constitution_rules'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Alteration of core Constitution rules.',
      approval_roles: [],
    };
    repository.rows.push(storedFrom(broken, 'draft', 'u-1'));

    await expect(
      service.activatePolicy({
        version: 'sentinel-constitution-broken',
        actor: steward(),
        ...TWO_AUTHORISED_APPROVERS,
      }),
    ).rejects.toBeInstanceOf(PolicyValidationError);
    expect(service.activePolicy.version).toBe(SENTINEL_BASELINE_POLICY.version);
  });
});
