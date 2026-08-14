/**
 * SENTINEL — Constitution service.
 *
 * The in-process entry point every other module uses: `evaluate(request)`.
 *
 * Responsibilities beyond the pure evaluator:
 *  - load the active policy at boot, and refuse to start if it is invalid (§5.1);
 *  - emit exactly one Decision Ledger record per evaluation, on every path (§62.1);
 *  - gate changes to the constitution with the constitution itself (§58.2).
 *
 * Identity (WP-03) is deliberately absent: approver roles arrive as resolved data on the
 * request (`approver_roles`). In-process callers resolve them from Identity at call time; that
 * wiring is lead work at integration.
 */

import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  CLASSIFICATION_LEVELS,
  CONSTITUTION_ENGINE_VERSION,
  evaluate as evaluateRequest,
  type Actor,
  type Approval,
  type ApproverRoles,
  type Classification,
  type ConstitutionDecision,
  type ConstitutionRequest,
  type Policy,
} from './constitution.engine';
import { policyContentSha256 } from './constitution.hash';
import { CONSTITUTION_ALTER_ACTION, parsePolicy } from './constitution.policy';
import {
  ConstitutionPolicyRepository,
  NoActivePolicyError,
  PolicyNotFoundError,
  type StoredPolicy,
} from './constitution.repository';
import { assertValidPolicy } from './constitution.validation';
import { buildDecisionRecord } from './decision-record';
import { LEDGER_SINK, type LedgerSink } from './ledger.sink';

/** The constitution document itself, as an evaluation target. */
const CONSTITUTION_TARGET_CLASSIFICATION: Classification = 'RESTRICTED';

export interface LoadedPolicy {
  readonly policy: Policy;
  readonly version: string;
  readonly contentSha256: string;
  readonly createdBy: string;
  readonly activatedAt: Date | null;
}

export interface ActivePolicyMetadata {
  readonly version: string;
  readonly content_sha256: string;
  readonly status: 'active';
  readonly activated_at: string | null;
  readonly engine_version: string;
}

export interface EvaluateOptions {
  /** Correlates the ledger entry with the request that caused it; generated when absent. */
  readonly traceId?: string;
}

export interface ActivatePolicyCommand {
  readonly version: string;
  readonly actor: Actor;
  readonly approvals?: readonly Approval[];
  readonly approver_roles?: ApproverRoles;
  readonly traceId?: string;
}

export interface ActivationResult {
  readonly activated: boolean;
  /** The gating decision. When it is not ALLOW, nothing was changed. */
  readonly decision: ConstitutionDecision;
  /** The policy that is active after the attempt — unchanged unless `activated` is true. */
  readonly active: LoadedPolicy;
}

/** The stored hash or version does not match the stored body: the row has been tampered with. */
export class PolicyIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyIntegrityError';
  }
}

export class ConstitutionNotLoadedError extends Error {
  constructor() {
    super(
      'Constitution has not been loaded; no action may be evaluated until an active policy ' +
        'is in force.',
    );
    this.name = 'ConstitutionNotLoadedError';
  }
}

@Injectable()
export class ConstitutionService implements OnModuleInit {
  private loaded: LoadedPolicy | null = null;

  constructor(
    @Inject(ConstitutionPolicyRepository)
    private readonly repository: ConstitutionPolicyRepository,
    @Inject(LEDGER_SINK) private readonly ledger: LedgerSink,
  ) {}

  /**
   * Boot gate. Seeds the baseline on an empty store (the documented bootstrap exemption), then
   * loads and validates the active policy. Any failure here propagates and stops the service
   * starting: a SENTINEL that cannot state its constitution must not serve requests.
   */
  async onModuleInit(): Promise<void> {
    await this.reload();
  }

  /** Loads (or re-loads) the active policy, validating it end to end. */
  async reload(): Promise<LoadedPolicy> {
    await this.repository.ensureBaselineSeeded();

    const stored = await this.repository.findActive();
    if (stored === null) throw new NoActivePolicyError();

    this.loaded = this.loadStored(stored);
    return this.loaded;
  }

  private loadStored(stored: StoredPolicy): LoadedPolicy {
    // 1. Shape: is the stored body a policy at all?
    const policy = parsePolicy(stored.body);

    // 2. Rules: is it a coherent constitution? (WP-06 addition 2 — boot fails if not.)
    assertValidPolicy(policy);

    // 3. Integrity: does the row describe the body it actually holds?
    const recomputed = policyContentSha256(policy);
    if (recomputed !== stored.contentSha256) {
      throw new PolicyIntegrityError(
        `Stored content hash for policy '${stored.version}' is ${stored.contentSha256} but the ` +
          `stored body hashes to ${recomputed}; the policy row has been altered outside the ` +
          `Constitution.`,
      );
    }
    if (policy.version !== stored.version) {
      throw new PolicyIntegrityError(
        `Policy row '${stored.version}' holds a body declaring version '${policy.version}'.`,
      );
    }

    return {
      policy,
      version: stored.version,
      contentSha256: stored.contentSha256,
      createdBy: stored.createdBy,
      activatedAt: stored.activatedAt,
    };
  }

  /** The active policy, or throws if the Constitution has not been loaded. */
  get activePolicy(): LoadedPolicy {
    if (this.loaded === null) throw new ConstitutionNotLoadedError();
    return this.loaded;
  }

  /** Metadata for `GET /api/v1/constitution/policy`. Never exposes the policy body. */
  get activePolicyMetadata(): ActivePolicyMetadata {
    const loaded = this.activePolicy;
    return {
      version: loaded.version,
      content_sha256: loaded.contentSha256,
      status: 'active',
      activated_at: loaded.activatedAt === null ? null : loaded.activatedAt.toISOString(),
      engine_version: CONSTITUTION_ENGINE_VERSION,
    };
  }

  /**
   * Evaluate a consequential action against the active Constitution.
   *
   * Exactly one Decision Ledger record is emitted per call, and it is emitted before the
   * decision is returned. If the sink rejects, so does this call: a decision that could not be
   * recorded is not a decision anyone may rely on, so the failure is propagated rather than
   * swallowed. There is no path from a returned decision to an unwritten ledger entry.
   */
  async evaluate(
    request: ConstitutionRequest,
    options: EvaluateOptions = {},
  ): Promise<ConstitutionDecision> {
    const loaded = this.activePolicy;
    const decision = evaluateRequest(request, loaded.policy);

    await this.ledger.append(
      buildDecisionRecord({
        request,
        decision,
        policyContentSha256: loaded.contentSha256,
        entryId: randomUUID(),
        decidedAt: new Date().toISOString(),
        traceId: options.traceId ?? randomUUID(),
      }),
    );

    return decision;
  }

  /** Stores a candidate constitution as a draft. Storing is not activating. */
  async createDraft(policy: Policy, createdBy: string): Promise<StoredPolicy> {
    return this.repository.createDraft(policy, createdBy);
  }

  /**
   * Activate a stored policy version — itself a Constitution-gated action (§58.2:
   * "altering core Constitution rules" is on the two-person list).
   *
   * The gate is not a separate rule engine: it is this service evaluating
   * `constitution.rules.alter.core` through the very policy currently in force. If that
   * evaluation is anything other than ALLOW, the store is not touched and the active policy is
   * unchanged; the caller receives the decision (typically REQUIRE_TWO_PERSON) and its trace.
   *
   * The evaluation happens *before* the version is looked up, so every activation attempt is
   * authorised and audited, and an unauthorised caller learns nothing about which versions
   * exist.
   */
  async activatePolicy(command: ActivatePolicyCommand): Promise<ActivationResult> {
    const decision = await this.evaluate(this.activationRequest(command), {
      traceId: command.traceId,
    });

    if (decision.decision !== 'ALLOW') {
      return { activated: false, decision, active: this.activePolicy };
    }

    const candidateRow = await this.repository.findByVersion(command.version);
    if (candidateRow === null) throw new PolicyNotFoundError(command.version);

    // A version may have been written before a validation rule existed; re-check before it
    // becomes the constitution in force.
    assertValidPolicy(parsePolicy(candidateRow.body));

    await this.repository.activate(command.version);
    const active = await this.reload();
    return { activated: true, decision, active };
  }

  /**
   * The request the activation gate evaluates.
   *
   * The target is the constitution document of the actor's own organisation, classified
   * RESTRICTED — so an activation additionally requires clearance >= 3, a stated purpose and a
   * trusted (or at worst degraded) device, on top of the two-person approval.
   */
  private activationRequest(command: ActivatePolicyCommand): ConstitutionRequest {
    return {
      action: CONSTITUTION_ALTER_ACTION,
      actor: command.actor,
      target: {
        organisationId: command.actor.organisationId,
        classification: CONSTITUTION_TARGET_CLASSIFICATION,
        classificationLevel: CLASSIFICATION_LEVELS[CONSTITUTION_TARGET_CLASSIFICATION] ?? 3,
      },
      approvals: command.approvals,
      approver_roles: command.approver_roles,
    };
  }
}
