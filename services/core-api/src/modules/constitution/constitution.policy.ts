/**
 * SENTINEL — Constitution baseline policy, freezing and deserialisation.
 *
 * Architecture references: §5.1 (versioned policy layer), §58.2 (two-person control list),
 * §62 (human roles and operational authority).
 *
 * The policy *body* is what is persisted as JSON in `constitution_policies.body` and what the
 * content SHA-256 is computed over, so its field names are part of the stored contract. They
 * follow the certified CERT-O shape, plus `approval_roles` (named verbatim per the WP-06
 * directive).
 */

import { z } from 'zod';
import type { ActionCategory, Policy } from './constitution.engine';

/* -------------------------------------------------------------------------- */
/* Freezing                                                                   */
/* -------------------------------------------------------------------------- */

/** Deep-freezes a policy so a loaded constitution cannot be mutated at runtime. */
export function freezePolicy(policy: Policy): Policy {
  Object.freeze(policy.prohibitedActions);
  for (const grants of Object.values(policy.roles)) Object.freeze(grants);
  Object.freeze(policy.roles);
  for (const category of Object.values(policy.categories)) {
    Object.freeze(category.approval_roles);
    Object.freeze(category);
  }
  Object.freeze(policy.categories);
  Object.freeze(policy.actions);
  return Object.freeze(policy);
}

/* -------------------------------------------------------------------------- */
/* Deserialisation                                                            */
/* -------------------------------------------------------------------------- */

const ActionCategorySchema: z.ZodType<ActionCategory> = z.object({
  approval: z.enum(['NONE', 'ONE', 'TWO_PERSON']),
  description: z.string().min(1),
  approval_roles: z.array(z.string().min(1)),
});

export const PolicyBodySchema = z.object({
  version: z.string().min(1),
  categories: z.record(ActionCategorySchema),
  actions: z.record(z.string().min(1)),
  roles: z.record(z.array(z.string().min(1))),
  prohibitedActions: z.array(z.string().min(1)),
});

/** Raised when a stored policy body is not a structurally valid policy. */
export class PolicyShapeError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Constitution policy body is not a valid policy: ${issues.join('; ')}`);
    this.name = 'PolicyShapeError';
    this.issues = issues;
  }
}

/**
 * Parses a persisted policy body into a frozen `Policy`.
 *
 * Shape validation only — the *rules* about a policy's internal consistency live in
 * `validatePolicy`. Both run at load time; boot fails if either rejects.
 */
export function parsePolicy(body: unknown): Policy {
  const parsed = PolicyBodySchema.safeParse(body);
  if (!parsed.success) {
    const issues = parsed.error.issues.map(
      (issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`,
    );
    throw new PolicyShapeError(issues);
  }
  return freezePolicy(parsed.data);
}

/** The JSON-serialisable form of a policy, as stored in `constitution_policies.body`. */
export function policyBody(policy: Policy): Record<string, unknown> {
  return JSON.parse(JSON.stringify(policy)) as Record<string, unknown>;
}

/* -------------------------------------------------------------------------- */
/* Baseline SENTINEL policy                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The baseline constitution, adapted from the certified CERT-O policy.
 *
 * Changes vs CERT-O:
 *  - every category declares `approval_roles` (the roles that carry approval authority for it);
 *  - two §62 roles are registered so the approval-authority lists are not dangling references:
 *    `site.commander` (Site Commander) and `org.security.director` (Organisation Security
 *    Director). `platform.admin` is CERT-O's id for the §62 Platform Security Administrator and
 *    is reused rather than duplicated under a second id.
 *
 * The six TWO_PERSON categories are exactly the §58.2 control list. Prohibited actions are
 * registered (so the constitution can name and classify them) but granted to no role.
 *
 * Approval authority is deliberately cross-functional: `alter_core_constitution_rules`, for
 * example, is approvable by a constitution steward *or* a security officer / director /
 * platform administrator, so two-person control on a constitution change cannot be satisfied
 * by two members of the same function colluding.
 */
export const SENTINEL_BASELINE_POLICY: Policy = freezePolicy({
  version: 'sentinel-constitution-1.1.0',

  categories: {
    routine_read: {
      approval: 'NONE',
      description: 'Read of operational records.',
      approval_roles: [],
    },
    routine_write: {
      approval: 'NONE',
      description: 'Annotation of operational records.',
      approval_roles: [],
    },

    sensitive_data_export: {
      approval: 'ONE',
      description: 'Export of sensitive data outside the platform.',
      approval_roles: [
        'org.security.director',
        'platform.admin',
        'security.officer',
        'site.commander',
      ],
    },
    account_privilege_change: {
      approval: 'ONE',
      description: 'Change to a user account role or privilege.',
      approval_roles: ['org.security.director', 'platform.admin'],
    },

    // §58.2 — two-person control.
    exceptional_tracking_powers: {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
      approval_roles: ['org.security.director', 'security.officer', 'site.commander'],
    },
    controlled_reality_high_activation: {
      approval: 'TWO_PERSON',
      description: '§58.2 High-level Controlled Reality activation.',
      approval_roles: ['org.security.director', 'security.officer', 'site.commander'],
    },
    disable_critical_security_protection: {
      approval: 'TWO_PERSON',
      description: '§58.2 Disabling a critical security protection.',
      approval_roles: ['org.security.director', 'platform.admin', 'security.officer'],
    },
    export_restricted_biometric_evidence: {
      approval: 'TWO_PERSON',
      description: '§58.2 Export of restricted biometric evidence.',
      approval_roles: ['evidence.custodian', 'org.security.director'],
    },
    modify_evidence_retention_legal_hold: {
      approval: 'TWO_PERSON',
      description: '§58.2 Modification of evidence retention under legal hold.',
      approval_roles: ['evidence.custodian', 'org.security.director'],
    },
    alter_core_constitution_rules: {
      approval: 'TWO_PERSON',
      description: '§58.2 Alteration of core Constitution rules.',
      approval_roles: [
        'constitution.steward',
        'org.security.director',
        'platform.admin',
        'security.officer',
      ],
    },

    irreversible_integrity_destruction: {
      approval: 'TWO_PERSON',
      description: 'Destruction of integrity records (prohibited in this policy).',
      approval_roles: ['org.security.director', 'platform.admin'],
    },
  },

  actions: {
    'incident.view': 'routine_read',
    'incident.annotate': 'routine_write',
    'report.export.summary': 'sensitive_data_export',
    'user.role.grant': 'account_privilege_change',

    'tracking.exceptional.enable': 'exceptional_tracking_powers',
    'reality.controlled.activate.high': 'controlled_reality_high_activation',
    'security.protection.disable': 'disable_critical_security_protection',
    'evidence.biometric.export.restricted': 'export_restricted_biometric_evidence',
    'evidence.retention.modify.legalhold': 'modify_evidence_retention_legal_hold',
    'constitution.rules.alter.core': 'alter_core_constitution_rules',

    // Registered so they can be named and classified — but prohibited below.
    'audit.ledger.delete': 'irreversible_integrity_destruction',
    'surveillance.mass.covert.enable': 'exceptional_tracking_powers',
    'evidence.legalhold.destroy': 'modify_evidence_retention_legal_hold',
    'constitution.evaluator.bypass': 'alter_core_constitution_rules',
  },

  roles: {
    viewer: ['incident.view'],
    analyst: ['incident.view', 'incident.annotate', 'report.export.summary'],
    'evidence.custodian': [
      'incident.view',
      'evidence.biometric.export.restricted',
      'evidence.retention.modify.legalhold',
    ],
    'security.officer': [
      'incident.view',
      'tracking.exceptional.enable',
      'reality.controlled.activate.high',
      'security.protection.disable',
    ],
    'site.commander': [
      'incident.view',
      'incident.annotate',
      'reality.controlled.activate.high',
    ],
    'org.security.director': [
      'incident.view',
      'incident.annotate',
      'report.export.summary',
      'user.role.grant',
      'tracking.exceptional.enable',
      'security.protection.disable',
    ],
    'platform.admin': ['incident.view', 'user.role.grant'],
    'constitution.steward': ['incident.view', 'constitution.rules.alter.core'],
  },

  prohibitedActions: [
    'audit.ledger.delete',
    'surveillance.mass.covert.enable',
    'evidence.legalhold.destroy',
    'constitution.evaluator.bypass',
  ],
});

/** The action whose evaluation gates every change to the constitution itself (§58.2). */
export const CONSTITUTION_ALTER_ACTION = 'constitution.rules.alter.core';
