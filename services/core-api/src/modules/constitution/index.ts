/**
 * SENTINEL — Constitution module public surface.
 *
 * Other modules should import from here (`../constitution`) rather than reaching into files:
 * the evaluator's internals are free to change, the contract is not.
 */

export {
  CHECK_SEQUENCE,
  CLASSIFICATION_LEVELS,
  CONSTITUTION_ENGINE_VERSION,
  MAX_CLASSIFICATION_LEVEL,
  PURPOSE_REQUIRED_AT_LEVEL,
  SUSPICIOUS_DEVICE_MAX_LEVEL,
  effectiveClassificationLevel,
  evaluate,
  requiredApproverCount,
  type ActionCategory,
  type Actor,
  type Approval,
  type ApprovalRequirement,
  type ApproverRoles,
  type CheckId,
  type CheckOutcome,
  type CheckSeverity,
  type Classification,
  type ConstitutionDecision,
  type ConstitutionRequest,
  type Decision,
  type DeviceTrust,
  type Policy,
  type Target,
  type TraceEntry,
  type TraceValue,
} from './constitution.engine';

export {
  CONSTITUTION_ALTER_ACTION,
  PolicyShapeError,
  SENTINEL_BASELINE_POLICY,
  freezePolicy,
  parsePolicy,
  policyBody,
} from './constitution.policy';

export {
  PolicyValidationError,
  assertValidPolicy,
  validatePolicy,
  type PolicyValidationCode,
  type PolicyValidationIssue,
} from './constitution.validation';

export {
  canonicalJson,
  policyBodyContentSha256,
  policyContentSha256,
  sha256Hex,
} from './constitution.hash';

export {
  BOOTSTRAP_AUTHOR,
  ConstitutionPolicyRepository,
  NoActivePolicyError,
  PolicyNotActivatableError,
  PolicyNotFoundError,
  SingleActivePolicyError,
  type PolicyStatus,
  type StoredPolicy,
} from './constitution.repository';

export {
  ConstitutionNotLoadedError,
  ConstitutionService,
  PolicyIntegrityError,
  type ActivatePolicyCommand,
  type ActivationResult,
  type ActivePolicyMetadata,
  type EvaluateOptions,
  type LoadedPolicy,
} from './constitution.service';

export {
  BUFFERING_LEDGER_SINK_CAPACITY,
  BufferingLedgerSink,
  LEDGER_SINK,
  type LedgerSink,
} from './ledger.sink';

export {
  CONSTITUTION_DECISION_TYPE,
  buildDecisionRecord,
  type DecisionRecord,
  type DecisionRecordInput,
} from './decision-record';

export { ConstitutionModule } from './constitution.module';
export {
  CONSTITUTION_POLICY_READER_ROLES,
  ConstitutionAdminGuard,
  extractPrincipal,
  type ConstitutionPrincipal,
} from './constitution-admin.guard';
