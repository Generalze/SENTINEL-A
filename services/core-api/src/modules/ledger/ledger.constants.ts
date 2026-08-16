export const DEFAULT_LIST_LIMIT = 50;
export const MAX_LIST_LIMIT = 200;

/**
 * Actions this module's routes require on the caller's principal; the global AccessGuard reads these
 * ledger-principal-action.guard.ts). `ledger.read` matches the action name the identity
 * module's §62 role table (src/modules/identity/roles.ts) already reserves for this purpose
 * (granted to the `investigator` role); this module does not import identity, so the name is
 * duplicated here rather than shared.
 */
export const ACTION_LEDGER_READ = 'ledger.read';

/** Directive #5: verifyChain is an admin endpoint, distinct from the general read action. */
export const ACTION_LEDGER_VERIFY = 'ledger.verify';
