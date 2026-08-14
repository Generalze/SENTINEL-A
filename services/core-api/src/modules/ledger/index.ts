/**
 * SENTINEL — Decision Ledger module public surface.
 *
 * Other modules should import from here (`../ledger`) rather than reaching into files: the
 * implementation's internals are free to change, the contract is not.
 */

export { canonicalJson, computeContentHash, sha256Hex, type HashableLedgerEntry } from './ledger.hash';

export {
  ACTION_LEDGER_READ,
  ACTION_LEDGER_VERIFY,
  DEFAULT_LIST_LIMIT,
  MAX_LIST_LIMIT,
} from './ledger.constants';

export type {
  AppendLedgerEntryInput,
  LedgerApproval,
  LedgerEntry,
  LedgerListFilter,
  LedgerListResult,
  VerifyChainBroken,
  VerifyChainOk,
  VerifyChainResult,
} from './ledger.types';

export { LedgerRepository, type InsertLedgerEntryData } from './ledger.repository';
export { LedgerService, LedgerValidationError } from './ledger.service';
export { LedgerController } from './ledger.controller';
export { LedgerModule } from './ledger.module';
export {
  LedgerPrincipalActionGuard,
  RequiresLedgerAction,
} from './ledger-principal-action.guard';
export type { LedgerPrincipal, RequestWithLedgerPrincipal } from './ledger.principal.types';
