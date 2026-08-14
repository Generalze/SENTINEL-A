import { z } from 'zod';

/**
 * Delivery / execution reliability semantics (architecture §76). Events and
 * commands may be retried, reordered or duplicated during failures, so
 * Sentinel tracks explicit requested/delivered/acknowledged/executed
 * distinctions rather than a single boolean "sent" flag.
 */
export const DeliveryStateSchema = z.enum([
  'REQUESTED',
  'DELIVERED',
  'ACKNOWLEDGED',
  'EXECUTED',
  'FAILED',
  'UNKNOWN',
]);
export type DeliveryState = z.infer<typeof DeliveryStateSchema>;

/**
 * Allowed transitions between delivery states.
 *
 * §76 defines the six states and their meanings but does not spell out the
 * full transition graph verbatim; this is this implementation's
 * interpretation, flagged here for lead confirmation:
 *
 * - Normal progression: REQUESTED -> DELIVERED -> ACKNOWLEDGED -> EXECUTED.
 * - Any pre-EXECUTED state can move to FAILED ("the action did not
 *   complete") or UNKNOWN ("cannot yet prove whether it completed").
 * - FAILED and UNKNOWN can always be retried back to REQUESTED.
 * - UNKNOWN can also resolve directly to any other state once proof
 *   arrives, since by definition Sentinel does not yet know the true state
 *   underlying an UNKNOWN — resolution is not restricted to "start over".
 * - EXECUTED is terminal: the requested operational action has been
 *   confirmed and nothing further is modelled.
 */
export const ALLOWED_DELIVERY_TRANSITIONS: Readonly<Record<DeliveryState, readonly DeliveryState[]>> = {
  REQUESTED: ['DELIVERED', 'FAILED', 'UNKNOWN'],
  DELIVERED: ['ACKNOWLEDGED', 'FAILED', 'UNKNOWN'],
  ACKNOWLEDGED: ['EXECUTED', 'FAILED', 'UNKNOWN'],
  EXECUTED: [],
  FAILED: ['REQUESTED'],
  UNKNOWN: ['REQUESTED', 'DELIVERED', 'ACKNOWLEDGED', 'EXECUTED', 'FAILED'],
};

/** Pure predicate: is `from -> to` an allowed delivery-state transition? */
export function canTransition(from: DeliveryState, to: DeliveryState): boolean {
  return ALLOWED_DELIVERY_TRANSITIONS[from].includes(to);
}
