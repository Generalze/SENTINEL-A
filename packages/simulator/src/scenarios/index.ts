import type { Scenario } from '../scenario.js';
import { proofAIntrusionV1, proofAIntrusionContradictionV1 } from './proof-a-intrusion.js';
import { singleSourceNoiseV1 } from './single-source-noise.js';
import { duplicateDeliveryV1 } from './duplicate-delivery.js';

export { proofAIntrusionV1, proofAIntrusionContradictionV1 } from './proof-a-intrusion.js';
export { singleSourceNoiseV1 } from './single-source-noise.js';
export { duplicateDeliveryV1 } from './duplicate-delivery.js';

export interface ScenarioLookupOptions {
  /** Selects the contradiction variant for scenarios that have one (currently: proof-a-intrusion). */
  readonly contradiction?: boolean;
}

const SCENARIO_FACTORIES: Readonly<Record<string, (options?: ScenarioLookupOptions) => Scenario>> = {
  'proof-a-intrusion': (options) => (options?.contradiction ? proofAIntrusionContradictionV1 : proofAIntrusionV1),
  'single-source-noise': () => singleSourceNoiseV1,
  'duplicate-delivery': () => duplicateDeliveryV1,
};

export const SCENARIO_NAMES: readonly string[] = Object.keys(SCENARIO_FACTORIES);

/** Every scenario variant in the library — used by the validation test suite. */
export const ALL_SCENARIOS: readonly Scenario[] = [
  proofAIntrusionV1,
  proofAIntrusionContradictionV1,
  singleSourceNoiseV1,
  duplicateDeliveryV1,
];

/** Looks up a scenario by its CLI `--name`. Throws on an unknown name. */
export function getScenario(name: string, options?: ScenarioLookupOptions): Scenario {
  const factory = SCENARIO_FACTORIES[name];
  if (!factory) {
    throw new Error(`Unknown scenario "${name}". Known scenarios: ${SCENARIO_NAMES.join(', ')}`);
  }
  return factory(options);
}
