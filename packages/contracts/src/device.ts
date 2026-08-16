import { z } from 'zod';

/**
 * Canonical device trust state (architecture section 28).
 *
 * This vocabulary is shared by Field, Whisper, Shield, Edge, Fusion and
 * Constitution-facing callers. Individual evaluators may initially support a
 * subset, but contracts must not introduce local competing trust enums.
 */
export const DeviceTrustSchema = z.enum([
  'TRUSTED',
  'DEGRADED',
  'SUSPICIOUS',
  'QUARANTINED',
  'COMPROMISED',
  'OFFLINE',
]);
export type DeviceTrust = z.infer<typeof DeviceTrustSchema>;
