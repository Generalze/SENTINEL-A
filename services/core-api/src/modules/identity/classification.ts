/**
 * Data classification levels (architecture §47 data governance table).
 * Numeric order doubles as the scale compared against `User.clearance`
 * (also 0-5) in the §62.1 access guard:
 *
 *   ALLOW requires clearance >= classification
 *
 * | Level      | Value | Examples (§47)                                   |
 * |------------|-------|---------------------------------------------------|
 * | PUBLIC     | 0     | Published organisation information                |
 * | INTERNAL   | 1     | Configuration and routine operational data         |
 * | SENSITIVE  | 2     | Field location, incident details, private contact |
 * | RESTRICTED | 3     | Biometric references, high-threat intelligence     |
 * | EVIDENCE   | 4     | Preserved incident material, chain-of-custody      |
 * | SECRETS    | 5     | Keys, credentials, signing material                |
 *
 * A route with no declared classification defaults to PUBLIC, i.e. the
 * clearance and purpose conjuncts are trivially satisfied.
 */
export const CLASSIFICATION_LEVELS = {
  PUBLIC: 0,
  INTERNAL: 1,
  SENSITIVE: 2,
  RESTRICTED: 3,
  EVIDENCE: 4,
  SECRETS: 5,
} as const;

export type ClassificationLevel = (typeof CLASSIFICATION_LEVELS)[keyof typeof CLASSIFICATION_LEVELS];

/**
 * §62.1: "purpose required for SENSITIVE+ reads" — any route whose
 * declared classification is >= this threshold requires a non-empty
 * `x-purpose` header.
 */
export const PURPOSE_REQUIRED_FROM: ClassificationLevel = CLASSIFICATION_LEVELS.SENSITIVE;
