import {
  EVIDENCE_PROVENANCE,
  PROOF_D_EVIDENCE_SOURCES,
  PROOF_D_FORBIDDEN_BUNDLE_FIELDS,
  PROOF_D_FORBIDDEN_FIELD_PATTERNS,
  PROOF_D_FORBIDDEN_VALUE_PATTERNS,
  type EvidenceProvenance,
  type ProofDEvidenceSource,
} from './proof-d-evidence.constants';
import type { EvidenceFact } from './proof-d-evidence.types';

/**
 * WP-31 — fact construction and the privacy scanner.
 *
 * TWO GUARANTEES LIVE HERE, AND NEITHER IS A CONVENTION.
 *
 *   1. A fact cannot be built without stating where it came from. The
 *      constructors below are the only way to make an `EvidenceFact`, and each
 *      one fixes the provenance and demands what that provenance requires —
 *      `observed` will not compile against a source outside the allowlist, and
 *      `attested` will not run without an attestor and an explanation.
 *
 *   2. A bundle that carries forbidden material cannot be emitted. The scanner
 *      walks the finished object and throws. It runs at the end of collection
 *      rather than at each write site, because the risk is not the field
 *      somebody thought about — it is the one that arrived by a spread, a
 *      rename or a widened projection three work packages from now.
 */

const SOURCE_SET: ReadonlySet<string> = new Set(PROOF_D_EVIDENCE_SOURCES);
const FORBIDDEN_FIELD_SET: ReadonlySet<string> = new Set(
  PROOF_D_FORBIDDEN_BUNDLE_FIELDS.map((field) => field.toLowerCase()),
);

/**
 * Sources are joined with ` + ` when a fact genuinely rests on more than one
 * table, and the validator splits on the same separator. The alternative —
 * naming one of the tables and dropping the rest — would make a bundle's
 * `cited_sources` a lie by omission, and that list is how a reader checks which
 * durable state the run actually rested on.
 */
export const SOURCE_JOIN = ' + ';

/** A fact read straight out of server-authoritative durable state. */
export function observed<T>(source: ProofDEvidenceSource, value: T): EvidenceFact<T> {
  return { provenance: 'OBSERVED', value, source, attested_by: null, note: null };
}

/** As `observed`, for a fact derived from several durable sources at once. */
export function observedFrom<T>(sources: readonly ProofDEvidenceSource[], value: T, note?: string): EvidenceFact<T> {
  return {
    provenance: 'OBSERVED',
    value,
    source: sources.join(SOURCE_JOIN),
    attested_by: null,
    note: note ?? null,
  };
}

/**
 * A fact that IS in the database and whose VALUE is still the device's word.
 *
 * `client_created_at` is the case this exists for. It is durably stored, so it
 * is tempting to call it observed; field-offline.prisma calls it telemetry and
 * forbids it from becoming server authority, and a bundle that blurred the two
 * would be doing precisely what the schema comment forbids.
 */
export function clientClaimed<T>(source: ProofDEvidenceSource, value: T, note: string): EvidenceFact<T> {
  return { provenance: 'CLIENT_CLAIMED', value, source, attested_by: null, note };
}

/** A fact central could not observe, supplied by the harness. */
export function attested<T>(attestedBy: string, value: T | null, note: string): EvidenceFact<T> {
  return { provenance: 'HARNESS_ATTESTED', value, source: null, attested_by: attestedBy, note };
}

/** The source exists, was queried, and had nothing to say for this run. */
export function absent<T>(source: ProofDEvidenceSource, note: string): EvidenceFact<T> {
  return { provenance: 'ABSENT', value: null, source, attested_by: null, note };
}

/** As `absent`, for a question that spanned several sources. */
export function absentFrom<T>(sources: readonly ProofDEvidenceSource[], note: string): EvidenceFact<T> {
  return { provenance: 'ABSENT', value: null, source: sources.join(SOURCE_JOIN), attested_by: null, note };
}

/**
 * The source does not exist at this commit.
 *
 * Distinct from `absent` on purpose. "The Edge receipt table holds no rows for
 * this run" and "no Edge receipt table has been built yet" are different
 * findings, and only one of them is a gap in the run rather than a gap in the
 * system. The source name is a plain string here precisely because a table
 * that does not exist cannot be on the allowlist.
 */
export function sourceNotPresent<T>(tableName: string, note: string): EvidenceFact<T> {
  return { provenance: 'SOURCE_NOT_PRESENT', value: null, source: tableName, attested_by: null, note };
}

/**
 * The source exists and this collector version has no reader for it.
 *
 * The counterpart of `sourceNotPresent`, and the reason it exists is that the
 * Edge sources are being built by other lanes right now. If one of them lands
 * under a name this collector does not know, the honest report is "the system
 * has this and I cannot read it", not "the system does not have this". Only one
 * of those two sentences leads someone to go and look.
 */
export function sourceNotReadable<T>(tableName: string, note: string): EvidenceFact<T> {
  return { provenance: 'SOURCE_NOT_READABLE', value: null, source: tableName, attested_by: null, note };
}

/**
 * The fact is collectable and is deliberately not collected.
 *
 * Recorded rather than omitted so that a privacy decision reads as a decision.
 * A field that simply vanished would be indistinguishable from one somebody
 * forgot, and the next author would "fix" it.
 */
export function withheld<T>(note: string): EvidenceFact<T> {
  return { provenance: 'WITHHELD_BY_PRIVACY_RULE', value: null, source: null, attested_by: null, note };
}

/**
 * A derived value is never more trustworthy than its least trustworthy input.
 *
 * `offline_dwell_ms` is the motivating case: it subtracts a server clock from a
 * device clock, and reporting the result as OBSERVED because one end was
 * observed would launder the device's claim into a server fact.
 */
const PROVENANCE_STRENGTH: Readonly<Record<EvidenceProvenance, number>> = {
  OBSERVED: 6,
  CLIENT_CLAIMED: 5,
  HARNESS_ATTESTED: 4,
  ABSENT: 3,
  SOURCE_NOT_READABLE: 2,
  SOURCE_NOT_PRESENT: 1,
  WITHHELD_BY_PRIVACY_RULE: 0,
};

export function weakestProvenance(...provenances: readonly EvidenceProvenance[]): EvidenceProvenance {
  return provenances.reduce((weakest, candidate) =>
    PROVENANCE_STRENGTH[candidate] < PROVENANCE_STRENGTH[weakest] ? candidate : weakest,
  );
}

/**
 * Build a derived fact that inherits the weaker of two provenances.
 *
 * Returns an ABSENT-shaped fact when either input had no value, because a
 * difference of two timestamps one of which does not exist is not zero.
 */
export function derived<T>(
  left: EvidenceFact<unknown>,
  right: EvidenceFact<unknown>,
  source: ProofDEvidenceSource,
  compute: () => T | null,
  note: string,
): EvidenceFact<T> {
  const provenance = weakestProvenance(left.provenance, right.provenance);
  if (left.value === null || right.value === null) {
    return { provenance: 'ABSENT', value: null, source, attested_by: null, note };
  }
  const value = compute();
  if (value === null) {
    return { provenance: 'ABSENT', value: null, source, attested_by: null, note };
  }
  return {
    provenance,
    value,
    source: provenance === 'HARNESS_ATTESTED' ? null : source,
    attested_by: provenance === 'HARNESS_ATTESTED' ? (left.attested_by ?? right.attested_by) : null,
    note,
  };
}

// ---------------------------------------------------------------------------
// Well-formedness
// ---------------------------------------------------------------------------

export class ProofDEvidenceIntegrityError extends Error {}

export class ProofDEvidencePrivacyError extends Error {}

function isEvidenceFact(candidate: Record<string, unknown>): boolean {
  return (
    typeof candidate.provenance === 'string' &&
    'value' in candidate &&
    'source' in candidate &&
    'attested_by' in candidate &&
    'note' in candidate
  );
}

/**
 * Every fact in the bundle must be internally consistent with its own
 * provenance. This is the check that stops a hand-built fact object — a
 * spread, a test fixture, a future shortcut — from entering the bundle without
 * the discipline the constructors impose.
 */
function assertFactWellFormed(path: string, fact: Record<string, unknown>): void {
  const provenance = fact.provenance;
  if (typeof provenance !== 'string' || !(EVIDENCE_PROVENANCE as readonly string[]).includes(provenance)) {
    throw new ProofDEvidenceIntegrityError(`${path}: unknown evidence provenance ${String(provenance)}`);
  }
  const source = fact.source;
  const note = fact.note;
  const attestedBy = fact.attested_by;

  if (provenance === 'OBSERVED' || provenance === 'CLIENT_CLAIMED' || provenance === 'ABSENT') {
    const cited = typeof source === 'string' && source.length > 0 ? source.split(SOURCE_JOIN) : [];
    if (cited.length === 0 || cited.some((entry) => !SOURCE_SET.has(entry))) {
      throw new ProofDEvidenceIntegrityError(
        `${path}: ${provenance} must cite sources on PROOF_D_EVIDENCE_SOURCES, got ${String(source)}`,
      );
    }
    if (attestedBy !== null) {
      throw new ProofDEvidenceIntegrityError(`${path}: ${provenance} must not name an attestor`);
    }
  }
  if (provenance === 'OBSERVED' && fact.value === null) {
    throw new ProofDEvidenceIntegrityError(`${path}: OBSERVED with a null value should be ABSENT`);
  }
  if (provenance === 'HARNESS_ATTESTED') {
    if (typeof attestedBy !== 'string' || attestedBy.length === 0) {
      throw new ProofDEvidenceIntegrityError(`${path}: HARNESS_ATTESTED must name who attested`);
    }
    if (source !== null) {
      throw new ProofDEvidenceIntegrityError(`${path}: HARNESS_ATTESTED must not cite a durable source`);
    }
  }
  if (provenance !== 'OBSERVED' && (typeof note !== 'string' || note.length === 0)) {
    throw new ProofDEvidenceIntegrityError(
      `${path}: ${provenance} must explain itself; only OBSERVED may omit a note`,
    );
  }
  if (
    provenance === 'SOURCE_NOT_PRESENT' ||
    provenance === 'SOURCE_NOT_READABLE' ||
    provenance === 'WITHHELD_BY_PRIVACY_RULE'
  ) {
    if (fact.value !== null) {
      throw new ProofDEvidenceIntegrityError(`${path}: ${provenance} must carry no value`);
    }
  }
  if (provenance === 'SOURCE_NOT_PRESENT' || provenance === 'SOURCE_NOT_READABLE') {
    if (typeof source !== 'string' || source.length === 0) {
      throw new ProofDEvidenceIntegrityError(`${path}: ${provenance} must name the source it means`);
    }
  }
}

// ---------------------------------------------------------------------------
// The privacy scanner
// ---------------------------------------------------------------------------

function forbiddenKeyReason(key: string): string | null {
  const lowered = key.toLowerCase();
  if (FORBIDDEN_FIELD_SET.has(lowered)) {
    return `field name "${key}" is on PROOF_D_FORBIDDEN_BUNDLE_FIELDS`;
  }
  for (const pattern of PROOF_D_FORBIDDEN_FIELD_PATTERNS) {
    if (pattern.test(lowered)) {
      return `field name "${key}" matches forbidden family ${pattern.source}`;
    }
  }
  return null;
}

function forbiddenValueReason(value: string): string | null {
  for (const pattern of PROOF_D_FORBIDDEN_VALUE_PATTERNS) {
    if (pattern.test(value)) {
      return `value matches forbidden material pattern ${pattern.source}`;
    }
  }
  return null;
}

interface ScanState {
  factCounts: Record<EvidenceProvenance, number>;
  citedSources: Set<string>;
}

function walk(node: unknown, path: string, state: ScanState): void {
  if (node === null || node === undefined) {
    return;
  }
  if (typeof node === 'string') {
    const reason = forbiddenValueReason(node);
    if (reason !== null) {
      throw new ProofDEvidencePrivacyError(`${path}: ${reason}`);
    }
    return;
  }
  if (typeof node !== 'object') {
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((entry, index) => walk(entry, `${path}[${index}]`, state));
    return;
  }

  const record = node as Record<string, unknown>;
  if (isEvidenceFact(record)) {
    assertFactWellFormed(path, record);
    const provenance = record.provenance as EvidenceProvenance;
    state.factCounts[provenance] += 1;
    if (provenance === 'OBSERVED' || provenance === 'CLIENT_CLAIMED') {
      for (const cited of String(record.source).split(SOURCE_JOIN)) {
        state.citedSources.add(cited);
      }
    }
  }

  for (const [key, value] of Object.entries(record)) {
    const childPath = `${path}.${key}`;
    const reason = forbiddenKeyReason(key);
    if (reason !== null) {
      throw new ProofDEvidencePrivacyError(`${childPath}: ${reason}`);
    }
    walk(value, childPath, state);
  }
}

export interface ProofDScanResult {
  fact_count_by_provenance: Readonly<Record<EvidenceProvenance, number>>;
  cited_sources: readonly string[];
}

/**
 * Walk a finished bundle, refuse forbidden material, and tally provenance.
 *
 * The scan and the tally are one pass on purpose. If they were separate, a
 * future edit could report an integrity summary for an object the scanner
 * never saw, and the summary would be the more convincing of the two.
 *
 * THROWS rather than filtering. A collector that quietly stripped a forbidden
 * field would emit a bundle that looks clean and hide the fact that something
 * upstream is now producing recipient identifiers; the loud failure is the
 * point.
 */
export function scanBundleForForbiddenMaterial(bundle: unknown): ProofDScanResult {
  const state: ScanState = {
    factCounts: {
      OBSERVED: 0,
      CLIENT_CLAIMED: 0,
      HARNESS_ATTESTED: 0,
      ABSENT: 0,
      SOURCE_NOT_PRESENT: 0,
      SOURCE_NOT_READABLE: 0,
      WITHHELD_BY_PRIVACY_RULE: 0,
    },
    citedSources: new Set<string>(),
  };
  walk(bundle, '$', state);
  return {
    fact_count_by_provenance: state.factCounts,
    cited_sources: [...state.citedSources].sort(),
  };
}
