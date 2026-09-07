import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEVICE_AUDIT_FORBIDDEN_FIELDS } from '@sentinel/contracts';
import { collectProofDEvidence } from './proof-d-evidence.collector';
import { PROOF_D_EVIDENCE_SOURCES, PROOF_D_FORBIDDEN_BUNDLE_FIELDS } from './proof-d-evidence.constants';
import {
  ProofDEvidenceIntegrityError,
  ProofDEvidencePrivacyError,
  scanBundleForForbiddenMaterial,
} from './proof-d-evidence.facts';
import { fixtureAttestation, fixtureObservation } from './proof-d-evidence.test-support';

/**
 * WP-31 — THE PRIVACY EXCLUSIONS, PROVEN RATHER THAN ASSERTED.
 *
 * Two kinds of guard are tested here and they fail differently, which is why
 * both exist:
 *
 *   THE SOURCE ALLOWLIST is structural. A table that is not on it cannot be the
 *   basis of any bundle field, so the Whisper tables and the message tables are
 *   excluded by construction rather than by anybody remembering to exclude
 *   them. These tests read the allowlist and the reader's own source text.
 *
 *   THE SCANNER is a backstop. It catches the field that arrives later — by a
 *   spread, a rename, a widened projection — under a name nobody reviewed. It
 *   is tested by feeding it violations and requiring it to throw.
 *
 * A guard that is only ever tested on clean input is a guard nobody has seen
 * work.
 */

const GENERATED_AT = '2026-09-05T10:30:00.000Z';
/**
 * Resolved from the working directory rather than `__dirname`, which the
 * repository's lint configuration does not declare as a permitted global. A
 * wrong path throws here rather than yielding an empty string, and the
 * extraction test below refuses a scan that found nothing — so this file cannot
 * report a clean result by failing to read anything.
 */
const READER_PATH = join(process.cwd(), 'src', 'modules', 'proof-d-evidence', 'proof-d-evidence.reader.ts');
const READER_SOURCE = readFileSync(READER_PATH, 'utf8');

/**
 * Every SQL statement the reader can run, with the prose stripped out.
 *
 * The comments have to go first, and the reason is worth stating: this file's
 * subject matter IS the material that must not be selected, so the reader's own
 * doctrine header names `payload`, `need_to_know_summary` and the message
 * tables in order to explain why it never touches them. A test that scanned the
 * raw file would fail on the explanation and pass on the code, which is exactly
 * the wrong way round. What is under test is the statements.
 */
const READER_CODE = READER_SOURCE.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, ' ');
const READER_SQL = READER_CODE.split('`')
  .filter((_, index) => index % 2 === 1)
  .join('\n')
  .toLowerCase();

describe('the source allowlist is the privacy boundary', () => {
  it('names no Whisper source, so no duress counter can exist', () => {
    // Traffic analysis on a duress channel is a safety defect before it is a
    // privacy one: a counter that rises when a particular operative is in
    // trouble tells a hostile reader when to act. The collector cannot produce
    // one because it cannot cite a source that would carry it.
    for (const source of PROOF_D_EVIDENCE_SOURCES) {
      expect(source).not.toMatch(/whisper/i);
      expect(source).not.toMatch(/duress/i);
    }
  });

  it('names no message body or recipient source', () => {
    expect(PROOF_D_EVIDENCE_SOURCES).not.toContain('incident_field_messages');
    expect(PROOF_D_EVIDENCE_SOURCES).not.toContain('incident_field_message_recipients');
  });

  it('inherits the frozen device-audit forbidden list rather than restating it', () => {
    for (const field of DEVICE_AUDIT_FORBIDDEN_FIELDS) {
      expect(PROOF_D_FORBIDDEN_BUNDLE_FIELDS).toContain(field);
    }
    expect(PROOF_D_FORBIDDEN_BUNDLE_FIELDS).toContain('recipient_user_id');
    expect(PROOF_D_FORBIDDEN_BUNDLE_FIELDS).toContain('need_to_know_summary');
    expect(PROOF_D_FORBIDDEN_BUNDLE_FIELDS).toContain('result_snapshot');
    expect(PROOF_D_FORBIDDEN_BUNDLE_FIELDS).toContain('location');
  });
});

describe('the reader cannot pull protected material out of the database', () => {
  it('extracts a non-trivial set of statements, so a passing scan is never an empty one', () => {
    // The gate that would otherwise manufacture evidence. If the extraction
    // above broke, every assertion below this one would pass against an empty
    // string and report a clean scan of nothing.
    expect(READER_SQL).toContain('field_offline_operation_receipts');
    expect(READER_SQL.split('select').length - 1).toBeGreaterThanOrEqual(15);
  });

  it('contains no star projection', () => {
    // A star projection would pull `need_to_know_summary`, `location`,
    // `payload` and `recipient_user_id` into an evidence artefact the day
    // somebody added a column.
    expect(READER_SQL).not.toMatch(/select\s+\*/);
  });

  it('never queries the message or Whisper tables', () => {
    expect(READER_SQL).not.toMatch(/\bincident_field_messages\b/);
    expect(READER_SQL).not.toMatch(/\bincident_field_message_recipients\b/);
    expect(READER_SQL).not.toMatch(/whisper/);
  });

  it('never selects a payload, a location, a need-to-know summary, a recipient column or a result snapshot', () => {
    expect(READER_SQL).not.toMatch(/\bpayload\b/);
    expect(READER_SQL).not.toMatch(/\blocation\b/);
    expect(READER_SQL).not.toMatch(/\bneed_to_know_summary\b/);
    expect(READER_SQL).not.toMatch(/\brecipient_user_id\b/);
    expect(READER_SQL).not.toMatch(/\bresult_snapshot\b/);
  });

  it('touches incident_field_message_action_idempotency only through the grouped-count helper', () => {
    // That table carries `recipient_user_id`, so it is admitted for exactly one
    // purpose: proving that one acknowledge produced one domain action. It must
    // therefore be reachable only through `countByKey`, whose statement selects
    // a key and a count and has nowhere to return anything else.
    const usages = READER_CODE.split('\n').filter((line) =>
      line.includes('incident_field_message_action_idempotency'),
    );
    expect(usages).toHaveLength(1);
    expect(usages[0]).toContain('countByKey(');

    expect(READER_SQL).toMatch(/select\s+idempotency_key,\s*count\(\*\)::text as row_count/);
    expect(READER_SQL).toContain('group by idempotency_key');
  });
});

describe('the scanner refuses forbidden material in a finished bundle', () => {
  it('passes the bundle the collector actually produces', () => {
    const result = collectProofDEvidence(fixtureObservation(), fixtureAttestation(), GENERATED_AT);
    expect(() => scanBundleForForbiddenMaterial(result)).not.toThrow();
    expect(result.integrity.privacy_scan).toBe('PASS');
  });

  it('throws on a recipient identifier however deeply it is buried', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({ final_state: { domain: [{ recipient_user_id: 'user-9' }] } }),
    ).toThrow(ProofDEvidencePrivacyError);
  });

  it('throws on a plausible new name in the recipient family that no fixed list would have caught', () => {
    // The failure mode is not the field somebody thought about. It is
    // `recipient_user_digest` arriving three work packages from now under a
    // name that looks harmless in a diff.
    expect(() => scanBundleForForbiddenMaterial({ counts: { recipient_user_digest: 'abc' } })).toThrow(
      ProofDEvidencePrivacyError,
    );
    expect(() => scanBundleForForbiddenMaterial({ counts: { per_recipient_totals: 3 } })).toThrow(
      ProofDEvidencePrivacyError,
    );
  });

  it('throws on any duress or Whisper counter, and on any per-device or per-user rate', () => {
    for (const key of [
      'duress_count',
      'duress_activations_per_hour',
      'whisper_signal_count',
      'whisper_rate',
      'activations_per_device',
      'submissions_per_user',
      'refusal_rate',
    ]) {
      expect(() => scanBundleForForbiddenMaterial({ metrics: { [key]: 1 } })).toThrow(ProofDEvidencePrivacyError);
    }
  });

  it('throws on message content, need-to-know material and operative location', () => {
    for (const key of ['body', 'message_body', 'need_to_know_summary', 'location', 'latitude', 'result_snapshot']) {
      expect(() => scanBundleForForbiddenMaterial({ leaked: { [key]: 'x' } })).toThrow(ProofDEvidencePrivacyError);
    }
  });

  it('throws on key material or a session credential smuggled under an innocuous name', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({ note: '-----BEGIN PRIVATE KEY-----AAAA-----END PRIVATE KEY-----' }),
    ).toThrow(ProofDEvidencePrivacyError);
    expect(() =>
      scanBundleForForbiddenMaterial({ note: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.signature' }),
    ).toThrow(ProofDEvidencePrivacyError);
  });

  it('does not refuse a legitimate identifier that merely contains a forbidden word', () => {
    // Matching on substrings would push authors toward vaguer field names,
    // which is the opposite of what an audit artefact needs. A context id
    // authorises nothing and is safe to record.
    expect(() =>
      scanBundleForForbiddenMaterial({ reconnect: { authenticated_device_context_id: 'ctx-1', key_id: 'key-alpha' } }),
    ).not.toThrow();
  });
});

describe('the scanner refuses a fact that has lost its provenance', () => {
  it('rejects an OBSERVED fact citing a source outside the allowlist', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({
        leaked: {
          provenance: 'OBSERVED',
          value: 3,
          source: 'whisper_recognition_receipts',
          attested_by: null,
          note: null,
        },
      }),
    ).toThrow(ProofDEvidenceIntegrityError);
  });

  it('rejects an OBSERVED fact that also claims an attestor', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({
        muddled: {
          provenance: 'OBSERVED',
          value: 3,
          source: 'field_offline_operation_receipts',
          attested_by: 'the harness',
          note: null,
        },
      }),
    ).toThrow(ProofDEvidenceIntegrityError);
  });

  it('rejects an attested fact that dresses itself in a durable source', () => {
    // This is the exact laundering the module exists to prevent: something the
    // harness said, presented as something a table holds.
    expect(() =>
      scanBundleForForbiddenMaterial({
        laundered: {
          provenance: 'HARNESS_ATTESTED',
          value: '2026-09-05T09:00:00.000Z',
          source: 'field_offline_operation_receipts',
          attested_by: 'the harness',
          note: 'the WAN was cut',
        },
      }),
    ).toThrow(ProofDEvidenceIntegrityError);
  });

  it('requires every non-observed fact to explain itself', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({
        unexplained: {
          provenance: 'ABSENT',
          value: null,
          source: 'field_offline_operation_receipts',
          attested_by: null,
          note: null,
        },
      }),
    ).toThrow(ProofDEvidenceIntegrityError);
  });

  it('rejects a withheld fact that nonetheless carries a value', () => {
    expect(() =>
      scanBundleForForbiddenMaterial({
        contradictory: {
          provenance: 'WITHHELD_BY_PRIVACY_RULE',
          value: { recipients: 4 },
          source: null,
          attested_by: null,
          note: 'withheld',
        },
      }),
    ).toThrow();
  });
});
