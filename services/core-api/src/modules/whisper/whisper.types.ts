import type { WhisperRecognitionConflictCode, WhisperSignal } from '@sentinel/contracts';

/**
 * WP-21B view and outcome types.
 *
 * WHAT IS DELIBERATELY ABSENT FROM EVERY TYPE HERE: a signature, a public key,
 * a verification key id, an anti-replay nonce and a submitted `context` value.
 * None of them has a field in any shape below, so a well-meaning future edit
 * cannot widen a Studio response or a runtime reply into a disclosure of the
 * material the modality's safety rests on (W21-14). The audit payload is
 * governed by the contract's own `.strict()` schema for the same reason.
 */

/**
 * One stored signal version as Studio reads it (B11-03/B11-04).
 *
 * The `WhisperSignal` half is round-tripped through WhisperSignalSchema before
 * it leaves the service, so a corrupt or drifted row is refused rather than
 * rendered. The four additional fields are PERSISTENCE FACTS about the
 * version's lifecycle, not part of the configuration the contract governs:
 * the fingerprint is a digest an approval binds to, and the three timestamps
 * record how long a version was actually live — which ROTATED and RETIRED are
 * distinct enough outcomes to need separately.
 */
export interface WhisperSignalVersionView extends WhisperSignal {
  configuration_fingerprint: string;
  activated_at: string | null;
  rotated_at: string | null;
  retired_at: string | null;
}

/**
 * A signal FAMILY and its version history (B11-04).
 *
 * `whisper_signal_id` is the family identifier — server-generated and stable
 * across versions — so the natural Studio detail view is the whole family,
 * newest version first. W21-02 makes every version immutable past DRAFT, so
 * this is a history, not a mutable list.
 */
export interface WhisperSignalFamilyView {
  whisper_signal_id: string;
  organisation_id: string;
  site_id: string | null;
  versions: WhisperSignalVersionView[];
}

/**
 * B11-10/B11-11/B11-12: what a runtime recognition RESOLVED TO.
 *
 * THREE DECIDED OUTCOMES, and every one of them is DATA rather than a thrown
 * error — a duress recognition that did not qualify is a durable refusal the
 * platform must be able to audit, not an exception that would leave the
 * anti-replay identity ambiguous.
 *
 *  - `accepted` the recognition was eligible and entered the existing SILENT
 *               incident-response path. `incident_id` is where it entered;
 *               `replayed` is true when this was a RETRY converging on an
 *               already-stored terminal outcome rather than a first effect.
 *  - `refused`  the recognition did not qualify. The conflict code comes from
 *               the contract's vocabulary, which deliberately cannot say
 *               whether a signal exists — only that the attempt did not
 *               qualify.
 *  - `invalid`  the raw result failed DeviceActionWhisperResultSchema, so it
 *               never reached persistence at all and consumed no replay
 *               identity. It carries no fingerprint because an unparsed result
 *               has no canonical signed statement to digest.
 *
 * THERE IS DELIBERATELY NO FOURTH `unknown` MEMBER. The contract's conflict
 * vocabulary has no code for "we do not know", and inventing one here would
 * let an unresolved outcome be reported as a decided refusal — the single
 * worst lie this module could tell about a silent duress signal. An
 * unresolved attempt is recorded UNKNOWN on its receipt and then raised as
 * WhisperRecognitionUnresolvedError, so the caller retries into convergence
 * instead of concluding anything.
 */
export type WhisperRecognitionOutcome =
  | {
      kind: 'accepted';
      recognition_fingerprint: string;
      incident_id: string | null;
      replayed: boolean;
    }
  | {
      kind: 'refused';
      conflict_code: WhisperRecognitionConflictCode;
      recognition_fingerprint: string;
      replayed: boolean;
    }
  | { kind: 'invalid'; issues: string[] };

/**
 * B11-12: the outcome of this attempt is genuinely UNRESOLVED.
 *
 * Raised in exactly two situations, both of which mean "an effect may or may
 * not have committed and this attempt cannot honestly say which":
 *
 *  1. an infrastructure fault while entering the SILENT path or while
 *     finalizing — the receipt is left UNKNOWN, which is immediately
 *     reclaimable under the lease; and
 *  2. a lost claim fence over a receipt a newer attempt has not yet
 *     finalized — that attempt owns the outcome, and this one wrote nothing.
 *
 * In both cases the durable receipt has already been written or preserved, so
 * the retry reclaims it and converges: the incident's own
 * `(organisation_id, source_kind, source_ref)` uniqueness means a second entry
 * on the same recognition fingerprint reuses the first incident rather than
 * opening another.
 */
export class WhisperRecognitionUnresolvedError extends Error {
  constructor(message = 'Whisper recognition outcome is unresolved; retry to converge') {
    super(message);
    this.name = 'WhisperRecognitionUnresolvedError';
  }
}
