/**
 * WP-21B Whisper runtime + Studio constants.
 *
 * The behavioural rules this module obeys are fixed by the FROZEN contract in
 * packages/contracts/src/whisper.ts. Nothing here re-states a rule that
 * contract already owns; what lives here are the module's own vocabulary
 * strings — actions, audit kinds, receipt statuses — stated once so no two
 * call sites can spell one of them differently.
 */

/**
 * W21-12/B11-02: four SEPARATE capabilities, already transcribed into
 * identity/roles.ts. Reading a signal roster, editing a configuration,
 * approving an activation and firing the thing are four different powers, and
 * NO existing action implies any of them.
 */
export const ACTION_WHISPER_SIGNAL_READ = 'whisper.signal.read';
export const ACTION_WHISPER_SIGNAL_MANAGE = 'whisper.signal.manage';
export const ACTION_WHISPER_SIGNAL_APPROVE = 'whisper.signal.approve';
export const ACTION_WHISPER_DEVICE_ACTION_INVOKE = 'whisper.device-action.invoke';

/**
 * W21-14 audit kinds, written to WhisperAuditLog.
 *
 * The KIND is the only free-text field in an audit row; everything else goes
 * through WhisperAuditPayloadSchema, whose `.strict()` is what actually keeps
 * signature material, keys, the authorised-user roster and the context VALUES
 * out of a record that oversight reads.
 */
export const AUDIT_WHISPER_SIGNAL_CREATED = 'WHISPER_SIGNAL_CREATED';
export const AUDIT_WHISPER_VERSION_PUBLISHED = 'WHISPER_VERSION_PUBLISHED';
export const AUDIT_WHISPER_STATUS_TRANSITIONED = 'WHISPER_STATUS_TRANSITIONED';
export const AUDIT_WHISPER_ACTIVATED = 'WHISPER_ACTIVATED';
export const AUDIT_WHISPER_ROTATED = 'WHISPER_ROTATED';
export const AUDIT_WHISPER_RECOGNITION_ACCEPTED = 'WHISPER_RECOGNITION_ACCEPTED';
export const AUDIT_WHISPER_RECOGNITION_REFUSED = 'WHISPER_RECOGNITION_REFUSED';

/**
 * B11-12 receipt lifecycle, as persisted in `whisper_recognition_receipts.status`.
 *
 * UNKNOWN is NOT a failure state, it is an UNRESOLVED one (the WP-20/C10-08
 * precedent): a recognition whose effect may or may not have committed is
 * retried into convergence under the lease, never silently finalized and never
 * reported as though it had been decided.
 */
export const RECEIPT_STATUS_RECEIVED = 'RECEIVED';
export const RECEIPT_STATUS_APPLYING = 'APPLYING';
export const RECEIPT_STATUS_APPLIED = 'APPLIED';
export const RECEIPT_STATUS_REFUSED = 'REFUSED';
export const RECEIPT_STATUS_UNKNOWN = 'UNKNOWN';

/** The two terminal receipt statuses. A receipt in either is never re-claimed. */
export const TERMINAL_RECEIPT_STATUSES: readonly string[] = [RECEIPT_STATUS_APPLIED, RECEIPT_STATUS_REFUSED];

/** W21-14 `outcome`, as persisted alongside a terminal status. */
export const RECEIPT_OUTCOME_ACCEPTED = 'ACCEPTED';
export const RECEIPT_OUTCOME_REFUSED = 'REFUSED';

/**
 * B11-12 crash-recovery lease, mirroring WP-20/C10-08's sixty seconds.
 *
 * A receipt left in APPLYING by a process that died is reclaimable once its
 * claim is older than this; a claim NEWER than this belongs to a live attempt,
 * and stealing it would be the double-fire the durable receipt exists to
 * prevent. The lease is what makes the guarantee "effectively once" rather
 * than "at most once": the retry re-enters the SILENT path on the same
 * recognition fingerprint, whose incident source identity is itself unique, so
 * the second attempt converges on the first incident instead of opening a
 * second one.
 */
export const WHISPER_PROCESSING_LEASE_MS = 60_000;

/**
 * B11-09: an Ed25519 signature is exactly 64 bytes. Stated here so the
 * verifier's length gate is a named constant rather than a literal buried in a
 * predicate — a wrong-length signature is refused BEFORE any crypto call.
 */
export const WHISPER_ED25519_SIGNATURE_BYTES = 64;

/** B11-09: the only key type this module will verify against. */
export const WHISPER_ED25519_KEY_TYPE = 'ed25519';
