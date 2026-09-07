import { z } from 'zod';
import { DeviceKeyVersionSchema, canonicalDeviceJson, deviceCanonicalDigest } from './device-identity.js';
import { DeviceSignatureProfileSchema } from './device-signature.js';
import { MAX_OFFLINE_DEVICE_SEQUENCE } from './field-offline.js';
import {
  DeviceEdgeReceiptSchema,
  DeviceOfflineOperationEnvelopeSchema,
} from './device-offline.js';

/**
 * WP-29B §13 — THE FIVE SHARED EDGE INTERFACES, AND NOTHING ELSE.
 *
 * `device-offline.ts` opens by saying WP-23 is contracts only: "no Edge
 * runtime, no reconciliation service, no queue, no persistence". WP-29B builds
 * that runtime, and the moment two lanes start writing it independently the
 * first thing that happens is that each invents its own idea of what an Edge
 * receipt, an Edge identity and a queued operation ARE. This module exists to
 * make that impossible before a line of the runtime is written.
 *
 * WHAT IS DELIBERATELY ABSENT: `EdgeReceipt`.
 * -------------------------------------------
 * There is no receipt type here. `DeviceEdgeReceipt` in `device-offline.ts` is
 * the only one, it is FROZEN, and it is imported rather than mirrored.
 *
 * A parallel `EdgeReceipt` is the single most dangerous duplication available
 * in this codebase, and the reason is mechanical rather than stylistic.
 * `DeviceEdgeReceiptSchema` is `.strict()`, and that `.strict()` is the entire
 * enforcement of "Edge may witness, Edge may not authorize" — an added
 * `approval`, `decision` or `device_trust` field is a PARSE FAILURE rather than
 * a review comment, and `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS` is the list the
 * Crucible proves cannot be attached. A second receipt type written here would
 * start life identical and would drift the first time a runtime author needed
 * "just one more field" locally: the local type would carry it, the central
 * evaluator would never see it, and the two would still typecheck. The strict
 * schema would be enforcing a rule about a structure nobody on the Edge side
 * was using any more.
 *
 * So the runtime's receipt type IS the contract's receipt type. Edge fills in
 * `edge_trusted_time` from its trusted-time anchor and `edge_monotonic_position`
 * from its own counter, signs `canonicalDeviceEdgeReceiptStatement`, and there
 * is no field anywhere in which it could say anything else.
 *
 * WHAT ELSE THIS MODULE REFUSES TO RESTATE
 * ----------------------------------------
 * `DeviceOfflineOperationEnvelope` is composed, never flattened. Every field of
 * that envelope is inside a device signature; a "convenience" copy of
 * `device_id` or `operation_kind` alongside the envelope is a second source of
 * truth for a value the signature already fixes, and the runtime would
 * eventually read the copy. Composition means there is only ever one place to
 * read a signed field from, and it is the signed thing itself.
 */

const scopedId = z.string().min(1).max(256);

/**
 * Edge's monotonic counter position, bounded by the SAME ceiling the frozen
 * receipt uses for `edge_monotonic_position`. Sharing the ceiling is the point:
 * a queue that could record a position the receipt schema then refuses to carry
 * would produce entries Edge cannot witness for, discovered at witness time
 * rather than at enqueue time.
 */
const edgeMonotonicPosition = z.number().int().nonnegative().max(MAX_OFFLINE_DEVICE_SEQUENCE);

// ---------------------------------------------------------------------------
// EdgeOperationState — two members, and only the server ends an entry
// ---------------------------------------------------------------------------

/**
 * A queued operation is either still queued or has been ENDED BY CENTRAL.
 * There is no third state, and specifically there is no `FAILED`, `EXPIRED` or
 * `ABANDONED`.
 *
 * This mirrors the Android `OfflineEntryState` ruling for the same reason it
 * was made there. Each of those three names describes a judgement Edge would be
 * making locally about work it did not author and cannot evaluate:
 *
 *   FAILED    — Edge saw a transport error. A transport error is a fact about
 *               the wire, not about the operation. `EdgeTransportResult.UNKNOWN`
 *               exists precisely so that "we could not tell" has somewhere to
 *               go that is not a verdict.
 *   EXPIRED   — Edge decided a policy lease had run out. Lease standing is
 *               `classifyDevicePolicyLease` against a trustworthy instant, and
 *               central owns both the lease record and the receipt clock it is
 *               judged at. An Edge that expires entries destroys evidence of
 *               work central might still have admitted.
 *   ABANDONED — Edge gave up. There is no operator-visible difference between
 *               "Edge gave up" and "the Field operative's duress signal was
 *               silently deleted in a wiring closet".
 *
 * Each of those is a way for a box on a site LAN to make an operation vanish
 * without central ever learning it existed. TERMINAL is reachable only by
 * carrying a proven central answer (see `EdgeStoredOperationSchema` below), so
 * the only thing that can end a queued operation is the party that owns the
 * decision.
 */
export const EdgeOperationStateSchema = z.enum(['QUEUED', 'TERMINAL']);
export type EdgeOperationState = z.infer<typeof EdgeOperationStateSchema>;

// ---------------------------------------------------------------------------
// EdgeTransportResult — a proven answer, or an honest "we do not know"
// ---------------------------------------------------------------------------

/**
 * Why Edge does not know. Every member is a fact about the WIRE, and none of
 * them is evidence about the operation.
 *
 * `TIMED_OUT` and `RESPONSE_UNINTELLIGIBLE` are the two that matter most,
 * because both are the shape of a request central DID apply. A timeout after
 * the bytes left the site, or a 200 whose body Edge cannot parse, are both
 * states in which the effect may already have committed. Treating either as a
 * failure and retrying-then-dropping is how a queue produces a duplicate
 * effect or loses a real one; treating both as UNKNOWN keeps the entry queued
 * and lets WP-20/C15-05 replay identity converge it on the stored outcome.
 */
const EdgeTransportUnknownReasonSchema = z.enum([
  /** Edge has not attempted delivery — no route to central, or not its turn yet. */
  'NOT_ATTEMPTED',
  /** The connection never established. Central certainly did not see the bytes. */
  'CONNECT_FAILED',
  /** The bytes may or may not have arrived and been applied. */
  'TIMED_OUT',
  /** Transport-level failure mid-exchange. Same ambiguity as a timeout. */
  'TRANSPORT_ERROR',
  /** Central answered something Edge cannot read as an answer. Not a refusal. */
  'RESPONSE_UNINTELLIGIBLE',
]);

/**
 * A CENTRAL answer that admitted the operation. `central_reference` is
 * central's own handle on the resulting record, so the queue's terminal state
 * points at server-owned evidence rather than at Edge's memory of a good day.
 */
const EdgeTransportAcceptedSchema = z
  .object({ outcome: z.literal('CENTRAL_ACCEPTED'), terminal: z.literal(true), central_reference: scopedId })
  .strict();

/**
 * A CENTRAL answer that refused. `refusal_code` is one of central's refusal
 * labels — `DeviceOfflineAdmissibilityRefusal`, or a gateway refusal — carried
 * verbatim so an operator sees the reason central gave, never Edge's paraphrase
 * of it. It is typed as a scoped id rather than as that enum on purpose: Edge
 * must be able to record a refusal label from a NEWER central than itself
 * without the entry becoming unparseable and stranding the queue.
 */
const EdgeTransportRefusedSchema = z
  .object({ outcome: z.literal('CENTRAL_REFUSED'), terminal: z.literal(true), refusal_code: scopedId })
  .strict();

/**
 * THE ONLY TWO ANSWERS THAT MAY END AN ENTRY, and they are both central's.
 *
 * Extracted as its own union so `EdgeStoredOperation.settlement` can be typed
 * as exactly these — making it structurally impossible to settle an entry on an
 * UNKNOWN, which is the defect this whole distinction exists to prevent.
 */
const EdgeTransportTerminalAnswerSchema = z.discriminatedUnion('outcome', [EdgeTransportAcceptedSchema, EdgeTransportRefusedSchema]);

/**
 * "CENTRAL SAID" VERSUS "WE DID NOT HEAR". THESE ARE NOT THE SAME FACT.
 *
 * The `terminal` discriminant is a LITERAL on every member — `true` on the two
 * central answers, `false` on UNKNOWN — following the `queued_domain_execution:
 * false` pattern in `DEVICE_REVOCATION_RESPONSES`. A future edit cannot flip
 * UNKNOWN into a terminal answer without changing a line that reads
 * `terminal: z.literal(false)`, which is a visible diff on a security rule
 * rather than an accident inside a retry loop.
 *
 * The defect this prevents is the ordinary one: a naive transport layer folds
 * every non-2xx and every thrown exception into "failed", the queue drains
 * itself on a bad afternoon of connectivity, and a shift's worth of Field
 * operations is gone with nothing in central to show for it. An UNKNOWN keeps
 * the entry QUEUED — indefinitely, deliberately — because a site that has been
 * cut off for six hours must still be holding its operations when the WAN
 * returns.
 */
export const EdgeTransportResultSchema = z.discriminatedUnion('outcome', [
  EdgeTransportAcceptedSchema,
  EdgeTransportRefusedSchema,
  z.object({ outcome: z.literal('UNKNOWN'), terminal: z.literal(false), reason: EdgeTransportUnknownReasonSchema }).strict(),
]);
export type EdgeTransportResult = z.infer<typeof EdgeTransportResultSchema>;

// ---------------------------------------------------------------------------
// EdgeStoredOperation — the frozen envelope, composed and never flattened
// ---------------------------------------------------------------------------

/**
 * One durable queue entry.
 *
 * WHY THE PAYLOAD IS TEXT
 * -----------------------
 * `payload_canonical_json` is the canonical JSON TEXT of the operation payload,
 * and it is stored, read and forwarded as those exact bytes. It is never a
 * parsed object in the stored form, and the difference is the whole entry's
 * integrity.
 *
 * `envelope.payload_digest` is inside the device's signature. Central re-digests
 * what arrives with `deviceCanonicalDigest(payload)` and refuses
 * PAYLOAD_DIGEST_MISMATCH when it differs. If Edge stored a parsed object, every
 * durable write and every restart round-trips the payload through
 * `JSON.parse`/`JSON.stringify`, and a re-serialisation that reorders keys —
 * which a plain `JSON.stringify` does whenever the insertion order differs, and
 * which any store that normalises JSON does unconditionally — produces different
 * bytes and therefore a different digest. The device signature would then be
 * intact and the operation would still be refused, hours later, at
 * reconciliation, with no way to reconstruct the original bytes. Storing the
 * canonical text means the bytes the device digested are the bytes central
 * re-digests, and the intervening store is a byte pipe with no opinion.
 *
 * The refinement below enforces exactly that, twice over: the text must BE
 * canonical (round-tripping it through `canonicalDeviceJson` must reproduce it
 * unchanged) and it must digest to the value the signature covers. An entry
 * read back from disk that fails either test is corrupt — bit rot, a partial
 * write, or tampering with the queue file — and refusing it at the parse
 * boundary means Edge finds out on read rather than at reconnect.
 */
export const EdgeStoredOperationSchema = z
  .object({
    schema_version: z.literal(1),
    /**
     * COMPOSED, NOT FLATTENED. The signed envelope in full. Its
     * `offline_operation_id` is this entry's identity — there is deliberately no
     * separate storage key, because a second id is a second identity and the
     * two would eventually disagree about which operation an entry is.
     */
    envelope: DeviceOfflineOperationEnvelopeSchema,
    /** Canonical JSON text. Never a parsed object. See the note above. */
    payload_canonical_json: z.string().min(2),
    /**
     * The receipt Edge minted when it witnessed this operation, or `null` when
     * it had no trusted time to witness with.
     *
     * `null` is a first-class, correct outcome and not a gap to be filled in
     * later: with no valid trusted-time anchor, Edge has nothing truthful to put
     * in `edge_trusted_time`, and central fails the operation closed at
     * NO_TRUSTWORTHY_TIME_WITNESS. That refusal is the designed behaviour. An
     * Edge that manufactured a receipt from its host wall clock would convert a
     * visible refusal into an invisible forgery.
     */
    receipt: DeviceEdgeReceiptSchema.nullable(),
    /**
     * Edge's own monotonic position when the entry was enqueued. NOT a wall
     * clock: an Edge with no trusted time still has ordering, and ordering is
     * what a queue needs. Nothing downstream reads this as a time.
     */
    enqueued_edge_monotonic_position: edgeMonotonicPosition,
    state: EdgeOperationStateSchema,
    /**
     * Central's proven answer, or `null`. Typed as the two TERMINAL transport
     * answers only, so there is no expressible way to settle an entry on an
     * UNKNOWN.
     */
    settlement: EdgeTransportTerminalAnswerSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    // ONLY THE SERVER ENDS A QUEUED OPERATION. The state and the evidence for
    // it are checked against each other in both directions: a TERMINAL entry
    // with no central answer is Edge having decided something on its own, and a
    // QUEUED entry carrying an answer is an entry that will be re-sent after
    // central already ruled on it.
    if (value.state === 'TERMINAL' && value.settlement === null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['settlement'],
        message: 'a TERMINAL entry must carry the central answer that ended it; Edge may not end a queued operation on its own',
      });
    }
    if (value.state === 'QUEUED' && value.settlement !== null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['state'],
        message: 'an entry central has answered is not QUEUED',
      });
    }

    // The receipt must be ABOUT this entry's device signature, not merely
    // present. `witnessed_operation_fingerprint` is compared centrally against
    // the fingerprint of the signed statement and refused as
    // WITNESS_FINGERPRINT_MISMATCH; catching a mis-pairing here means Edge
    // never persists a receipt filed against the wrong operation in the first
    // place. Only the shape of the pairing is checkable locally — the
    // fingerprint itself depends on the SERVER-resolved signature profile,
    // which Edge does not own — so this refuses the empty case rather than
    // pretending Edge can recompute central's fingerprint.
    if (value.receipt !== null && value.receipt.witnessed_operation_fingerprint.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['receipt', 'witnessed_operation_fingerprint'],
        message: 'a stored receipt must name the operation it witnessed',
      });
    }

    // THE PAYLOAD BYTES MUST STILL BE THE BYTES THE SIGNATURE COVERS.
    //
    // Parsing here is verification, not storage: the parsed value is used to
    // re-derive the canonical form and the digest and is then discarded. The
    // stored field remains the text.
    let parsedPayload: unknown;
    try {
      parsedPayload = JSON.parse(value.payload_canonical_json);
    } catch {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['payload_canonical_json'],
        message: 'payload_canonical_json must be readable JSON text',
      });
      return;
    }
    let recanonicalised: string;
    let digest: string;
    try {
      recanonicalised = canonicalDeviceJson(parsedPayload);
      digest = deviceCanonicalDigest(parsedPayload);
    } catch {
      // `canonicalDeviceJson` refuses values it cannot canonicalise without
      // loss. A payload central could never re-digest identically is not
      // storable, and finding that out at enqueue is the point.
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['payload_canonical_json'],
        message: 'payload must be canonicalisable without loss',
      });
      return;
    }
    if (recanonicalised !== value.payload_canonical_json) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['payload_canonical_json'],
        message: 'payload_canonical_json must already be in canonical form; re-serialisation must not change the bytes',
      });
    }
    if (digest !== value.envelope.payload_digest) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['payload_canonical_json'],
        message: 'the stored payload does not digest to the value the device signature covers',
      });
    }
  });
export type EdgeStoredOperation = z.infer<typeof EdgeStoredOperationSchema>;

// ---------------------------------------------------------------------------
// EdgeIdentityContext — who Edge is, and pointedly not how trusted it is
// ---------------------------------------------------------------------------

/**
 * WHAT EDGE IS ALLOWED TO KNOW ABOUT ITSELF.
 *
 * THERE IS NO TRUST FIELD, AND THERE MUST NEVER BE ONE.
 *
 * `edge_trust` lives on `EdgeRegistryKeyRecordSchema` — central's record, read
 * by `evaluateOfflineOperationAdmissibility` at reconciliation, refused as
 * EDGE_NOT_TRUSTED when it is anything but TRUSTED. It is central's judgement
 * about Edge, and the judgement is only worth anything because Edge cannot
 * hold, cache or influence it.
 *
 * An Edge that cached `edge_trust: 'TRUSTED'` would be an Edge that keeps
 * believing it is trusted for exactly as long as the WAN is down — which is
 * precisely the window in which a suspension matters. Suspend a compromised
 * Edge at 02:00 and it never hears; it goes on minting receipts all night from
 * a cached "TRUSTED" it read a week ago. Central still refuses them at
 * reconciliation — the check runs against central's record, not the receipt —
 * so the cached value never confers anything. It only ever produces an Edge
 * confidently doing work that will be thrown away, and an operator looking at a
 * healthy-looking Edge that is in fact revoked. `.strict()` makes adding the
 * field a parse failure.
 *
 * There is likewise no key material here. `edge_key_id` and `edge_key_version`
 * are registry IDENTITIES, in the same spirit as `DeviceAuditPayloadSchema`
 * carrying a `key_id` and never a key: this context is the structure that gets
 * logged at boot, attached to diagnostics and shown on a readiness page, and a
 * private key must not be reachable from any of those. The signing key is held
 * by whatever mints receipts and is never handed around as "identity".
 */
export const EdgeIdentityContextSchema = z
  .object({
    schema_version: z.literal(1),
    /** The tenant this Edge belongs to. Central refuses EDGE_ORGANISATION_MISMATCH on a mismatch. */
    organisation_id: scopedId,
    edge_id: scopedId,
    /** Registry identity of the receipt-signing key. Never the key. */
    edge_key_id: scopedId,
    edge_key_version: DeviceKeyVersionSchema,
    /**
     * The signature profile Edge signs receipts with. This is a claim, exactly
     * as `claimed_edge_signature_profile` is on the receipt: central binds it to
     * the profile on its own registry record and refuses
     * EDGE_SIGNATURE_PROFILE_CLAIM_MISMATCH. Edge stating it here does not make
     * it true, and nothing in the runtime may treat it as agreement.
     */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /**
     * The sites this Edge believes it may witness for. ADVISORY AND NARROWING
     * ONLY.
     *
     * Central holds `authorised_site_ids` on the registry record and refuses
     * EDGE_SITE_NOT_AUTHORISED against ITS copy. This local list exists so Edge
     * declines to witness for a site it knows it has no business at, rather than
     * minting receipts central will certainly reject. Because it can only cause
     * Edge to do LESS, a stale copy fails closed: an entry Edge wrongly declines
     * to witness is refused at NO_TRUSTWORTHY_TIME_WITNESS and is visible, where
     * a widened local list buys nothing at all — central still refuses. Nothing
     * in the runtime may read this as permission.
     */
    authorised_site_ids: z.array(scopedId).min(1),
  })
  .strict();
export type EdgeIdentityContext = z.infer<typeof EdgeIdentityContextSchema>;

// ---------------------------------------------------------------------------
// EdgeQueueMetrics — aggregate only, because a count can be an identity
// ---------------------------------------------------------------------------

/**
 * AGGREGATE ONLY. NO PER-DEVICE, PER-ACTOR, PER-RECIPIENT OR PER-KIND BREAKDOWN.
 *
 * This is the WP-18 protected-recipient rule applied to telemetry, and the
 * reason it applies to a QUEUE DEPTH is not obvious until it is stated.
 *
 * Metrics are the most widely exported, least access-controlled surface any
 * service has: scraped by anything on the LAN, retained forever, joined against
 * everything else in the observability stack, and never subject to the
 * authorisation a query against the same facts would face. A queue-depth gauge
 * labelled by `device_id` is a per-operative activity trace with a timestamp on
 * every increment. Labelled by `actor_user_id`, it says which named operative
 * was working which shift at which site. Labelled by `recipient` — or by
 * anything that reduces to one, which `operation_kind` does when a kind exists
 * for one recipient class — it reconstructs exactly the relationship WP-18
 * exists to protect, from a system that never intended to disclose it and never
 * logged that it had.
 *
 * The rule is therefore structural rather than procedural. Every field below is
 * a scalar over the whole queue. There is no map, no array of per-entity rows,
 * and no field whose cardinality is a person, a device or a site — so there is
 * no label to attach in the first place, and `.strict()` refuses one being
 * added. A future need for per-device visibility is an authenticated, audited
 * query against central, not a widening of this shape.
 */
export const EdgeQueueMetricsSchema = z
  .object({
    schema_version: z.literal(1),
    /** How many entries are still QUEUED, in total. */
    queued_count: z.number().int().nonnegative(),
    /** How many entries central has answered and that have not yet been pruned. */
    terminal_count: z.number().int().nonnegative(),
    /** The durable queue's hard capacity, so saturation is visible before it bites. */
    capacity: z.number().int().positive(),
    /**
     * Age of the oldest queued entry, measured on Edge's MONOTONIC clock in
     * milliseconds, or `null` when the queue is empty. Monotonic rather than
     * wall-clock deliberately: this number must stay meaningful on an Edge that
     * has no trusted time at all, which is the exact situation in which an
     * operator most needs to see a backlog growing.
     */
    oldest_queued_monotonic_age_ms: z.number().int().nonnegative().nullable(),
    /**
     * Whether Edge currently holds a valid trusted-time anchor. A BOOLEAN, not
     * the anchor, not its expiry and not the time itself — an operator needs to
     * know that receipts are being minted, and anything more detailed here is a
     * clock reading exported from an unauthenticated endpoint.
     */
    trusted_time_available: z.boolean(),
    /**
     * Consecutive UNKNOWN transport results. This is the number that
     * distinguishes "the WAN is down" from "central is refusing our work", and
     * it is aggregate because the distinction is about the link, not about whose
     * operations are in the queue.
     */
    consecutive_unknown_transport_results: z.number().int().nonnegative(),
  })
  .strict();
export type EdgeQueueMetrics = z.infer<typeof EdgeQueueMetricsSchema>;
