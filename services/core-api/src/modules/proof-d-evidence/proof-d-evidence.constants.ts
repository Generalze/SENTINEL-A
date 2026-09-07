import { DEVICE_AUDIT_FORBIDDEN_FIELDS } from '@sentinel/contracts';

/**
 * WP-31 — PROOF D EVIDENCE MACHINERY.
 *
 * This module builds a machine-readable EVIDENCE BUNDLE for the locked Proof D
 * acceptance definition in docs/execution/MILESTONE-3-ROADMAP.md. It builds
 * nothing else. In particular:
 *
 *   IT IS NOT A METRICS PLATFORM. It introduces no counter store, no scrape
 *   endpoint, no time series and no background collection. It runs once, on
 *   demand, behind a gate, and it reads.
 *
 *   IT IS NOT A CLAIM. A bundle is the material an assessor reads in order to
 *   decide; it is never the decision. `PROOF_D_CLAIM` below is a constant, not
 *   a computation, and there is no code path anywhere in this module that can
 *   move it. Proof D stays UNCLAIMED until a human signs the physical
 *   acceptance, and a simulator run producing a clean bundle changes nothing
 *   about that.
 *
 * THE ONE IDEA THIS MODULE EXISTS TO PROTECT
 * ------------------------------------------
 * Most of Proof D is already answerable by SQL over durable audit state that
 * exists today — receipts, cursors, gateway events, leases, outbox rows — so
 * the honest thing to build is a COLLECTOR, not new instrumentation. But a
 * collector that mixes what the server SAW with what the harness SAID would
 * quietly manufacture evidence, because central cannot observe an interval it
 * was absent for. Every fact therefore carries its own provenance
 * (`EVIDENCE_PROVENANCE` below), and the fact constructors in
 * `proof-d-evidence.facts.ts` make an unprovenanced fact unrepresentable.
 *
 * An absent fact must be VISIBLY absent. Other lanes are concurrently building
 * the Edge transport, the Edge durable queue and the WP-30 outage harness; a
 * source those lanes have not landed yet produces a `SOURCE_NOT_PRESENT` fact
 * naming the source and the question it would have answered, never a silently
 * omitted field.
 */

/** The bundle format version. Bumped when the SHAPE changes, never per run. */
export const PROOF_D_BUNDLE_SCHEMA_VERSION = 1 as const;

export const PROOF_D_BUNDLE_KIND = 'SENTINEL_PROOF_D_EVIDENCE' as const;

/**
 * The claim block, frozen as data.
 *
 * These are not defaults that a successful run overwrites. There is no writer
 * for them. WP-31 may complete its software and harness implementation while
 * Proof D physical/system acceptance remains blocked, and that asymmetry is
 * the whole reason the constant is here rather than derived.
 */
export const PROOF_D_CLAIM = {
  proof_c: 'UNCLAIMED',
  proof_d: 'UNCLAIMED',
  wp_26_physical_acceptance: 'DEFERRED — NOT WAIVED',
  wp_28: 'BLOCKED — NOT STARTED',
} as const;

/**
 * The sentence that travels with every bundle so that a bundle detached from
 * its sign-off document still says what it is.
 */
export const PROOF_D_CLAIM_STATEMENT =
  'This bundle is evidence, not an acceptance. Proof D remains UNCLAIMED. ' +
  'The locked acceptance definition requires a real outage with central online, ' +
  'a real Field device connected and an Edge operational; no bundle produced ' +
  'from a simulated or laboratory environment can satisfy it, and no bundle ' +
  'produced from a real one satisfies it without a signed physical acceptance.';

/**
 * WHERE A FACT CAME FROM. This is the integrity of the bundle, so it is a
 * closed vocabulary rather than a free string.
 *
 *   OBSERVED                 Server-authoritative durable state, read from a
 *                            named source in `PROOF_D_EVIDENCE_SOURCES`. The
 *                            server's own clock, the server's own decision.
 *
 *   CLIENT_CLAIMED           Durably stored by the server, but the VALUE
 *                            originated on the device and is never server
 *                            authority. `client_created_at` is the archetype:
 *                            field-offline.prisma calls it telemetry and
 *                            forbids it from backdating a transition. A
 *                            collector that reported it as OBSERVED would
 *                            launder a device clock into a server fact.
 *
 *   HARNESS_ATTESTED         Supplied by the outage harness because central
 *                            could not observe it. The severance interval is
 *                            the archetype: an absent server has no record of
 *                            its own absence.
 *
 *   ABSENT                   The source exists, was queried, and holds nothing
 *                            for this run. A real, reportable answer.
 *
 *   SOURCE_NOT_PRESENT       The source does not exist at this commit — the
 *                            work package that owns it has not landed. Not the
 *                            same as ABSENT, and conflating them would let an
 *                            unbuilt capability read as an empty one.
 *
 *   SOURCE_NOT_READABLE      The source EXISTS and this collector version does
 *                            not know how to read it. The mirror image of the
 *                            case above, and it has to be said separately:
 *                            other lanes are landing Edge sources concurrently,
 *                            so a collector that reported an arrived-but-
 *                            unrecognised table as SOURCE_NOT_PRESENT would be
 *                            claiming the system lacks a capability it has.
 *
 *   WITHHELD_BY_PRIVACY_RULE The fact is collectable and is deliberately not
 *                            collected. Recorded rather than omitted, so the
 *                            privacy decision is auditable instead of looking
 *                            like an oversight.
 */
export const EVIDENCE_PROVENANCE = [
  'OBSERVED',
  'CLIENT_CLAIMED',
  'HARNESS_ATTESTED',
  'ABSENT',
  'SOURCE_NOT_PRESENT',
  'SOURCE_NOT_READABLE',
  'WITHHELD_BY_PRIVACY_RULE',
] as const;
export type EvidenceProvenance = (typeof EVIDENCE_PROVENANCE)[number];

/**
 * THE SOURCE ALLOWLIST, AND THEREFORE THE PRIVACY BOUNDARY.
 *
 * A fact may only be marked OBSERVED (or CLIENT_CLAIMED, or ABSENT) if it
 * cites one of these. That makes the list two things at once:
 *
 *   1. an integrity control — "observed" cannot be asserted about a source
 *      nobody named; and
 *   2. a PRIVACY control — a table that is not on this list cannot be the
 *      basis of any bundle field, so the exclusions below are structural
 *      rather than a promise somebody has to keep.
 *
 * WHAT IS DELIBERATELY ABSENT FROM THIS LIST, AND WHY.
 *
 *   whisper_*                 Every Whisper table. Traffic rates and per-device
 *   (all of them)             or per-user duress counters are TRAFFIC ANALYSIS
 *                             ON A DURESS CHANNEL. That is a safety defect
 *                             before it is a privacy one: a counter that rises
 *                             when a particular operative is in trouble tells a
 *                             hostile reader when to act. Proof D is about
 *                             ordering and idempotency under WAN loss; it does
 *                             not need a single Whisper row, so it reads none.
 *
 *   incident_field_messages   Message bodies.
 *   incident_field_message_   The WP-18 protected recipient set. Reading it —
 *   recipients                even to count — would let a technical counter
 *                             reconstruct who may see what, which §62.1 exists
 *                             to prevent.
 *
 *   field_assignments.        Not a table exclusion but a COLUMN one: the
 *   need_to_know_summary      assignment projection in the reader names its
 *                             columns explicitly and this is not among them.
 *
 *   field_operative_*.        Operative location. Never a Proof D fact; the
 *   location                  projections omit it and the scanner refuses it.
 *
 * `incident_field_message_action_idempotency` IS on the list, and it is the
 * one entry that needed an argument. The table carries `recipient_user_id`,
 * so reading rows from it is exactly the reconstruction risk above. It is
 * admitted for a COUNT AGAINST A KNOWN SERVER-DERIVED KEY and nothing else,
 * and the reader's return type for it has nowhere to put a recipient — the
 * same technique `EdgeEnrolmentAuthority` uses when it says a structure with
 * nowhere to put a raw secret cannot leak one. The count is what proves that
 * one acknowledge produced one domain action, which is the centre of Proof D.
 */
export const PROOF_D_EVIDENCE_SOURCES = [
  // The offline replay executor's own durable state.
  'field_offline_operation_receipts',
  'field_offline_device_cursors',
  // The authenticated device boundary.
  'device_gateway_operation_events',
  'authenticated_device_contexts',
  'device_context_establishment_challenges',
  'device_policy_leases',
  'device_trust_transitions',
  'device_security_events',
  // Edge identity and standing.
  'edges',
  'edge_security_events',
  // The Field capability audit trail.
  'field_audit_log',
  // Domain-side single-effect evidence. Projections only; see the header.
  'field_assignments',
  'field_assignment_action_idempotency',
  'field_state_update_idempotency',
  'field_operative_current_states',
  'field_operative_state_history',
  'incident_field_message_action_idempotency',
  // Fan-out recovery: `published_at IS NULL`, counted at organisation scope.
  'field_outbox',
  'incident_field_message_outbox',
  'incident_update_outbox',
  'events',
  // Structural evidence about the database itself.
  'pg_indexes',
  'information_schema.tables',
] as const;
export type ProofDEvidenceSource = (typeof PROOF_D_EVIDENCE_SOURCES)[number];

/**
 * The four outbox tables whose `published_at IS NULL` predicate answers
 * "did the fan-out recover after the link came back?". Each is already indexed
 * for exactly this predicate, which is why the question needs no new
 * instrumentation to ask.
 *
 * COUNTS ONLY, AT ORGANISATION SCOPE. `incident_field_message_outbox` has a
 * `recipient_user_id` routing column; a per-recipient breakdown of it would be
 * the protected recipient set with extra steps. The reader returns a scalar
 * count and an oldest-unpublished timestamp, and nothing else crosses.
 */
export const PROOF_D_OUTBOX_SOURCES = [
  'field_outbox',
  'incident_field_message_outbox',
  'incident_update_outbox',
  'events',
] as const satisfies readonly ProofDEvidenceSource[];

/**
 * The two unique constraints that make duplicate suppression STRUCTURAL rather
 * than measured.
 *
 * This is worth stating precisely, because it changes what the bundle should
 * even try to prove. Nothing in the service counts duplicates and reports a
 * suppression rate; Postgres refuses the second row. So the honest evidence is
 * not a metric — it is a verification that these indexes EXIST in the database
 * the run was performed against. The reader resolves them from `pg_indexes`,
 * and a missing one is a far louder finding than any counter could be.
 */
export const PROOF_D_STRUCTURAL_CONSTRAINTS = [
  {
    index_name: 'field_offline_receipt_sequence_key',
    table_name: 'field_offline_operation_receipts',
    enforces:
      'One receipt per queue position per authenticated namespace. This is what makes REPLAY, SEQUENCE_REUSED and SEQUENCE_STALE distinguishable instead of guessable.',
  },
  {
    index_name: 'field_offline_receipt_operation_key',
    table_name: 'field_offline_operation_receipts',
    enforces:
      'One offline operation id occupies exactly one queue position in its namespace, enforced below the service layer, so a service-bypassing writer cannot smuggle the same operation in twice.',
  },
  {
    index_name: 'field_offline_cursor_namespace_key',
    table_name: 'field_offline_device_cursors',
    enforces:
      'One cursor row per authenticated replay namespace, so a device cannot hold two competing queue positions.',
  },
  {
    index_name: 'field_assignment_action_idem_key',
    table_name: 'field_assignment_action_idempotency',
    enforces:
      'One assignment action per (assignment, action, idempotency key) — the domain-side guarantee the offline executor converges onto when it retries with the stored downstream key.',
  },
  {
    index_name: 'field_state_update_idem_key',
    table_name: 'field_state_update_idempotency',
    enforces: 'One state update per (namespace, idempotency key).',
  },
  {
    index_name: 'incident_field_message_action_idem_key',
    table_name: 'incident_field_message_action_idempotency',
    enforces: 'One message action per (message, recipient, action, idempotency key).',
  },
] as const;

/**
 * Sources this collector KNOWS it wants and that do not exist yet.
 *
 * WP-29B/WP-30 own the Edge durable queue, the Edge receipt and the Edge
 * session record. They are not on `PROOF_D_EVIDENCE_SOURCES` because they
 * cannot be read; they are listed here so the bundle can say WHICH QUESTION
 * went unanswered and WHO owns the answer, instead of dropping the field.
 *
 * The reader also reports any `edge_%` or `field_offline_%` table it finds in
 * the database that it does not know how to read, so a lane landing a source
 * under a different name shows up as an unrecognised source rather than as a
 * silent `SOURCE_NOT_PRESENT`. Degradation has to be honest in both
 * directions: a collector that cannot see a source must not imply the source
 * is missing.
 */
export const PROOF_D_PENDING_SOURCES = [
  {
    table_name: 'edge_operation_receipts',
    question: 'Which Edge receipt proves the operation was durably persisted at the Edge before central saw it?',
    owner: 'WP-29B / WP-30 Edge durable queue',
  },
  {
    table_name: 'edge_sessions',
    question: 'When did the Edge reconnect, and which authenticated Edge identity reconnected?',
    owner: 'WP-29B Edge transport',
  },
  {
    table_name: 'edge_queue_entries',
    question: 'What did the Edge hold locally while central was unreachable, and in what order did it release it?',
    owner: 'WP-29B / WP-30 Edge durable queue',
  },
] as const;

/** Table-name prefixes the reader sweeps when looking for unrecognised sources. */
export const PROOF_D_SOURCE_SURVEY_PREFIXES = ['edge_', 'field_offline_'] as const;

/**
 * Tables the sweep will find, that this collector KNOWS about and deliberately
 * does not read.
 *
 * Without this list the survey is noise. It would report the whole Edge
 * enrolment ceremony as "unrecognised" on every run, and a signal that fires
 * constantly is a signal nobody reads — so the one case the survey exists for,
 * a genuinely new source arriving under an unexpected name, would arrive in a
 * list of five things that are always there and be missed.
 *
 * Each of these is excluded because it answers an ENROLMENT question, not a
 * Proof D one. How an Edge earned its identity is WP-29B's subject; whether an
 * operation survived an outage without duplicating is this one's. The Edge's
 * current standing, which is the part Proof D does care about, is read from
 * `edges` and `edge_security_events`.
 */
export const PROOF_D_KNOWN_UNREAD_SOURCES = [
  'edge_enrolment_authorities',
  'edge_enrolment_requests',
  'edge_possession_challenges',
  'edge_possession_verifications',
  'edge_registry_keys',
] as const;

/**
 * MATERIAL THAT MAY NEVER APPEAR IN A BUNDLE, ENUMERATED SO THE REFUSAL IS
 * PROVEN RATHER THAN ASSERTED.
 *
 * `DEVICE_AUDIT_FORBIDDEN_FIELDS` is the frozen WP-23 standard and is included
 * whole rather than restated, so this list cannot drift from it. The additions
 * below are the ones Proof D specifically could have got wrong, each with the
 * reason it is here:
 *
 *   recipient_user_id and family   WP-18's protected recipient set. A Proof D
 *                                  bundle that named recipients would let an
 *                                  evidence artefact reconstruct need-to-know.
 *   duress / whisper counters      Traffic analysis on a duress channel.
 *   need_to_know_summary, body     Content, not disposition.
 *   location and coordinates       Operative position is not a Proof D fact.
 *   result_snapshot                Bounded and allowlisted it may be, but it is
 *                                  read back on reconnect for the DEVICE, not
 *                                  copied into an artefact that leaves the
 *                                  boundary. The bundle carries the receipt's
 *                                  disposition instead.
 *
 * The match is on exact object KEY names, not substrings: a field legitimately
 * called `authenticated_device_context_id` must not be refused because
 * `context` is on the list, and refusing it would push authors toward vaguer
 * names, which is the opposite of what an audit artefact needs.
 */
export const PROOF_D_FORBIDDEN_BUNDLE_FIELDS = [
  ...DEVICE_AUDIT_FORBIDDEN_FIELDS,
  'recipient_user_id',
  'recipient_user_ids',
  'recipient_id',
  'recipient_ids',
  'recipients',
  'recipient_count',
  'need_to_know_summary',
  'need_to_know',
  'message_body',
  'body',
  'content',
  'text',
  'summary',
  'location',
  'lat',
  'lon',
  'latitude',
  'longitude',
  'coordinates',
  'secret',
  'secret_digest',
  'credential',
  'password',
  'token',
  'authorization',
  'result_snapshot',
  'duress_count',
  'duress_rate',
  'whisper_count',
  'whisper_rate',
  'whisper_signal_count',
  'activation_count',
  'recognition_count',
] as const;

/**
 * Key-name PATTERNS, for the families a fixed list cannot close.
 *
 * A future author adding `duress_activations_per_hour` or
 * `recipient_user_digest` would slip past an exact list, and the whole point of
 * these two families is that a plausible-looking new name is exactly how the
 * defect arrives.
 */
export const PROOF_D_FORBIDDEN_FIELD_PATTERNS: readonly RegExp[] = [
  /recipient/i,
  /duress/i,
  /whisper/i,
  /need_to_know/i,
  /(^|_)(rate|per_hour|per_minute|per_device|per_user)(_|$)/i,
];

/**
 * VALUE patterns that indicate credential or key material regardless of the
 * field it arrived under. Key names are the first line; a value scan is the
 * second, because material can be smuggled under an innocuous name.
 */
export const PROOF_D_FORBIDDEN_VALUE_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*(PRIVATE|PUBLIC) KEY-----/,
  /^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./,
];

/**
 * The harness environments a bundle may be produced in.
 *
 * FIELD is the only one the locked definition can ever be satisfied from, and
 * even a FIELD bundle is evidence rather than acceptance. The distinction is
 * carried explicitly so nobody has to infer it from context later: a bundle
 * detached from its conversation still says which kind of run made it.
 */
export const PROOF_D_HARNESS_ENVIRONMENTS = ['SIMULATED', 'LABORATORY', 'FIELD'] as const;
export type ProofDHarnessEnvironment = (typeof PROOF_D_HARNESS_ENVIRONMENTS)[number];

/** How the WAN was severed. `SIMULATED` can never support physical acceptance. */
export const PROOF_D_SEVERANCE_METHODS = ['PHYSICAL', 'LOGICAL', 'SIMULATED'] as const;
export type ProofDSeveranceMethod = (typeof PROOF_D_SEVERANCE_METHODS)[number];

/** The environment variable that must be set for the collector CLI to run. */
export const PROOF_D_COLLECTOR_GATE_ENV = 'SENTINEL_PROOF_D_EVIDENCE';

/** Receipt statuses that have consumed their queue position. */
export const PROOF_D_FINALIZED_STATUSES = ['APPLIED', 'REJECTED'] as const;
