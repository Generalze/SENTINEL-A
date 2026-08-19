import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { WhisperSignalVersion } from '@prisma/client';
import {
  canTransitionWhisperSignalStatus,
  classifyWhisperConfigurationEdit,
  classifyWhisperRecognitionFreshness,
  DeviceActionWhisperResultSchema,
  deviceActionWhisperReplayIdentity,
  evaluateWhisperRuntimeEligibility,
  isAllowlistedWhisperResponseProtocol,
  isCanonicalJsonRecord,
  WhisperJsonValueSchema,
  WhisperRecognitionConflictCodeSchema,
  WhisperResponseProtocolSchema,
  WhisperSignalSchema,
  WhisperSignalStatusSchema,
  whisperActivationApproverIsDistinct,
  whisperConfigurationFingerprint,
  whisperRecognitionFingerprint,
  type AuthenticatedWhisperDeviceContext,
  type DeviceActionWhisperResult,
  type ServerWhisperContextFacts,
  type WhisperJsonValue,
  type WhisperRecognitionConflictCode,
  type WhisperResponseProtocol,
  type WhisperRuntimeEligibilityInput,
  type WhisperSemanticConfiguration,
  type WhisperSignalStatus,
} from '@sentinel/contracts';
import { z } from 'zod';
import type { Principal } from '../../common/security/principal';
import { IncidentsService } from '../incidents/incidents.service';
import { DEFAULT_LIST_LIMIT, intersectSiteScope, MAX_LIST_LIMIT } from '../identity/list-pagination';
import {
  ACTION_WHISPER_DEVICE_ACTION_INVOKE,
  ACTION_WHISPER_SIGNAL_APPROVE,
  ACTION_WHISPER_SIGNAL_MANAGE,
  ACTION_WHISPER_SIGNAL_READ,
  AUDIT_WHISPER_RECOGNITION_ACCEPTED,
  AUDIT_WHISPER_RECOGNITION_REFUSED,
  AUDIT_WHISPER_SIGNAL_CREATED,
  AUDIT_WHISPER_VERSION_PUBLISHED,
  RECEIPT_OUTCOME_ACCEPTED,
  RECEIPT_OUTCOME_REFUSED,
  RECEIPT_STATUS_APPLIED,
  RECEIPT_STATUS_REFUSED,
  TERMINAL_RECEIPT_STATUSES,
} from './whisper.constants';
import {
  WhisperRepository,
  WhisperUniquenessConflictError,
  type FinalizeReceiptInput,
  type WhisperAuditInput,
  type WhisperStoredReceipt,
  type WhisperWriteOutcome,
} from './whisper.repository';
import { WhisperSignatureVerifier } from './whisper-signature.verifier';
import {
  WhisperRecognitionUnresolvedError,
  type WhisperRecognitionOutcome,
  type WhisperSignalFamilyView,
  type WhisperSignalVersionView,
} from './whisper.types';

/**
 * B11-06: context requirements, validated on the RAW input.
 *
 * The custom guard runs FIRST for the reason the frozen contract spells out:
 * `z.record(...)` alone classifies a `RegExp`, a `Date` or a class instance as
 * an ordinary object, finds no enumerable keys and parses it into `{}` — the
 * value is gone before any refinement can see it, and the fingerprint then
 * attests to an empty requirement set nobody wrote. Reusing the contract's own
 * `isCanonicalJsonRecord` here means the API boundary refuses exactly what the
 * canonicaliser would refuse, with no second definition to drift.
 */
const contextRequirementsInput = z
  .custom<Record<string, WhisperJsonValue>>(isCanonicalJsonRecord, {
    message: 'context_requirements must be a plain record of canonically representable JSON values',
  })
  .pipe(z.record(WhisperJsonValueSchema));

/**
 * The six SEMANTIC configuration fields, as a request body.
 *
 * `modality` is absent because DEVICE_ACTION is the only one Milestone 2 has,
 * and the contract pins it to a literal; accepting it would create a field a
 * caller could get wrong for no benefit. `status` is absent because advancing
 * the lifecycle is an audited transition, not a configuration edit. Nothing
 * here can name an organisation, a version number or a family id: all three
 * are server-owned.
 */
const configurationBody = {
  name: z.string().min(1).max(256),
  device_action_id: z.string().min(1).max(256),
  authorised_user_ids: z.array(z.string().min(1).max(256)).min(1).max(1024),
  context_requirements: contextRequirementsInput,
  minimum_confidence: z.number().min(0).max(1),
  response_protocol_id: WhisperResponseProtocolSchema.nullable(),
  trace_id: z.string().min(1).max(256),
};

const CreateSignalInputSchema = z
  .object({
    /** NULL is organisation-wide scope (W21-03/C11-02), not an unknown site. */
    site_id: z.string().min(1).max(256).nullable(),
    ...configurationBody,
  })
  .strict();
export type CreateSignalInput = z.infer<typeof CreateSignalInputSchema>;

/**
 * A new version carries a whole configuration and NO site: scope belongs to
 * the family. Letting a publish move it would let a site-scoped commander
 * widen a signal to a site they never held authority over.
 */
const PublishVersionInputSchema = z.object({ ...configurationBody }).strict();
export type PublishVersionInput = z.infer<typeof PublishVersionInputSchema>;

/**
 * A DRAFT edit REPLACES the configuration rather than patching fields into it.
 *
 * `classifyWhisperConfigurationEdit` compares two COMPLETE configurations, so
 * partial semantics would mean merging a submitted fragment onto stored state
 * and then fingerprinting the merge — and a caller who omitted a field would
 * be attesting to a value they never sent. A full replacement is the only
 * shape in which "this is the configuration I mean" is unambiguous.
 */
const UpdateDraftInputSchema = z.object({ ...configurationBody }).strict();
export type UpdateDraftInput = z.infer<typeof UpdateDraftInputSchema>;

const TransitionInputSchema = z
  .object({ to: WhisperSignalStatusSchema, trace_id: z.string().min(1).max(256) })
  .strict();
export type TransitionInput = z.infer<typeof TransitionInputSchema>;

const ActivateInputSchema = z.object({ trace_id: z.string().min(1).max(256) }).strict();
export type ActivateInput = z.infer<typeof ActivateInputSchema>;

const ListQuerySchema = z
  .object({
    whisper_signal_id: z.string().min(1).max(256).optional(),
    limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  })
  .strict();
export type ListQuery = z.infer<typeof ListQuerySchema>;

const VersionParamSchema = z.coerce.number().int().positive();

function parseOrBadRequest<T>(schema: z.ZodSchema<T>, raw: unknown): T {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
  return parsed.data;
}

/**
 * B11-10: an UNRESOLVED signal, expressed as one the trusted scope EXCLUDES.
 *
 * The runtime must call `evaluateWhisperRuntimeEligibility` exactly once, and
 * that function needs a signal — so when no stored version answers the signed
 * family and version, the gate is handed this instead of being bypassed by a
 * second, hand-rolled decision tree.
 *
 * WHY THIS SHAPE, PRECISELY. The contract orders its checks so that identity
 * and scope failures are decided BEFORE anything reveals that a signal exists
 * at all. If an unresolved lookup short-circuited to its own refusal, an
 * attacker could submit a deliberately mismatched device context and read the
 * difference: DEVICE_CONTEXT_MISMATCH would mean "the signal resolved",
 * anything else would mean "it did not" — an existence oracle assembled out of
 * two refusals that are individually harmless. Routing through the same gate
 * keeps the ordering intact: the three device-context checks and the
 * authorised-site check still decide first, exactly as they would for a signal
 * that does exist.
 *
 * `organisation_id` is the CONTEXT's, so the gate's organisation check passes
 * and the refusal lands on the site check immediately after it. `site_id` is
 * the recognition's site with a suffix appended, which is STRICTLY LONGER and
 * therefore provably unequal to it — no coincidence of tenant data can make
 * this placeholder look in-scope. The result is SIGNAL_SCOPE_MISMATCH, the
 * same code a foreign or out-of-scope real signal produces, so missing,
 * foreign and out-of-scope are indistinguishable.
 *
 * Every remaining field is independently fail-closed — a terminal status, an
 * empty roster, an impossible confidence threshold, no protocol — so this
 * placeholder could not become eligible even if the gate's ordering ever
 * changed underneath it.
 */
function unresolvableSignalPlaceholder(
  context: AuthenticatedWhisperDeviceContext,
  result: DeviceActionWhisperResult,
): WhisperRuntimeEligibilityInput['signal'] {
  return {
    whisper_signal_id: result.whisper_signal_id,
    organisation_id: context.organisationId,
    site_id: `${result.site_id}\u0000unresolved`,
    status: 'RETIRED',
    signal_version: result.whisper_signal_version,
    device_action_id: result.device_action_id,
    authorised_user_ids: [],
    context_requirements: {},
    minimum_confidence: 1,
    response_protocol_id: null,
  };
}

@Injectable()
export class WhisperService {
  constructor(
    @Inject(WhisperRepository) private readonly repository: WhisperRepository,
    @Inject(WhisperSignatureVerifier) private readonly verifier: WhisperSignatureVerifier,
    @Inject(IncidentsService) private readonly incidents: IncidentsService,
  ) {}

  // ===========================================================================
  // Request parsing (B11-03)
  // ===========================================================================

  parseCreateSignal(raw: unknown): CreateSignalInput {
    return parseOrBadRequest(CreateSignalInputSchema, raw);
  }

  parsePublishVersion(raw: unknown): PublishVersionInput {
    return parseOrBadRequest(PublishVersionInputSchema, raw);
  }

  parseUpdateDraft(raw: unknown): UpdateDraftInput {
    return parseOrBadRequest(UpdateDraftInputSchema, raw);
  }

  parseTransition(raw: unknown): TransitionInput {
    return parseOrBadRequest(TransitionInputSchema, raw);
  }

  parseActivate(raw: unknown): ActivateInput {
    return parseOrBadRequest(ActivateInputSchema, raw);
  }

  parseListQuery(raw: unknown): ListQuery {
    return parseOrBadRequest(ListQuerySchema, raw);
  }

  parseVersion(raw: unknown): number {
    return parseOrBadRequest(VersionParamSchema, raw);
  }

  // ===========================================================================
  // B11-03/B11-04/B11-05 Studio
  // ===========================================================================

  /**
   * B11-03: creates a family at version 1, DRAFT.
   *
   * The organisation comes from the PRINCIPAL and from nowhere else — there is
   * no body field for it, so a caller cannot author into another tenant. The
   * site is the caller's, but only after both checks below: that their grant
   * reaches it, and that it actually exists inside their organisation.
   */
  async createSignal(principal: Principal, input: CreateSignalInput): Promise<WhisperSignalVersionView> {
    this.assertAdministrativeScope(principal, ACTION_WHISPER_SIGNAL_MANAGE, input.site_id);
    if (input.site_id !== null && !(await this.repository.siteExistsInOrganisation(principal.organisation_id, input.site_id))) {
      // WP-17A/C7-07: a nonexistent site and another tenant's real site are
      // the same 404, so this cannot be used to discover that some id is a
      // real site somewhere else in the platform.
      throw new NotFoundException('Site not found');
    }
    const roster = await this.validatedRoster(principal.organisation_id, input.authorised_user_ids);
    const configuration = this.toSemanticConfiguration(input, roster);
    this.assertConfigurationIsContractValid(principal.organisation_id, input.site_id, input.name, configuration, input.trace_id);

    let row: WhisperSignalVersion;
    try {
      row = await this.repository.createSignalFamily({
        organisationId: principal.organisation_id,
        siteId: input.site_id,
        name: input.name,
        deviceActionId: configuration.device_action_id,
        authorisedUserIds: roster,
        contextRequirements: configuration.context_requirements,
        minimumConfidence: configuration.minimum_confidence,
        responseProtocolId: configuration.response_protocol_id,
        configurationFingerprint: whisperConfigurationFingerprint(configuration),
        createdByUserId: principal.user.id,
        traceId: input.trace_id,
      });
    } catch (error) {
      throw this.translateUniquenessConflict(error);
    }

    await this.repository.recordAudit({
      organisationId: row.organisationId,
      siteId: row.siteId,
      kind: AUDIT_WHISPER_SIGNAL_CREATED,
      actorUserId: principal.user.id,
      payload: this.lifecyclePayload(row, principal.user.id, null, 'DRAFT', input.trace_id),
    });
    return this.toVersionView(row);
  }

  /** B11-04: the bounded Studio list, scoped by the caller's read grant. */
  async list(principal: Principal, query: ListQuery): Promise<WhisperSignalVersionView[]> {
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_READ);
    const rows = await this.repository.listForScope(principal.organisation_id, scope, {
      limit: query.limit ?? DEFAULT_LIST_LIMIT,
      whisperSignalId: query.whisper_signal_id,
    });
    return rows.map((row) => this.toVersionView(row));
  }

  /**
   * B11-04: one family and its whole version history.
   *
   * A family the caller's grant does not reach simply is not found. That is
   * the scope filter doing the work — an organisation-wide signal is invisible
   * to a site-scoped commander because `site_id IN (...)` is never true for a
   * NULL — so there is no separate authorisation branch that could disagree
   * with the query, and no 403 that would confirm the family exists.
   */
  async getFamily(principal: Principal, whisperSignalId: string): Promise<WhisperSignalFamilyView> {
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_READ);
    const rows = await this.repository.findFamilyVersions(principal.organisation_id, whisperSignalId, scope);
    const newest = rows[0];
    if (newest === undefined) throw new NotFoundException('Whisper signal not found');
    return {
      whisper_signal_id: newest.whisperSignalId,
      organisation_id: newest.organisationId,
      site_id: newest.siteId,
      versions: rows.map((row) => this.toVersionView(row)),
    };
  }

  /**
   * W21-02: publishes a NEW version of an existing family.
   *
   * This is the only way to change a configuration that has left DRAFT. The
   * new version starts at DRAFT and must walk the whole lifecycle again,
   * because an approval attests to a TESTED configuration and a new
   * configuration has not been tested.
   */
  async publishVersion(principal: Principal, whisperSignalId: string, input: PublishVersionInput): Promise<WhisperSignalVersionView> {
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_MANAGE);
    const roster = await this.validatedRoster(principal.organisation_id, input.authorised_user_ids);
    const configuration = this.toSemanticConfiguration(input, roster);

    // The family's site decides the shape of the contract pre-flight, so it is
    // read before the write — and read UNDER SCOPE, so a family the caller
    // cannot administer is simply absent.
    const latest = await this.repository.findFamilyVersions(principal.organisation_id, whisperSignalId, scope);
    const newest = latest[0];
    if (newest === undefined) throw new NotFoundException('Whisper signal not found');
    this.assertConfigurationIsContractValid(principal.organisation_id, newest.siteId, input.name, configuration, input.trace_id);

    let outcome: WhisperWriteOutcome<WhisperSignalVersion>;
    try {
      outcome = await this.repository.publishNewVersion({
        organisationId: principal.organisation_id,
        whisperSignalId,
        siteScope: scope,
        name: input.name,
        deviceActionId: configuration.device_action_id,
        authorisedUserIds: roster,
        contextRequirements: configuration.context_requirements,
        minimumConfidence: configuration.minimum_confidence,
        responseProtocolId: configuration.response_protocol_id,
        configurationFingerprint: whisperConfigurationFingerprint(configuration),
        createdByUserId: principal.user.id,
        traceId: input.trace_id,
      });
    } catch (error) {
      throw this.translateUniquenessConflict(error);
    }
    const row = this.requireWritten(outcome, 'Whisper signal not found');

    await this.repository.recordAudit({
      organisationId: row.organisationId,
      siteId: row.siteId,
      kind: AUDIT_WHISPER_VERSION_PUBLISHED,
      actorUserId: principal.user.id,
      payload: this.lifecyclePayload(row, principal.user.id, null, 'DRAFT', input.trace_id),
    });
    return this.toVersionView(row);
  }

  /**
   * W21-02: edits a version's configuration, which is legal only while DRAFT.
   *
   * The classification comes from the contract, not from a second opinion
   * here, and each of its three answers is a different response:
   *
   *  - EDITABLE             the version is DRAFT; apply the edit.
   *  - UNCHANGED            past DRAFT but the configuration is identical, so
   *                         there is nothing to refuse and nothing to do. A
   *                         409 here would fail an idempotent retry that had
   *                         actually succeeded.
   *  - REQUIRES_NEW_VERSION past DRAFT and materially different. This is a 409
   *                         naming the remedy, because the version is already
   *                         ACCUMULATING EVIDENCE — simulation results,
   *                         anti-spoof results, a field drill, an approval —
   *                         and editing underneath that evidence is how a
   *                         tested-and-safe label ends up on something nobody
   *                         tested.
   */
  async updateDraft(
    principal: Principal,
    whisperSignalId: string,
    signalVersion: number,
    input: UpdateDraftInput,
  ): Promise<WhisperSignalVersionView> {
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_MANAGE);
    const current = await this.repository.findVersion(principal.organisation_id, whisperSignalId, signalVersion, scope);
    if (current === null) throw new NotFoundException('Whisper signal version not found');

    const roster = await this.validatedRoster(principal.organisation_id, input.authorised_user_ids);
    const proposed = this.toSemanticConfiguration(input, roster);
    this.assertConfigurationIsContractValid(principal.organisation_id, current.siteId, input.name, proposed, input.trace_id);

    const status = this.requireStatus(current);
    const classification = classifyWhisperConfigurationEdit(status, this.storedSemanticConfiguration(current), proposed);
    if (classification === 'UNCHANGED') return this.toVersionView(current);
    if (classification === 'REQUIRES_NEW_VERSION') {
      throw new ConflictException(
        `Configuration of a ${status} version is frozen; publish a new version of this signal instead`,
      );
    }

    const outcome = await this.repository.updateDraftConfiguration({
      organisationId: principal.organisation_id,
      whisperSignalId,
      signalVersion,
      siteScope: scope,
      name: input.name,
      deviceActionId: proposed.device_action_id,
      authorisedUserIds: roster,
      contextRequirements: proposed.context_requirements,
      minimumConfidence: proposed.minimum_confidence,
      responseProtocolId: proposed.response_protocol_id,
      configurationFingerprint: whisperConfigurationFingerprint(proposed),
      actorUserId: principal.user.id,
      traceId: input.trace_id,
    });
    if (outcome.kind === 'status-conflict') {
      throw new ConflictException('This version left DRAFT concurrently; publish a new version of this signal instead');
    }
    return this.toVersionView(this.requireWritten(outcome, 'Whisper signal version not found'));
  }

  /**
   * The section 14.5 lifecycle, one audited step at a time.
   *
   * ACTIVE is refused here even though the contract's table admits
   * APPROVAL -> ACTIVE. Activation is not merely a status change: it needs a
   * SECOND person distinct from the version's creator (W21-12), it must bind
   * the exact tested configuration (W21-13), and it must rotate the incumbent
   * in the same transaction. Allowing it through a generic transition endpoint
   * would let all three be skipped by a caller who simply chose the other
   * route, which is exactly the sort of alternative door a two-person control
   * exists to have none of.
   */
  async transition(
    principal: Principal,
    whisperSignalId: string,
    signalVersion: number,
    input: TransitionInput,
  ): Promise<WhisperSignalVersionView> {
    if (input.to === 'ACTIVE') {
      throw new ConflictException('Activation is not a status transition; use the activate endpoint, which requires a distinct approver');
    }
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_MANAGE);
    const current = await this.repository.findVersion(principal.organisation_id, whisperSignalId, signalVersion, scope);
    if (current === null) throw new NotFoundException('Whisper signal version not found');

    const from = this.requireStatus(current);
    if (!canTransitionWhisperSignalStatus(from, input.to)) {
      throw new ConflictException(`Illegal Whisper signal status transition ${from} -> ${input.to}`);
    }

    const outcome = await this.repository.transitionStatus({
      organisationId: principal.organisation_id,
      whisperSignalId,
      signalVersion,
      siteScope: scope,
      expectedStatus: from,
      toStatus: input.to,
      actorUserId: principal.user.id,
      traceId: input.trace_id,
    });
    if (outcome.kind === 'status-conflict') {
      throw new ConflictException('This version changed status concurrently; re-read it and retry');
    }
    return this.toVersionView(this.requireWritten(outcome, 'Whisper signal version not found'));
  }

  /**
   * W21-12/W21-13: activation, by a SECOND authenticated person.
   *
   * `whisper.signal.approve` is a separate capability from
   * `whisper.signal.manage`, but the separation W21-12 actually requires is
   * between distinct PEOPLE — site.commander holds both, and the distinctness
   * check below is what enforces the control. A creator approving their own
   * signal would make the entire test-and-approve lifecycle self-attesting:
   * one compromised or mistaken account could mint an active silent-dispatch
   * trigger end to end.
   *
   * The approval binds the CURRENT PERSISTED fingerprint, read here and
   * re-asserted as a compare-and-set inside the activating transaction. An
   * approval that does not match the stored configuration is an approval of
   * something that no longer exists.
   */
  async activate(
    principal: Principal,
    whisperSignalId: string,
    signalVersion: number,
    input: ActivateInput,
  ): Promise<WhisperSignalVersionView> {
    const scope = intersectSiteScope(principal, ACTION_WHISPER_SIGNAL_APPROVE);
    const current = await this.repository.findVersion(principal.organisation_id, whisperSignalId, signalVersion, scope);
    if (current === null) throw new NotFoundException('Whisper signal version not found');

    const from = this.requireStatus(current);
    if (!canTransitionWhisperSignalStatus(from, 'ACTIVE')) {
      throw new ConflictException(`A ${from} version cannot be activated; it must reach APPROVAL first`);
    }
    if (!whisperActivationApproverIsDistinct(current.createdByUserId, principal.user.id)) {
      throw new ConflictException('Activation requires an approver distinct from the version creator');
    }
    // W21-10: ACTIVE without an allowlisted protocol reference is refused by
    // the contract itself, so it is refused HERE — before the write — rather
    // than as a round-trip failure after a durable state change.
    if (!isAllowlistedWhisperResponseProtocol(current.responseProtocolId)) {
      throw new ConflictException('This version has no allowlisted response protocol and cannot be activated');
    }

    let outcome: WhisperWriteOutcome<{ activated: WhisperSignalVersion; rotatedVersions: number[] }>;
    try {
      outcome = await this.repository.activate({
        organisationId: principal.organisation_id,
        whisperSignalId,
        signalVersion,
        siteScope: scope,
        expectedStatus: from,
        expectedConfigurationFingerprint: current.configurationFingerprint,
        createdByUserId: current.createdByUserId,
        approvedByUserId: principal.user.id,
        traceId: input.trace_id,
      });
    } catch (error) {
      throw this.translateUniquenessConflict(error);
    }
    if (outcome.kind === 'status-conflict') {
      throw new ConflictException('This version changed status concurrently; re-read it and retry');
    }
    if (outcome.kind === 'fingerprint-conflict') {
      throw new ConflictException('This version has changed configuration since it was read; re-read it and retry');
    }
    return this.toVersionView(this.requireWritten(outcome, 'Whisper signal version not found').activated);
  }

  // ===========================================================================
  // B11-08..B11-12 runtime
  // ===========================================================================

  /**
   * Submits ONE device-action recognition.
   *
   * INTERNAL ONLY, AND NO CONTROLLER REACHES IT. `deviceContext` is a TRUSTED
   * ARGUMENT (W21-05): a `device_id`, an actor, an organisation or a trust
   * level read from a JSON body is not authenticated device identity, and this
   * method's entire safety argument rests on that context being established by
   * the platform. Exposing a route before a genuine device-authentication
   * facility exists would mean accepting the context from the wire — the exact
   * trust hole the ruling forbids, on the one channel where the consequence is
   * a forged silent duress dispatch. The seam is this method; whoever builds
   * that facility wires the transport.
   *
   * The order below is the ruling's order, and each step's placement carries
   * an argument — see the comments at each one.
   */
  async recognise(
    deviceContext: AuthenticatedWhisperDeviceContext,
    rawResult: unknown,
    principal: Principal,
  ): Promise<WhisperRecognitionOutcome> {
    // ---- 1. Parse. NO PERSISTENCE. --------------------------------------
    // A result that does not satisfy the contract never reached a trusted
    // device's signing routine in the shape we require, so it leaves no trace
    // and consumes no replay identity. It also has no canonical statement, so
    // there is nothing here to fingerprint or audit.
    const parsed = DeviceActionWhisperResultSchema.safeParse(rawResult);
    if (!parsed.success) return { kind: 'invalid', issues: parsed.error.issues.map((issue) => issue.message) };
    const result = parsed.data;
    const recognitionFingerprint = whisperRecognitionFingerprint(result);

    // ---- 2. Signature FIRST. Still no receipt. ---------------------------
    // B11-12: AN INVALID SIGNATURE MUST NOT CONSUME A REPLAY IDENTITY. The
    // seven-column identity is a one-shot resource, and every field of it is
    // attacker-chosen in an unsigned submission — so writing a receipt before
    // the signature is proven would let anyone who can reach this method burn
    // the identities a genuine operative's future recognitions need. The
    // refusal is still AUDITED: an unverifiable attempt on a silent duress
    // channel is exactly the thing oversight must be able to see.
    if (!(await this.verifier.verify(deviceContext, result))) {
      await this.repository.recordAudit(
        this.recognitionAudit({
          context: deviceContext,
          result,
          recognitionFingerprint,
          configurationFingerprint: null,
          outcome: 'REFUSED',
          conflictCode: 'SIGNATURE_INVALID',
          responseProtocolId: null,
          incidentId: null,
        }),
      );
      return { kind: 'refused', conflict_code: 'SIGNATURE_INVALID', recognition_fingerprint: recognitionFingerprint, replayed: false };
    }

    // ---- 3. Resolve the stored version. ----------------------------------
    // The ORGANISATION comes from the trusted context; the family and version
    // come from the SIGNED result. A missing or foreign signal is not reported
    // as missing — it is handed to the gate as an out-of-scope signal, which
    // collapses it into the same refusal a real out-of-scope signal produces.
    const stored = await this.repository.findVersionForRuntime(
      deviceContext.organisationId,
      result.whisper_signal_id,
      result.whisper_signal_version,
    );

    // ---- 4. SERVER facts. -------------------------------------------------
    const serverFacts = await this.serverFacts(deviceContext, result);

    // ---- 5. Freshness, against the AUTHORITATIVE server clock. -----------
    // The submitted `freshness_ms` plays no part whatsoever: a device that
    // under-reports its own age must not thereby extend its acceptance window.
    // This same instant becomes the receipt's `recorded_at`, so the time the
    // decision was judged against and the time the receipt records are one
    // value rather than two that could disagree.
    const receivedAt = await this.repository.now();
    const freshness = classifyWhisperRecognitionFreshness(new Date(result.recognised_at), receivedAt);

    // ---- 6. CURRENT authority, recomputed now. ---------------------------
    // W21-04: the roster on a stored version is an allowlist, not a grant.
    // This is the live answer to "may this authenticated person do this here,
    // now", so revoking someone stops them even while an older active version
    // still lists their id. The site is the recognition's, already bound to
    // the device context by the gate that follows.
    const invokeScope = intersectSiteScope(principal, ACTION_WHISPER_DEVICE_ACTION_INVOKE);
    const actorHoldsCurrentAuthority =
      principal.hasAction(ACTION_WHISPER_DEVICE_ACTION_INVOKE) &&
      (invokeScope.orgWide || invokeScope.siteIds.includes(result.site_id));

    // ---- 7. THE GATE, ONCE. ----------------------------------------------
    // Every ordering argument in W21-04/W21-07/C11-02/C11-05 lives inside this
    // one function. A second decision tree here — even a faithful one — would
    // be a second thing to keep faithful, and the first place a future edit
    // would drift.
    const eligibility = evaluateWhisperRuntimeEligibility({
      signal: stored === null ? unresolvableSignalPlaceholder(deviceContext, result) : this.toGateSignal(stored),
      context: deviceContext,
      result,
      actorHoldsCurrentAuthority,
      serverFacts,
      freshness,
    });

    // ---- 8. The durable receipt. -----------------------------------------
    return this.consumeReplayIdentity({
      deviceContext,
      result,
      recognitionFingerprint,
      receivedAt,
      storedVersionId: stored?.id ?? null,
      configurationFingerprint: stored?.configurationFingerprint ?? null,
      eligibility,
    });
  }

  /**
   * W21-07: the facts the SERVER establishes about the world at recognition
   * time. The submitted `context` is ignored ENTIRELY — it is not read, not
   * merged and not compared. A device asserting `{on_duty: true}` about itself
   * is precisely what this gate exists to not believe.
   *
   * `on_duty` is derived from authoritative Field state for the exact
   * (organisation, site, actor), and its three cases are deliberate:
   *
   *  - NO ROW: the key is OMITTED, not set false. An absent fact fails the
   *    contract's context gate closed, which is the correct answer to "the
   *    server cannot establish this" — a silent dispatch is not something to
   *    grant on a guess, and it is not something to refuse with a fabricated
   *    negative either.
   *  - OFF_DUTY: false. The one state that genuinely means not on duty.
   *  - EVERY OTHER DEFINED STATE: true, INCLUDING COMPROMISED. A compromised
   *    operative is on duty and is exactly the person a duress channel exists
   *    for — treating that state as "not on duty" would disable the signal for
   *    the situation it was built to report. Device trust remains a wholly
   *    independent gate: a compromised DEVICE is still refused by
   *    DEVICE_TRUST_INSUFFICIENT, which is a different judgement about a
   *    different subject.
   */
  private async serverFacts(
    context: AuthenticatedWhisperDeviceContext,
    result: DeviceActionWhisperResult,
  ): Promise<ServerWhisperContextFacts> {
    const facts: Record<string, unknown> = {};
    const dutyState = await this.repository.onDutyFact(context.organisationId, result.site_id, context.actorUserId);
    if (dutyState !== null) facts.on_duty = dutyState !== 'OFF_DUTY';
    return facts;
  }

  /**
   * B11-12: the one-shot identity, and everything that turns on it.
   *
   * THE IDENTITY IS BUILT FROM THE AUTHENTICATED CONTEXT, not from the signed
   * result, for organisation, actor and device. The contract's own helper
   * still shapes it — so the seven columns stay the contract's structure — but
   * the three values that decide WHOSE namespace is being spent come from
   * W21-05's server-established context.
   *
   * WHY THAT MATTERS. A compromised-but-trusted device in tenant A can sign a
   * statement CLAIMING tenant B. If the receipt were keyed on the claim, that
   * device could pre-consume arbitrary (organisation, site, actor, device,
   * signal, nonce) tuples across every tenant on the platform; a genuine
   * operative in B who later signalled with a pre-consumed nonce would be met
   * with REPLAY_IDENTITY_REUSED, and their duress signal would be refused.
   * That is a denial of service on the duress channel itself, mounted from
   * outside the victim's tenant. Binding the identity to the authenticated
   * context confines every such attempt to the attacker's own namespace, where
   * the gate refuses it as DEVICE_CONTEXT_MISMATCH anyway. For every outcome
   * other than that mismatch the two compositions are byte-identical, because
   * the gate has already proven the claim equals the context.
   */
  private async consumeReplayIdentity(input: {
    deviceContext: AuthenticatedWhisperDeviceContext;
    result: DeviceActionWhisperResult;
    recognitionFingerprint: string;
    receivedAt: Date;
    storedVersionId: string | null;
    configurationFingerprint: string | null;
    eligibility: ReturnType<typeof evaluateWhisperRuntimeEligibility>;
  }): Promise<WhisperRecognitionOutcome> {
    const { deviceContext, result, recognitionFingerprint } = input;
    const identity = deviceActionWhisperReplayIdentity({
      organisation_id: deviceContext.organisationId,
      site_id: result.site_id,
      actor_user_id: deviceContext.actorUserId,
      device_id: deviceContext.deviceId,
      whisper_signal_id: result.whisper_signal_id,
      whisper_signal_version: result.whisper_signal_version,
      anti_replay_nonce: result.anti_replay_nonce,
    });

    const existing = await this.repository.findReceiptByIdentity(identity);
    const preflight = await this.classifyAgainstReceipt(input, existing);
    if (preflight !== null) return preflight;

    let receipt: WhisperStoredReceipt;
    try {
      const ensured = await this.repository.ensureReceipt({
        identity,
        signalVersionId: input.storedVersionId,
        recognitionFingerprint,
        recordedAt: input.receivedAt,
        traceId: result.trace_id,
      });
      receipt = ensured.receipt;
    } catch (error) {
      if (error instanceof WhisperUniquenessConflictError) throw new WhisperRecognitionUnresolvedError(error.message);
      throw error;
    }
    // The create may have lost a race with a concurrent attempt on the same
    // identity, so the row in hand is re-classified rather than assumed fresh.
    const postflight = await this.classifyAgainstReceipt(input, receipt);
    if (postflight !== null) return postflight;

    const claimGeneration = await this.repository.claimReceipt(receipt.id);
    if (claimGeneration === null) {
      // Either a live attempt holds the claim, or it finalized between the
      // classification above and this line. Re-read before concluding
      // anything: the other attempt's stored outcome is the truthful answer,
      // and if there is none yet, this attempt genuinely does not know.
      return this.reportLostFence(receipt.id);
    }

    return this.executeAndFinalize({ ...input, receipt, claimGeneration });
  }

  /**
   * The two answers a pre-existing receipt can give, and nothing else.
   *
   *  - SAME identity, DIFFERENT statement: REPLAY_IDENTITY_REUSED, with ZERO
   *    effect. A recognition may be retried; it may never be replayed, and a
   *    reused one-shot identity carrying a different statement is the
   *    signature of a captured recognition being re-presented.
   *  - SAME identity, SAME statement, already finalized: the STORED terminal
   *    outcome, verbatim. It is rebuilt from receipt columns and never
   *    recomputed from current state, so a retry cannot produce a different
   *    answer than the one already recorded.
   *
   * `null` means neither applies and the caller should proceed.
   */
  private async classifyAgainstReceipt(
    input: {
      deviceContext: AuthenticatedWhisperDeviceContext;
      result: DeviceActionWhisperResult;
      recognitionFingerprint: string;
      configurationFingerprint: string | null;
    },
    receipt: WhisperStoredReceipt | null,
  ): Promise<WhisperRecognitionOutcome | null> {
    if (receipt === null) return null;
    if (receipt.recognitionFingerprint !== input.recognitionFingerprint) {
      await this.repository.recordAudit(
        this.recognitionAudit({
          context: input.deviceContext,
          result: input.result,
          recognitionFingerprint: input.recognitionFingerprint,
          configurationFingerprint: input.configurationFingerprint,
          outcome: 'REFUSED',
          conflictCode: 'REPLAY_IDENTITY_REUSED',
          responseProtocolId: null,
          incidentId: null,
        }),
      );
      return {
        kind: 'refused',
        conflict_code: 'REPLAY_IDENTITY_REUSED',
        recognition_fingerprint: input.recognitionFingerprint,
        replayed: false,
      };
    }
    return this.isFinalized(receipt) ? this.storedOutcome(receipt) : null;
  }

  /**
   * The claimed attempt: recover, decide, finalize.
   *
   * TRUTHFUL RECOVERY BEFORE RE-DECIDING (the WP-20/B10-02 precedent, and it
   * bites harder here). Generation 1 is the first attempt, so nothing can have
   * committed under this receipt and the gate's verdict is the whole truth.
   * Generation > 1 means an earlier attempt claimed this receipt and died
   * without finalizing — and by the time the lease expires, the recognition is
   * almost certainly older than the freshness window, so re-deciding would
   * return RECOGNITION_STALE. Writing that as the outcome would record a
   * REFUSAL for a duress signal whose incident is already open: false history,
   * on the one record that says whether anyone was sent.
   *
   * So the incidents domain is asked for evidence first. The incident is keyed
   * by `(organisation_id, 'WHISPER_RECOGNITION', recognition_fingerprint)` and
   * written in one transaction, so its presence PROVES the effect committed
   * and its absence proves it did not. On evidence, the receipt is finalized
   * ACCEPTED against the incident that already exists and the gate's stale
   * verdict is discarded.
   */
  private async executeAndFinalize(input: {
    deviceContext: AuthenticatedWhisperDeviceContext;
    result: DeviceActionWhisperResult;
    recognitionFingerprint: string;
    configurationFingerprint: string | null;
    eligibility: ReturnType<typeof evaluateWhisperRuntimeEligibility>;
    receipt: WhisperStoredReceipt;
    claimGeneration: number;
  }): Promise<WhisperRecognitionOutcome> {
    const { deviceContext, result, recognitionFingerprint, receipt, claimGeneration } = input;

    const recovered =
      claimGeneration > 1
        ? await this.incidents.findWhisperSilentIncident(deviceContext.organisationId, recognitionFingerprint)
        : null;

    if (recovered === null && !input.eligibility.eligible) {
      return this.finalizeAndReport({
        receiptId: receipt.id,
        claimGeneration,
        recognitionFingerprint,
        status: RECEIPT_STATUS_REFUSED,
        outcome: RECEIPT_OUTCOME_REFUSED,
        conflictCode: input.eligibility.conflictCode,
        incidentId: null,
        audit: this.recognitionAudit({
          context: deviceContext,
          result,
          recognitionFingerprint,
          configurationFingerprint: input.configurationFingerprint,
          outcome: 'REFUSED',
          conflictCode: input.eligibility.conflictCode,
          responseProtocolId: null,
          incidentId: null,
        }),
      });
    }

    // W21-10: the protocol comes from the STORED version the gate resolved and
    // never from the device — a device that could sign its own protocol could
    // choose its own consequence. On the recovery path the gate may no longer
    // find the recognition eligible (typically because it is now stale), so
    // this attempt records NO protocol rather than restating one it did not
    // resolve; the attempt that actually accepted it wrote its own audit row
    // carrying the protocol it did resolve.
    const responseProtocolId: WhisperResponseProtocol | null = input.eligibility.eligible
      ? input.eligibility.responseProtocolId
      : null;

    let incidentId: string;
    if (recovered !== null) {
      incidentId = recovered.incidentId;
    } else {
      try {
        const opened = await this.incidents.openWhisperSilentIncident({
          organisationId: deviceContext.organisationId,
          siteId: result.site_id,
          recognitionFingerprint,
          // C11-04: the SIGNED confidence. It is evidence, never authority,
          // and it can only ever have narrowed what the gate permitted.
          confidence: result.confidence,
          traceId: result.trace_id,
        });
        incidentId = opened.incidentId;
      } catch {
        // The effect may or may not have committed. That is the one thing this
        // module must never guess about, so the receipt records UNKNOWN — which
        // is immediately reclaimable — and the caller is told to retry rather
        // than handed a decided outcome. The retry converges: the incident's
        // source identity is unique, so a second entry on this fingerprint
        // reuses the first incident instead of opening another.
        await this.markUnknownQuietly(receipt.id, claimGeneration);
        throw new WhisperRecognitionUnresolvedError();
      }
    }

    return this.finalizeAndReport({
      receiptId: receipt.id,
      claimGeneration,
      recognitionFingerprint,
      status: RECEIPT_STATUS_APPLIED,
      outcome: RECEIPT_OUTCOME_ACCEPTED,
      conflictCode: null,
      incidentId,
      audit: this.recognitionAudit({
        context: deviceContext,
        result,
        recognitionFingerprint,
        configurationFingerprint: input.configurationFingerprint,
        outcome: 'ACCEPTED',
        conflictCode: null,
        responseProtocolId,
        incidentId,
      }),
    });
  }

  /**
   * Finalizes, then reports what was actually recorded.
   *
   * A finalization that FAILS is the "we genuinely do not know" case: the
   * silent incident may already be open, so the receipt is marked UNKNOWN and
   * the caller retries into convergence rather than being handed a verdict
   * this attempt never durably recorded. A finalization whose FENCE was lost
   * means a newer attempt owns the receipt, so the honest answer is that
   * attempt's stored outcome, not this one's.
   */
  private async finalizeAndReport(
    input: FinalizeReceiptInput & { recognitionFingerprint: string; conflictCode: WhisperRecognitionConflictCode | null },
  ): Promise<WhisperRecognitionOutcome> {
    let result: 'finalized' | 'lost';
    try {
      result = await this.repository.finalizeReceipt(input);
    } catch {
      await this.markUnknownQuietly(input.receiptId, input.claimGeneration);
      throw new WhisperRecognitionUnresolvedError();
    }
    if (result === 'lost') return this.reportLostFence(input.receiptId);
    if (input.conflictCode === null) {
      return {
        kind: 'accepted',
        recognition_fingerprint: input.recognitionFingerprint,
        incident_id: input.incidentId,
        replayed: false,
      };
    }
    return {
      kind: 'refused',
      conflict_code: input.conflictCode,
      recognition_fingerprint: input.recognitionFingerprint,
      replayed: false,
    };
  }

  /**
   * B11-12: this attempt's fence did not match, so a NEWER attempt owns the
   * receipt and this one wrote nothing.
   *
   * Re-read it. If the owner already finalized, answer with THAT stored
   * outcome down the ordinary replay path — built purely from receipt columns,
   * never recomputed. If it has not finalized yet, the owner is still live and
   * this attempt genuinely cannot say what happened.
   */
  private async reportLostFence(receiptId: string): Promise<WhisperRecognitionOutcome> {
    const current = await this.repository.getReceiptById(receiptId);
    if (current !== null && this.isFinalized(current)) return this.storedOutcome(current);
    throw new WhisperRecognitionUnresolvedError();
  }

  /**
   * Records UNKNOWN without letting a second fault mask the first.
   *
   * The caller is already on its way to reporting an unresolved outcome, so a
   * failure to write the UNKNOWN changes nothing about that answer: the
   * receipt simply stays APPLYING and becomes reclaimable when its lease
   * expires, which is the same recovery path by a slower route.
   */
  private async markUnknownQuietly(receiptId: string, claimGeneration: number): Promise<void> {
    try {
      await this.repository.markReceiptUnknown({ receiptId, claimGeneration });
    } catch {
      // Deliberately swallowed; see this method's contract above.
    }
  }

  private isFinalized(receipt: WhisperStoredReceipt): boolean {
    return TERMINAL_RECEIPT_STATUSES.includes(receipt.status);
  }

  /** The stored terminal outcome, rebuilt from receipt columns alone. */
  private storedOutcome(receipt: WhisperStoredReceipt): WhisperRecognitionOutcome {
    if (receipt.status === RECEIPT_STATUS_APPLIED) {
      return {
        kind: 'accepted',
        recognition_fingerprint: receipt.recognitionFingerprint,
        incident_id: receipt.incidentId,
        replayed: true,
      };
    }
    const conflictCode = WhisperRecognitionConflictCodeSchema.safeParse(receipt.conflictCode);
    // A REFUSED receipt without a recognisable code cannot be reported
    // honestly, and guessing one would put a reason in the record that nobody
    // decided. Fail loudly instead.
    if (!conflictCode.success) {
      throw new Error(`Corrupt Whisper recognition receipt ${receipt.id}: refused without a recognisable conflict code`);
    }
    return {
      kind: 'refused',
      conflict_code: conflictCode.data,
      recognition_fingerprint: receipt.recognitionFingerprint,
      replayed: true,
    };
  }

  /**
   * W21-14: IDENTITY AND DISPOSITION ONLY.
   *
   * The schema's `.strict()` is what actually enforces this, but the call site
   * matters too: there is no parameter here through which a signature, a key,
   * a nonce, a submitted context value or the authorised-user roster could
   * travel, so the payload cannot be widened by passing more in. The
   * organisation is the TRUSTED one; the site is the site AS RECORDED at the
   * moment of the event, which is what a history artefact should hold.
   */
  private recognitionAudit(input: {
    context: AuthenticatedWhisperDeviceContext;
    result: DeviceActionWhisperResult;
    recognitionFingerprint: string;
    configurationFingerprint: string | null;
    outcome: 'ACCEPTED' | 'REFUSED';
    conflictCode: WhisperRecognitionConflictCode | null;
    responseProtocolId: WhisperResponseProtocol | null;
    incidentId: string | null;
  }): WhisperAuditInput {
    return {
      organisationId: input.context.organisationId,
      siteId: input.result.site_id,
      kind: input.outcome === 'ACCEPTED' ? AUDIT_WHISPER_RECOGNITION_ACCEPTED : AUDIT_WHISPER_RECOGNITION_REFUSED,
      actorUserId: input.context.actorUserId,
      payload: {
        whisper_signal_id: input.result.whisper_signal_id,
        signal_version: input.result.whisper_signal_version,
        configuration_fingerprint: input.configurationFingerprint,
        actor_user_id: input.context.actorUserId,
        device_id: input.context.deviceId,
        from_status: null,
        to_status: null,
        outcome: input.outcome,
        conflict_code: input.conflictCode,
        recognition_fingerprint: input.recognitionFingerprint,
        response_protocol_id: input.responseProtocolId,
        incident_id: input.incidentId,
        trace_id: input.result.trace_id,
      },
    };
  }

  // ===========================================================================
  // Shared helpers
  // ===========================================================================

  /**
   * B11-03: which signals this principal may administer.
   *
   * An organisation-wide signal (site_id NULL) may be recognised at EVERY site
   * in the tenant, so administering one is an organisation-wide power and
   * requires an org-wide grant. A site-scoped commander is confined to their
   * own sites. This is only needed where the caller NAMES a site — everywhere
   * else the same rule is enforced by the repository's scope filter, so an
   * out-of-scope signal is simply not found rather than refused with a 403
   * that would confirm it exists.
   */
  private assertAdministrativeScope(principal: Principal, action: string, siteId: string | null): void {
    const scope = intersectSiteScope(principal, action);
    if (siteId === null) {
      if (!scope.orgWide) {
        throw new ForbiddenException('An organisation-wide Whisper signal requires an organisation-wide grant');
      }
      return;
    }
    if (!scope.orgWide && !scope.siteIds.includes(siteId)) {
      throw new ForbiddenException('Principal is not scoped to this site');
    }
  }

  /**
   * B11-05: every roster member must belong to the principal's organisation,
   * and the refusal must not say WHICH one did not.
   *
   * Naming the failing id would turn a signal-authoring form into a
   * cross-tenant user-existence oracle: submit a candidate id, read whether it
   * was singled out. The roster is returned SORTED because it is an allowlist
   * SET — the contract's fingerprint sorts before digesting for exactly that
   * reason, so storing it sorted keeps the stored order and the digested order
   * the same thing.
   */
  private async validatedRoster(organisationId: string, userIds: readonly string[]): Promise<string[]> {
    const known = await this.repository.userIdsInOrganisation(organisationId, userIds);
    if (userIds.some((id) => !known.has(id))) {
      throw new BadRequestException('one or more authorised_user_ids are not members of this organisation');
    }
    return [...userIds].sort();
  }

  private toSemanticConfiguration(
    input: { device_action_id: string; context_requirements: Record<string, WhisperJsonValue>; minimum_confidence: number; response_protocol_id: WhisperResponseProtocol | null },
    roster: string[],
  ): WhisperSemanticConfiguration {
    return {
      modality: 'DEVICE_ACTION',
      device_action_id: input.device_action_id,
      authorised_user_ids: roster,
      context_requirements: input.context_requirements,
      minimum_confidence: input.minimum_confidence,
      response_protocol_id: input.response_protocol_id,
    };
  }

  /**
   * A PRE-FLIGHT through the contract's own schema, before any write.
   *
   * This is how the context byte budget, the roster uniqueness rule and every
   * other bound the contract owns are enforced at the request boundary without
   * restating a single one of them here — no duplicated constant to drift, and
   * no bound that could be tightened in the contract and silently missed. The
   * alternative is a post-write round-trip failure, which means the caller is
   * told the request failed while a durable side effect succeeded.
   *
   * The probe is built at DRAFT with matched timestamps, because DRAFT is what
   * create, publish and edit all produce: the contract's ACTIVE-requires-a-
   * protocol rule is inert here and is enforced at activation instead.
   */
  private assertConfigurationIsContractValid(
    organisationId: string,
    siteId: string | null,
    name: string,
    configuration: WhisperSemanticConfiguration,
    traceId: string,
  ): void {
    const at = new Date().toISOString();
    const probe = WhisperSignalSchema.safeParse({
      schema_version: 1,
      // The real family id is server-generated at write time; this placeholder
      // exercises the same `scopedId` bound and nothing else.
      whisper_signal_id: 'pre-flight',
      organisation_id: organisationId,
      site_id: siteId,
      name,
      signal_version: 1,
      status: 'DRAFT',
      ...configuration,
      created_at: at,
      updated_at: at,
      created_by_user_id: 'pre-flight',
      trace_id: traceId,
    });
    if (!probe.success) {
      throw new BadRequestException({ message: probe.error.issues.map((issue) => issue.message) });
    }
  }

  /**
   * B11-04: round-trips a persisted row through WhisperSignalSchema before it
   * leaves the service, so a drifted or corrupt row is refused rather than
   * rendered as though the platform stood behind it.
   */
  private toVersionView(row: WhisperSignalVersion): WhisperSignalVersionView {
    const parsed = WhisperSignalSchema.safeParse({
      schema_version: 1,
      whisper_signal_id: row.whisperSignalId,
      organisation_id: row.organisationId,
      site_id: row.siteId,
      name: row.name,
      signal_version: row.signalVersion,
      status: row.status,
      modality: row.modality,
      device_action_id: row.deviceActionId,
      authorised_user_ids: [...row.authorisedUserIds],
      context_requirements: row.contextRequirements,
      minimum_confidence: row.minimumConfidence,
      response_protocol_id: row.responseProtocolId,
      created_at: row.createdAt.toISOString(),
      updated_at: row.updatedAt.toISOString(),
      created_by_user_id: row.createdByUserId,
      trace_id: row.traceId,
    });
    // The message names the row and nothing in it: a corruption report is not
    // a licence to echo a roster or a requirement set into a log.
    if (!parsed.success) throw new Error(`Corrupt Whisper signal version row ${row.id}`);
    return {
      ...parsed.data,
      configuration_fingerprint: row.configurationFingerprint,
      activated_at: row.activatedAt?.toISOString() ?? null,
      rotated_at: row.rotatedAt?.toISOString() ?? null,
      retired_at: row.retiredAt?.toISOString() ?? null,
    };
  }

  /**
   * The RUNTIME's narrow view of a stored version — deliberately NOT the full
   * `WhisperSignalSchema` round-trip that Studio performs.
   *
   * Studio can afford to refuse a row over any contract violation; the duress
   * runtime cannot. `WhisperSignalSchema` also validates `name`, `trace_id`
   * and `updated_at >= created_at` — and that last one compares a database
   * `DEFAULT CURRENT_TIMESTAMP` against a value Prisma stamps from the
   * application clock, so ordinary clock skew between the two could make a
   * perfectly good row fail. Refusing to evaluate a duress recognition because
   * two clocks disagree by a millisecond is not a trade worth making.
   *
   * So exactly the ten fields the gate reads are validated, and only where
   * misinterpretation could make the gate WRONG rather than merely strict:
   * `status`, because only ACTIVE proceeds; `context_requirements`, because a
   * non-record would be iterated as one; and the protocol reference, which the
   * gate re-checks against its own allowlist regardless. A row that fails
   * these is a data-integrity fault, not a runtime condition — it can only
   * arise from a writer that bypassed this service — so it is raised loudly
   * BEFORE any receipt exists, which means nothing fires and no replay
   * identity is consumed.
   */
  private toGateSignal(row: WhisperSignalVersion): WhisperRuntimeEligibilityInput['signal'] {
    return {
      whisper_signal_id: row.whisperSignalId,
      organisation_id: row.organisationId,
      site_id: row.siteId,
      status: this.requireStatus(row),
      signal_version: row.signalVersion,
      device_action_id: row.deviceActionId,
      authorised_user_ids: [...row.authorisedUserIds],
      context_requirements: this.requireCanonicalRequirements(row),
      minimum_confidence: row.minimumConfidence,
      response_protocol_id: this.requireProtocol(row),
    };
  }

  /** The stored configuration in the shape `classifyWhisperConfigurationEdit` compares. */
  private storedSemanticConfiguration(row: WhisperSignalVersion): WhisperSemanticConfiguration {
    if (row.modality !== 'DEVICE_ACTION') throw new Error(`Corrupt Whisper signal version row ${row.id}: unknown modality`);
    return {
      modality: 'DEVICE_ACTION',
      device_action_id: row.deviceActionId,
      authorised_user_ids: [...row.authorisedUserIds],
      context_requirements: this.requireCanonicalRequirements(row),
      minimum_confidence: row.minimumConfidence,
      response_protocol_id: this.requireProtocol(row),
    };
  }

  private requireStatus(row: WhisperSignalVersion): WhisperSignalStatus {
    const status = WhisperSignalStatusSchema.safeParse(row.status);
    if (!status.success) throw new Error(`Corrupt Whisper signal version row ${row.id}: unknown status`);
    return status.data;
  }

  private requireProtocol(row: WhisperSignalVersion): WhisperResponseProtocol | null {
    if (row.responseProtocolId === null) return null;
    const protocol = WhisperResponseProtocolSchema.safeParse(row.responseProtocolId);
    if (!protocol.success) throw new Error(`Corrupt Whisper signal version row ${row.id}: unknown response protocol`);
    return protocol.data;
  }

  private requireCanonicalRequirements(row: WhisperSignalVersion): Record<string, WhisperJsonValue> {
    if (!isCanonicalJsonRecord(row.contextRequirements)) {
      throw new Error(`Corrupt Whisper signal version row ${row.id}: context requirements are not canonically representable`);
    }
    return row.contextRequirements as Record<string, WhisperJsonValue>;
  }

  private requireWritten<T>(outcome: WhisperWriteOutcome<T>, notFoundMessage: string): T {
    if (outcome.kind === 'written') return outcome.row;
    if (outcome.kind === 'not-found') throw new NotFoundException(notFoundMessage);
    if (outcome.kind === 'fingerprint-conflict') {
      throw new ConflictException('This version has changed configuration since it was read; re-read it and retry');
    }
    throw new ConflictException(`This version is ${outcome.currentStatus}; re-read it and retry`);
  }

  /** A lifecycle audit payload: identity, status and digest — never configuration. */
  private lifecyclePayload(
    row: WhisperSignalVersion,
    actorUserId: string,
    fromStatus: WhisperSignalStatus | null,
    toStatus: WhisperSignalStatus,
    traceId: string,
  ): WhisperAuditInput['payload'] {
    return {
      whisper_signal_id: row.whisperSignalId,
      signal_version: row.signalVersion,
      configuration_fingerprint: row.configurationFingerprint,
      actor_user_id: actorUserId,
      device_id: null,
      from_status: fromStatus,
      to_status: toStatus,
      outcome: null,
      conflict_code: null,
      recognition_fingerprint: null,
      response_protocol_id: null,
      incident_id: null,
      trace_id: traceId,
    };
  }

  /**
   * A translated uniqueness race, never a raw Prisma error. The constraint
   * name and the colliding columns must not reach a response — for this module
   * they would name a nonce, a roster member or another tenant's identifiers.
   */
  private translateUniquenessConflict(error: unknown): unknown {
    return error instanceof WhisperUniquenessConflictError ? new ConflictException(error.message) : error;
  }
}
