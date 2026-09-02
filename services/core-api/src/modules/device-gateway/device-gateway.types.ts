import type { DeviceRequestProofRefusal, DevicePrincipalRefusal, DeviceTrust } from '@sentinel/contracts';
import type { DeviceGatewayOperationKind, DeviceGatewayTargetType } from './device-gateway.envelope';

/**
 * WP-25 — THE TWO REFUSAL VOCABULARIES, AND WHY THERE ARE TWO.
 *
 * D25-13 rules that the refusal boundary is not an enumeration oracle:
 *
 *     foreign-tenant device      nonexistent device
 *     foreign context            nonexistent context
 *     device not usable by this actor / site
 *
 * all shape the SAME external refusal, while "the precise security reason and
 * the trace id are appended to the internal audit". That is two vocabularies,
 * not one vocabulary with a redaction step — a redaction step is a filter, and
 * a filter fails open the day somebody adds a case to it.
 *
 * `DeviceGatewayRefusal` below is the INTERNAL one. It is deliberately richer
 * than anything a caller is told, it is written to
 * `DeviceGatewayOperationEvent.refusal_reason`, and it never crosses the HTTP
 * boundary. The external answer is `DeviceGatewayExternalRefusal`, which has
 * three members and no relationship to the internal reason beyond the mapping
 * the controller applies.
 */
export const DEVICE_GATEWAY_REFUSALS = [
  /** The request body or the proof did not parse as the shapes this module accepts. */
  'ENVELOPE_MALFORMED',
  'PROOF_MALFORMED',
  /** D25-11: a body-supplied `operation_kind` or `target_type` disagreed with the ROUTE. */
  'OPERATION_KIND_CONFLICT',
  /** The persisted context is absent, foreign, closed or past its ceiling. */
  'CONTEXT_NOT_USABLE',
  /** The device is absent, foreign, or has no resolvable current key. */
  'DEVICE_NOT_USABLE',
  'REGISTRY_KEY_UNRESOLVABLE',
  /** The named actor is absent from this tenant, or holds no gateway capability. */
  'ACTOR_NOT_USABLE',
  /** The site is not one this context, this actor or this device may act at. */
  'SITE_NOT_USABLE',
  /** The frozen `evaluateDeviceRequestProof` refused. Its verdict is appended verbatim. */
  'PROOF_REFUSED',
  /** The frozen `evaluateDeviceOperationPrincipals` refused. Its verdict is appended verbatim. */
  'PRINCIPALS_REFUSED',
  /** D25-02: same one-shot identity, different signed semantics. */
  'REPLAY_CONFLICT',
  /**
   * D25-02: an EXACT_DUPLICATE whose stored outcome reference cannot be proved
   * against the authoritative domain row. FAIL CLOSED, never manufacture
   * convergence.
   */
  'DUPLICATE_UNRESOLVABLE',
  /**
   * The domain service ran and did not produce the effect the gateway was
   * about to attest to. The whole transaction is rolled back rather than
   * recording an outcome nobody can prove.
   */
  'DOMAIN_EFFECT_NOT_AUTHORITATIVE',
  /** The domain service refused, under its own rules and its own exception. */
  'DOMAIN_EFFECT_REFUSED',
  /** The establishment challenge is absent, foreign, spent or past its ceiling. */
  'ESTABLISHMENT_NOT_USABLE',
  /** No current human session with gateway-capable authority stood behind the request. */
  'ESTABLISHMENT_NOT_PERMITTED',
  /** The one-context-per-ceremony database constraint spoke. */
  'ESTABLISHMENT_ALREADY_ISSUED',
  /**
   * C17-02: the tenant the PROOF claimed is not the tenant of the persisted
   * challenge or context the AUTHENTICATED SESSION resolved.
   *
   * The claimed organisation may appear in this internal reason. It may NEVER
   * select which tenant owns an audit row — the session's organisation does
   * that until a server-owned row resolves, and the row's own persisted
   * organisation does it afterwards.
   */
  'PROOF_ORGANISATION_MISMATCH',
  /**
   * C17-01: a valid possession proof presented under a DIFFERENT authenticated
   * human than the one the challenge or context is bound to.
   *
   * This is the refusal that makes the two principals two. A perfect signature
   * over a perfect statement, carried by a live session belonging to somebody
   * else, is not a weaker request — it is a request by a person who was never
   * granted this context.
   */
  'SESSION_ACTOR_MISMATCH',
] as const;
export type DeviceGatewayRefusal = (typeof DEVICE_GATEWAY_REFUSALS)[number];

/**
 * WHAT THE CALLER IS TOLD. Three values, and no more.
 *
 * `DEVICE_REQUEST_REFUSED` is the D25-13 answer: every resolution failure,
 * every contract refusal and every authority failure collapse into it, so a
 * caller cannot use the boundary to discover which devices, contexts, actors
 * or sites exist. `DEVICE_REQUEST_MALFORMED` is a SHAPE complaint about the
 * caller's own bytes and reveals nothing about server state.
 * `DEVICE_REQUEST_CONFLICT` is reachable ONLY by a caller that has already
 * spent a one-shot identity under a valid signature — it is a statement about
 * the caller's own nonce, not about anything the caller could otherwise
 * enumerate.
 */
export type DeviceGatewayExternalRefusal = 'DEVICE_REQUEST_REFUSED' | 'DEVICE_REQUEST_MALFORMED' | 'DEVICE_REQUEST_CONFLICT';

/**
 * The internal refusal, with whatever the frozen evaluator said, kept together.
 *
 * `contractRefusal` exists so an operator reading the audit sees
 * `PROOF_REFUSED / POSSESSION_NOT_PROVEN` rather than a gateway paraphrase of
 * a contract verdict. Paraphrasing a security decision is how two vocabularies
 * drift into disagreement.
 */
export interface DeviceGatewayRefusalDetail {
  readonly refusal: DeviceGatewayRefusal;
  readonly contractRefusal: DeviceRequestProofRefusal | DevicePrincipalRefusal | null;
}

/** What a device-authenticated operation can end as. */
export type DeviceGatewayOperationResult =
  | {
      readonly outcome: 'COMMITTED';
      readonly operationKind: DeviceGatewayOperationKind;
      readonly targetType: DeviceGatewayTargetType;
      readonly targetId: string;
      readonly contextId: string;
      /** The authoritative view the DOMAIN returned. The gateway reinterprets nothing. */
      readonly view: unknown;
    }
  | {
      readonly outcome: 'CONVERGED';
      readonly operationKind: DeviceGatewayOperationKind;
      readonly targetType: DeviceGatewayTargetType;
      readonly targetId: string;
      readonly contextId: string;
      readonly view: unknown;
    }
  | { readonly outcome: 'CONFLICT' }
  | { readonly outcome: 'REFUSED' };

/**
 * WP-25/C17-01 — THE FIVE FACTS, NAMED SEPARATELY, BECAUSE THEY ARE FIVE.
 *
 * The defect this shape exists to make unrepresentable was one boolean doing
 * two jobs: `userAuthenticated` was fed from "a matching user row exists and
 * their roles resolve", which is CURRENT AUTHORISATION and says nothing at all
 * about whether THIS HTTP request came from that human. A device holding a
 * stolen context and a registered key satisfied it every time.
 *
 *   sessionAuthenticated      THIS REQUEST carries the authenticated human
 *                             principal the global guard chain attached. It is
 *                             the only fact that answers "who is calling?", and
 *                             nothing else in this module may be substituted
 *                             for it.
 *   actorCurrentlyAuthorised  the live user/role re-read says that person still
 *                             exists in this tenant and still holds the
 *                             capability THIS operation requires. Authorisation
 *                             NOW — a different question, asked separately.
 *   deviceAuthenticated       possession was PROVEN against the registered key
 *                             AND the credential is intact. Which hardware.
 *   deviceCurrentlyTrusted    the registry's CURRENT effective standing, never
 *                             the context's issuance-time snapshot.
 *   siteAuthorityGranted      BOTH halves: the human currently works the site
 *                             and the device is currently deployed at it.
 *
 * None substitutes for another, and the compiler now says so: a caller cannot
 * satisfy `sessionAuthenticated` by passing the value it computed for
 * `actorCurrentlyAuthorised` without writing that substitution out by hand.
 */
export interface DeviceGatewayPrincipalFacts {
  readonly sessionAuthenticated: boolean;
  readonly actorCurrentlyAuthorised: boolean;
  readonly deviceAuthenticated: boolean;
  readonly deviceCurrentlyTrusted: DeviceTrust;
  readonly siteAuthorityGranted: boolean;
}

/** What the establishment ceremony can end as. */
export type DeviceContextEstablishmentResult =
  | {
      readonly outcome: 'ISSUED';
      /**
       * The ISSUED context — server state, a scope statement, and NOT a
       * credential (D25-01). It is safe to hand back precisely because holding
       * it authorises nothing: every effect-causing request that names it must
       * still carry a fresh hardware-signed possession proof.
       */
      readonly context: unknown;
    }
  | {
      /**
       * C17-03: an EXACT RETRY of a ceremony that already succeeded, answered
       * with the context that ALREADY EXISTS.
       *
       * The lost-response case is not an attack and must not be answered like
       * one: the server issued a context, the response never arrived, and the
       * device re-sent the byte-identical signed request. Telling that retry
       * `ESTABLISHMENT_NOT_USABLE` is Sentinel lying about a ceremony that
       * succeeded. The context here is READ BACK from the committed row — same
       * id, same `issued_at`, same `expires_at`. No second context, no extended
       * window, and no authority that the first issuance did not already grant.
       */
      readonly outcome: 'CONVERGED';
      readonly context: unknown;
    }
  | { readonly outcome: 'REFUSED' };
