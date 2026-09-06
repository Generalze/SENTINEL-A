import type { EdgeRegistryKeyRecord } from '@sentinel/contracts';

/**
 * Every way the Edge ceremony can refuse.
 *
 * INTERNAL VOCABULARY ONLY. These names are for the audit trail and for this
 * module's own tests; the transport surface collapses them to one flat external
 * string, following `CommandEnrollmentController`'s doctrine — a caller able to
 * tell "no such authority" from "wrong site" from "already consumed" holds an
 * oracle over the estate's enrolment state.
 */
export type EdgeRefusalCode =
  | 'NOT_AUTHORISED'
  | 'ORGANISATION_NOT_FOUND'
  | 'SITE_NOT_FOUND'
  | 'SITE_NOT_IN_ORGANISATION'
  | 'AUTHORITY_NOT_FOUND'
  | 'AUTHORITY_SITE_MISMATCH'
  | 'AUTHORITY_NOT_USABLE'
  | 'AUTHORITY_ALREADY_CONSUMED'
  | 'PUBLIC_KEY_NOT_RUNTIME_VALID'
  | 'ENROLMENT_REQUEST_NOT_FOUND'
  | 'ENROLMENT_STATE_INVALID'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_MISBOUND'
  | 'POSSESSION_NOT_VERIFIED'
  | 'POSSESSION_KEY_MISMATCH'
  | 'EDGE_NOT_FOUND'
  | 'EDGE_STATE_INVALID'
  | 'REPLAY_CONFLICT'
  | 'REPLAY_FACT_INCONSISTENT'
  | 'TIME_NOT_AUTHORITATIVE';

export type IssueEdgeAuthorityOutcome =
  | {
      readonly outcome: 'ISSUED';
      readonly authorityId: string;
      /**
       * IN TRANSIT ONLY, and only to this caller. Nothing persisted holds it
       * and nothing in this module can be asked for it again.
       */
      readonly secret: string;
      readonly siteId: string;
      readonly expiresAt: Date;
    }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeRefusalCode };

export type RequestEdgeEnrolmentOutcome =
  | {
      readonly outcome: 'REQUESTED';
      readonly enrolmentRequestId: string;
      readonly edgeId: string;
      /** SERVER-resolved from the authority. The Edge learns where it belongs. */
      readonly siteId: string;
      readonly organisationId: string;
    }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeRefusalCode };

export type IssueEdgeChallengeOutcome =
  | { readonly outcome: 'ISSUED'; readonly challengeId: string; readonly nonce: string; readonly expiresAt: Date }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeRefusalCode };

export type CompleteEdgeEnrolmentOutcome =
  | {
      readonly outcome: 'ENROLLED';
      readonly edgeId: string;
      readonly edgeKeyId: string;
      readonly edgeKeyVersion: number;
    }
  /** An exact retry of a ceremony that already completed. NO second identity. */
  | { readonly outcome: 'CONVERGED'; readonly edgeId: string }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeRefusalCode };

export type WithdrawEdgeOutcome =
  | { readonly outcome: 'WITHDRAWN'; readonly edgeId: string }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeRefusalCode };

/** What the offline evaluator is handed, or `null` when nothing resolves. */
export type ResolvedEdgeRegistryKey = EdgeRegistryKeyRecord | null;
