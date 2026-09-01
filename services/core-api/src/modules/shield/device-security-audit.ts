import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { DeviceSecurityEventType } from './shield.constants';

/**
 * WP-24/D24-12 — THE APPEND-ONLY DEVICE SECURITY AUDIT.
 *
 * TWO PROPERTIES, AND BOTH ARE STRUCTURAL RATHER THAN PROMISED.
 *
 * 1. THE PAYLOAD IS AN ALLOWLIST, NOT A FILTER.
 *
 *    Every event type below is built by its OWN function returning its OWN
 *    object literal. There is no `{ ...input }`, no `pick(input, keys)`, no
 *    generic redactor and no shared "safe fields" helper — because all four of
 *    those are filters, and a filter fails OPEN the moment somebody adds a
 *    field to the input type. A field that is not written out by hand in the
 *    builder below cannot reach a security event at all, whatever a caller
 *    passes and whatever an input interface grows next year.
 *
 *    Never recorded, per D24-12: private key material (no such field exists
 *    anywhere in this module or in WP-23's contracts), the raw bootstrap token
 *    (see `device-enrollment.service.ts` — it exists only in transit and only
 *    as a digest in the database), a raw possession response or its nonce, a
 *    raw attestation vendor blob (the contract has nowhere to put one), a
 *    signature, or any authentication/session credential. What IS recorded is
 *    fingerprints, digests, key ids, request ids, reason codes and state names
 *    — enough to reconstruct WHAT the platform decided without carrying
 *    anything an attacker could use.
 *
 *    Nonces are deliberately absent even though they are "just identifiers":
 *    a possession or rotation nonce is a live secret for the length of its
 *    challenge window, and an audit stream is read by more people than the
 *    ceremony is.
 *
 * 2. THERE IS NO UPDATE AND NO DELETE.
 *
 *    This class exposes exactly one write, `record`, and it only ever calls
 *    `create`. `DeviceSecurityEvent`, `DeviceTrustTransition` and
 *    `DeviceAttestationObservation` have no mutation path anywhere in the
 *    module, and `test/shield-append-only.architecture.spec.ts` scans the
 *    source for one rather than trusting review to notice a future edit — the
 *    same discipline as the Whisper boundary guard.
 */

/**
 * The JSON a security-event payload may contain.
 *
 * Scalars only, deliberately. A nested object is where a raw blob hides: the
 * moment a payload can carry a structure, "just this one vendor response" is a
 * one-line change nobody reads twice. Everything D24-12 permits — a digest, an
 * id, a version, a reason code, a state name, a boolean verdict — is a scalar.
 */
export type DeviceSecurityEventPayload = Readonly<Record<string, string | number | boolean | null>>;

/**
 * The typed input for each event, as a discriminated union.
 *
 * The union is what makes the allowlist checkable: `buildDeviceSecurityEventPayload`
 * switches on `type` and TypeScript proves every member has an arm, so an
 * eighteenth-plus-one event type added to `DEVICE_SECURITY_EVENT_TYPES` without
 * a builder fails to compile rather than silently writing `{}`.
 */
export type DeviceSecurityEventInput =
  | {
      readonly type: 'BOOTSTRAP_ISSUED';
      readonly grantId: string;
      readonly siteId: string;
      readonly intendedUserId: string;
      readonly issuedByUserId: string;
      readonly expiresAt: string;
    }
  | {
      readonly type: 'BOOTSTRAP_REVOKED';
      readonly grantId: string;
      readonly siteId: string;
      readonly revokedByUserId: string;
    }
  | {
      readonly type: 'BOOTSTRAP_CONSUMED';
      readonly grantId: string;
      readonly siteId: string;
      readonly intendedUserId: string;
      readonly enrollmentRequestId: string;
      readonly enrollmentRequestFingerprint: string;
    }
  | {
      /**
       * D24-03a: a grant presented in an unexpected organisation, site or user
       * context. The PRESENTED scope is recorded because that is the probe;
       * the token that was presented is not, and there is no field for it.
       */
      readonly type: 'BOOTSTRAP_REPLAY_REFUSED';
      readonly grantId: string;
      readonly refusal: string;
      readonly presentedOrganisationId: string;
      readonly presentedSiteId: string;
      readonly presentedIntendedUserId: string;
    }
  | {
      readonly type: 'ENROLLMENT_REQUESTED';
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string;
      readonly siteId: string;
      readonly intendedUserId: string;
      readonly custody: string;
      readonly keyStorage: string;
      readonly publicKeyThumbprint: string;
      readonly signatureProfile: string;
      readonly attestationOutcome: string;
    }
  | {
      readonly type: 'ENROLLMENT_APPROVED';
      readonly enrollmentRequestId: string;
      readonly approvedRequestFingerprint: string;
      readonly approvedByUserId: string;
      readonly siteId: string;
      readonly custody: string;
    }
  | {
      readonly type: 'ENROLLMENT_REFUSED';
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string | null;
      readonly refusal: string;
    }
  | {
      readonly type: 'POSSESSION_VERIFIED';
      readonly enrollmentRequestId: string;
      readonly challengeId: string;
      readonly publicKeyThumbprint: string;
      readonly possessionStatementFingerprint: string;
      readonly signatureProfile: string;
      /** `false` is a real, recordable verdict (C15-03). It is not an omission. */
      readonly verified: boolean;
    }
  | {
      readonly type: 'DEVICE_ENROLLED';
      readonly deviceId: string;
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string;
      readonly siteId: string;
      readonly custody: string;
      readonly sequenceNamespaceId: string;
      readonly keyId: string;
      readonly keyVersion: number;
      readonly publicKeyThumbprint: string;
      readonly keyStorage: string;
      readonly signatureProfile: string;
      readonly initialTrust: string;
    }
  | {
      readonly type: 'TRUST_CHANGED';
      readonly previousTrust: string;
      readonly newTrust: string;
      readonly reason: string;
      readonly authorisedByUserId: string | null;
    }
  | {
      readonly type: 'DEVICE_QUARANTINED';
      readonly previousTrust: string;
      readonly reason: string;
    }
  | {
      readonly type: 'DEVICE_LOST';
      readonly previousTrust: string;
      readonly newTrust: string;
      readonly disposition: string;
    }
  | {
      readonly type: 'DEVICE_STOLEN';
      readonly previousTrust: string;
      readonly newTrust: string;
      readonly disposition: string;
      readonly keyId: string;
      readonly keyVersion: number;
    }
  | {
      readonly type: 'DEVICE_REVOKED';
      readonly disposition: string;
      readonly previousTrust: string;
      readonly newTrust: string;
      readonly revokedAt: string;
    }
  | {
      readonly type: 'KEY_ROTATED';
      readonly rotationRequestId: string;
      readonly rotationRequestFingerprint: string;
      readonly fromKeyId: string;
      readonly fromKeyVersion: number;
      readonly toKeyId: string;
      readonly toKeyVersion: number;
      readonly newPublicKeyThumbprint: string;
      readonly newKeyStorage: string;
      readonly signatureProfile: string;
    }
  | {
      readonly type: 'KEY_REVOKED';
      readonly keyId: string;
      readonly keyVersion: number;
      readonly disposition: string;
    }
  | {
      readonly type: 'KEY_COMPROMISED';
      readonly keyId: string;
      readonly keyVersion: number;
      readonly disposition: string;
    }
  | {
      readonly type: 'REPLAY_CONFLICT';
      readonly ceremony: string;
      readonly replayIdentityDigest: string;
      readonly presentedStatementFingerprint: string;
      readonly outcome: string;
    };

/**
 * D24-12's allowlist, one hand-written literal per event type.
 *
 * Read this function as the definitive answer to "what can a device security
 * event contain?". Every property that appears in the output appears here,
 * spelled out, next to the type it belongs to. That verbosity is the feature:
 * a reviewer can audit the whole disclosure surface of the module by reading
 * one switch, and a widening is a visible diff on a specific line rather than
 * a new field quietly riding an object spread.
 *
 * Exported separately from the writer so it can be unit-tested without a
 * database — the property under test is what the payload CONTAINS, and that is
 * a pure question.
 */
export function buildDeviceSecurityEventPayload(input: DeviceSecurityEventInput): DeviceSecurityEventPayload {
  switch (input.type) {
    case 'BOOTSTRAP_ISSUED':
      return {
        grant_id: input.grantId,
        site_id: input.siteId,
        intended_user_id: input.intendedUserId,
        issued_by_user_id: input.issuedByUserId,
        expires_at: input.expiresAt,
      };
    case 'BOOTSTRAP_REVOKED':
      return {
        grant_id: input.grantId,
        site_id: input.siteId,
        revoked_by_user_id: input.revokedByUserId,
      };
    case 'BOOTSTRAP_CONSUMED':
      return {
        grant_id: input.grantId,
        site_id: input.siteId,
        intended_user_id: input.intendedUserId,
        enrollment_request_id: input.enrollmentRequestId,
        enrollment_request_fingerprint: input.enrollmentRequestFingerprint,
      };
    case 'BOOTSTRAP_REPLAY_REFUSED':
      return {
        grant_id: input.grantId,
        refusal: input.refusal,
        presented_organisation_id: input.presentedOrganisationId,
        presented_site_id: input.presentedSiteId,
        presented_intended_user_id: input.presentedIntendedUserId,
      };
    case 'ENROLLMENT_REQUESTED':
      return {
        enrollment_request_id: input.enrollmentRequestId,
        request_fingerprint: input.requestFingerprint,
        site_id: input.siteId,
        intended_user_id: input.intendedUserId,
        custody: input.custody,
        key_storage: input.keyStorage,
        public_key_thumbprint: input.publicKeyThumbprint,
        signature_profile: input.signatureProfile,
        attestation_outcome: input.attestationOutcome,
      };
    case 'ENROLLMENT_APPROVED':
      return {
        enrollment_request_id: input.enrollmentRequestId,
        approved_request_fingerprint: input.approvedRequestFingerprint,
        approved_by_user_id: input.approvedByUserId,
        site_id: input.siteId,
        custody: input.custody,
      };
    case 'ENROLLMENT_REFUSED':
      return {
        enrollment_request_id: input.enrollmentRequestId,
        request_fingerprint: input.requestFingerprint,
        refusal: input.refusal,
      };
    case 'POSSESSION_VERIFIED':
      return {
        enrollment_request_id: input.enrollmentRequestId,
        challenge_id: input.challengeId,
        public_key_thumbprint: input.publicKeyThumbprint,
        possession_statement_fingerprint: input.possessionStatementFingerprint,
        signature_profile: input.signatureProfile,
        verified: input.verified,
      };
    case 'DEVICE_ENROLLED':
      return {
        device_id: input.deviceId,
        enrollment_request_id: input.enrollmentRequestId,
        request_fingerprint: input.requestFingerprint,
        site_id: input.siteId,
        custody: input.custody,
        sequence_namespace_id: input.sequenceNamespaceId,
        key_id: input.keyId,
        key_version: input.keyVersion,
        public_key_thumbprint: input.publicKeyThumbprint,
        key_storage: input.keyStorage,
        signature_profile: input.signatureProfile,
        initial_trust: input.initialTrust,
      };
    case 'TRUST_CHANGED':
      return {
        previous_trust: input.previousTrust,
        new_trust: input.newTrust,
        reason: input.reason,
        authorised_by_user_id: input.authorisedByUserId,
      };
    case 'DEVICE_QUARANTINED':
      return {
        previous_trust: input.previousTrust,
        reason: input.reason,
      };
    case 'DEVICE_LOST':
      return {
        previous_trust: input.previousTrust,
        new_trust: input.newTrust,
        disposition: input.disposition,
      };
    case 'DEVICE_STOLEN':
      return {
        previous_trust: input.previousTrust,
        new_trust: input.newTrust,
        disposition: input.disposition,
        key_id: input.keyId,
        key_version: input.keyVersion,
      };
    case 'DEVICE_REVOKED':
      return {
        disposition: input.disposition,
        previous_trust: input.previousTrust,
        new_trust: input.newTrust,
        revoked_at: input.revokedAt,
      };
    case 'KEY_ROTATED':
      return {
        rotation_request_id: input.rotationRequestId,
        rotation_request_fingerprint: input.rotationRequestFingerprint,
        from_key_id: input.fromKeyId,
        from_key_version: input.fromKeyVersion,
        to_key_id: input.toKeyId,
        to_key_version: input.toKeyVersion,
        new_public_key_thumbprint: input.newPublicKeyThumbprint,
        new_key_storage: input.newKeyStorage,
        signature_profile: input.signatureProfile,
      };
    case 'KEY_REVOKED':
      return {
        key_id: input.keyId,
        key_version: input.keyVersion,
        disposition: input.disposition,
      };
    case 'KEY_COMPROMISED':
      return {
        key_id: input.keyId,
        key_version: input.keyVersion,
        disposition: input.disposition,
      };
    case 'REPLAY_CONFLICT':
      return {
        ceremony: input.ceremony,
        replay_identity_digest: input.replayIdentityDigest,
        presented_statement_fingerprint: input.presentedStatementFingerprint,
        outcome: input.outcome,
      };
  }
}

/** The row envelope: who, where and when, held as COLUMNS rather than payload. */
export interface DeviceSecurityEventEnvelope {
  readonly organisationId: string;
  /** `null` before a device identity exists — every pre-commit event (D24-03). */
  readonly deviceId: string | null;
  /** The AUTHENTICATED human, or `null` for a server-initiated observation. */
  readonly actorUserId: string | null;
  readonly occurredAt: Date;
  readonly traceId: string;
}

/**
 * The single writer. `create` and nothing else, ever.
 *
 * It takes a transaction client rather than opening its own, because a
 * security event about a decision must commit or roll back WITH that decision.
 * An audit row that survives a rolled-back commit is a record of something
 * that did not happen; one that is lost when the commit succeeds is worse.
 */
@Injectable()
export class DeviceSecurityAudit {
  async record(
    tx: Prisma.TransactionClient,
    envelope: DeviceSecurityEventEnvelope,
    input: DeviceSecurityEventInput,
  ): Promise<void> {
    const eventType: DeviceSecurityEventType = input.type;
    await tx.deviceSecurityEvent.create({
      data: {
        organisationId: envelope.organisationId,
        deviceId: envelope.deviceId,
        eventType,
        actorUserId: envelope.actorUserId,
        // The single JSON boundary in this module. The value crossing it was
        // built by the allowlist above and by nothing else.
        payload: buildDeviceSecurityEventPayload(input) as Prisma.InputJsonObject,
        occurredAt: envelope.occurredAt,
        traceId: envelope.traceId,
      },
    });
  }
}
