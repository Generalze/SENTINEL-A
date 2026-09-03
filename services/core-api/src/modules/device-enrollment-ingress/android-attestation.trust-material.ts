import { Injectable } from '@nestjs/common';
import { X509Certificate } from 'node:crypto';
import { ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS } from './device-enrollment-ingress.constants';

/**
 * ============================================================================
 * WP-26/D26-04B — THE TRUST MATERIAL SEAM.
 *
 * THE ONE RULE THIS FILE EXISTS TO MAKE STRUCTURAL
 * ------------------------------------------------
 *
 *     TRUST ANCHORS ARE SERVER CONFIGURATION.
 *     A ROOT IS NEVER TRUSTED BECAUSE THE DEVICE SUPPLIED IT.
 *
 * An attestation chain arrives from the thing being attested. If the verifier
 * took its anchor from that chain, every device could mint its own root and
 * every verdict would be the device's own opinion of itself. So the anchors
 * come from HERE, they are versioned, and the verifier compares — it never
 * discovers.
 *
 * AND THE SECOND RULE, WHICH IS C14-05 APPLIED TO TRUST MATERIAL
 * --------------------------------------------------------------
 *
 *     revocation data unavailable or stale  -> UNAVAILABLE
 *     provider / network outage             -> UNAVAILABLE
 *     never "assume not revoked"
 *     never VERIFIED from stale or absent evidence
 *
 * That is why this seam returns a SNAPSHOT with a `fetchedAt` and a version
 * rather than a bare list. A list with no freshness attached cannot answer "do
 * we still know this?", and a verifier that cannot answer that question has no
 * honest way to say VERIFIED.
 *
 * NO BACKGROUND SCHEDULER (D25-08, still binding). `current()` is called at
 * REQUEST TIME. A production implementation may serve an explicitly refreshed
 * bounded cache from it; what it may not do is start a timer, a job or a
 * sweeper. WP-24's live suite already contends over one shared Postgres and
 * this module adds nothing to that.
 * ============================================================================
 */

/** One certificate revocation fact, as the snapshot records it. */
export interface AndroidCertificateRevocationEntry {
  /** Google's status list uses `REVOKED` and `SUSPENDED`. Both withdraw trust. */
  readonly status: string;
  readonly reason: string | null;
}

/**
 * Everything the verifier needs from server configuration, at one instant.
 *
 * `configured: false` is a FIRST-CLASS ANSWER, not an error. A deployment that
 * has not been given trust material is in exactly the epistemic position of a
 * provider outage: it has not looked, so it cannot say. The verifier turns that
 * into `UNAVAILABLE`, which is neither positive nor negative device evidence —
 * and, per `initialDeviceTrustOnEnrollment`, means a device enrolled in that
 * deployment operates every ordinary path at `DEGRADED` and simply cannot be
 * TRUSTED. That is the correct posture and it required no policy to be written
 * here.
 */
export type AndroidAttestationTrustMaterial =
  | {
      readonly configured: false;
      /** Why, for the artifact record. Never returned to a caller. */
      readonly reason: string;
      readonly trustAnchorSetVersion: string;
      readonly revocationSnapshotVersion: string;
    }
  | {
      readonly configured: true;
      /** The PINNED roots. Order is irrelevant; membership is everything. */
      readonly anchors: readonly X509Certificate[];
      readonly trustAnchorSetVersion: string;
      /**
       * Serial number (lowercase hex, no leading zeros) -> revocation entry.
       * Absence from this map means "not revoked ACCORDING TO A SNAPSHOT WE
       * STILL TRUST", which is only meaningful together with `fetchedAt`.
       */
      readonly revocations: ReadonlyMap<string, AndroidCertificateRevocationEntry>;
      readonly revocationSnapshotVersion: string;
      /** When the revocation snapshot was obtained. Freshness is checked, not assumed. */
      readonly revocationFetchedAt: Date;
      /**
       * The Sentinel Android application identity the leaf must attest to.
       * Server configuration for the same reason the anchors are: an app
       * identity a device could choose is not an app identity.
       */
      readonly expectedPackageName: string;
      /** Lowercase hex SHA-256 signing-certificate digests. Any one may match. */
      readonly expectedSigningDigests: readonly string[];
    };

/** The Nest injection token. An interface has no runtime identity. */
export const ANDROID_ATTESTATION_TRUST_MATERIAL = Symbol('ANDROID_ATTESTATION_TRUST_MATERIAL');

export interface AndroidAttestationTrustMaterialProvider {
  /**
   * The trust material AS IT STANDS NOW.
   *
   * It takes the authoritative server instant rather than reading a clock, for
   * the reason `DeviceAttestationEvaluator.evaluate` does: a freshness decision
   * taken against a second clock could disagree with the instant the evaluation
   * was recorded at.
   *
   * An implementation must never throw to mean "no answer". An unreachable
   * provider returns `configured: false` with a reason, which is a real value
   * with defined meaning; a throw would leave the verifier unable to tell an
   * outage from a defect, and the two have opposite trust consequences.
   */
  current(now: Date): Promise<AndroidAttestationTrustMaterial>;
}

/**
 * D26-04B: the DEFAULT, and the only implementation this work package ships.
 *
 * IT PINS NOTHING, AND SAYS SO.
 *
 * There are two real Google hardware-attestation roots in the world, including
 * a newer one signing chains from 2026-02-01, and a third-party engineer
 * writing them out from memory is exactly how a wrong root gets pinned into a
 * security-critical path and nobody notices until it matters. Sentinel's
 * standing rule on this path is WP-24's: NEVER MANUFACTURE EVIDENCE. So the
 * shipped default declares itself unconfigured, the verifier returns
 * `UNAVAILABLE`, and no device can reach `TRUSTED` on trust material nobody
 * supplied.
 *
 * WIRING THE REAL ROOTS IS A DEPLOYMENT ACT, and it is one of the things
 * D26-10's PHYSICAL DEVICE ACCEPTANCE has to demonstrate — against a genuine
 * StrongBox device, with the real Google roots and a real revocation snapshot
 * in front of a real chain. A synthetic chain in a test suite proves the
 * verifier's LOGIC; it cannot and does not prove the trust material.
 */
@Injectable()
export class UnconfiguredAndroidAttestationTrustMaterial implements AndroidAttestationTrustMaterialProvider {
  async current(_now: Date): Promise<AndroidAttestationTrustMaterial> {
    return {
      configured: false,
      reason: 'TRUST_MATERIAL_NOT_CONFIGURED',
      trustAnchorSetVersion: UNCONFIGURED_VERSION,
      revocationSnapshotVersion: UNCONFIGURED_VERSION,
    };
  }
}

/**
 * The version string recorded on an artifact evaluated with no trust material.
 *
 * It is a NAMED value rather than an empty string so that a row in
 * `android_key_attestation_artifacts` says plainly what the server knew when it
 * answered, and a reviewer never has to guess whether a blank column means
 * "unconfigured" or "not written".
 */
export const UNCONFIGURED_VERSION = 'UNCONFIGURED';

/**
 * Is this revocation snapshot still usable at `now`?
 *
 * Exclusive boundary, matching every other freshness bound in WP-23..WP-26. A
 * snapshot whose age has reached the ceiling is STALE, and stale is
 * `UNAVAILABLE` — never "assume not revoked". A `fetchedAt` in the FUTURE is
 * also refused: it does not describe a possible history, which is the same
 * fail-closed reading C15-07 gives an impossible attestation timeline.
 */
export function revocationSnapshotIsFresh(fetchedAt: Date, now: Date): boolean {
  const age = now.getTime() - fetchedAt.getTime();
  if (!Number.isFinite(age)) return false;
  if (age < 0) return false;
  return age < ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS;
}

/**
 * A certificate's serial number in the ONE form the revocation map is keyed by.
 *
 * `X509Certificate.serialNumber` is uppercase hex with no separator and may
 * carry leading zeros depending on the encoding; Google's status list is
 * lowercase and unpadded. Normalising in ONE function is the difference between
 * a revocation check that works and one that silently never matches — which
 * would be a check that fails OPEN, the single worst outcome available here.
 */
export function normaliseCertificateSerial(serialNumber: string): string {
  const lowered = serialNumber.trim().toLowerCase().replace(/^0x/u, '');
  const unpadded = lowered.replace(/^0+/u, '');
  return unpadded.length === 0 ? '0' : unpadded;
}
