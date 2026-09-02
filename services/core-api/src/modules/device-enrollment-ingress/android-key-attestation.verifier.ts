import { Inject, Injectable } from '@nestjs/common';
import { X509Certificate, createHash, timingSafeEqual } from 'node:crypto';
import type { DeviceAttestationOutcome } from '@sentinel/contracts';
import {
  ANDROID_EC_CURVE_P256,
  ANDROID_KEY_ALGORITHM_EC,
  ANDROID_KEY_ATTESTATION_VERIFIER_VERSION,
  ANDROID_KEY_ORIGIN_GENERATED,
  ANDROID_KEY_PURPOSE_SIGN,
  ANDROID_KEY_PURPOSE_VERIFY,
  ANDROID_KEY_SIZE_P256,
  ANDROID_SECURITY_LEVEL_STRONGBOX,
  ANDROID_VERIFIED_BOOT_STATE_VERIFIED,
  MAX_ATTESTATION_CERTIFICATE_BASE64_LENGTH,
  MAX_ATTESTATION_CHAIN_LENGTH,
} from './device-enrollment-ingress.constants';
import {
  ANDROID_KEY_ATTESTATION_EXTENSION_OID,
  findCertificateExtension,
  parseAndroidKeyDescription,
  type AndroidKeyDescription,
} from './android-attestation.der';
import {
  ANDROID_ATTESTATION_TRUST_MATERIAL,
  normaliseCertificateSerial,
  revocationSnapshotIsFresh,
  type AndroidAttestationTrustMaterialProvider,
} from './android-attestation.trust-material';

/**
 * ============================================================================
 * WP-26/D26-04B — THE ANDROID KEY ATTESTATION VERIFIER.
 *
 * WP-24 built the attestation seam and had it return `UNAVAILABLE`, and said in
 * as many words that it was doing so "precisely until a real provider existed".
 * This is that provider, and it is the first thing in Sentinel's history that
 * can produce a positive hardware verdict. Everything about it is therefore
 * written to fail closed.
 *
 * THE VERIFIED PROFILE. ALL OF IT, OR NOT VERIFIED.
 * -------------------------------------------------
 *     chain validates to a PINNED Google root       trust anchors are SERVER
 *                                                   config; a root is never
 *                                                   trusted because the device
 *                                                   supplied one
 *     no certificate expired / not yet valid
 *     revocation CHECKED, and not revoked
 *     attestationChallenge === the exact server challenge bytes
 *     leaf public key      === the submitted P-256 public key
 *     attestationSecurityLevel AND keymasterSecurityLevel === StrongBox (2)
 *     algorithm EC / P-256, purpose SIGN, origin GENERATED
 *     the expected Sentinel Android package + signing identity
 *     acceptable verified-boot / device-lock state
 *
 * Anything short of that is NOT VERIFIED. In particular a TEE certificate —
 * security level 1 — is never promoted into the StrongBox profile. It gets its
 * own outcome and its own reason, because "this is good hardware, but not the
 * hardware WP-26's reference path requires" and "this is not hardware" are
 * different facts and an operator must be able to tell them apart (D26-03A).
 *
 * FAILURE SEMANTICS, WHICH ARE C14-05'S AND ARE FROZEN
 * ----------------------------------------------------
 *     revocation data unavailable or stale   -> UNAVAILABLE
 *     provider / trust-material outage        -> UNAVAILABLE
 *     an unexpected internal fault            -> UNAVAILABLE
 *     chain invalid / challenge mismatch /
 *       key mismatch / wrong profile          -> NEGATIVE   (device evidence)
 *     unparseable structure                   -> INVALID    (device evidence)
 *     a revoked certificate                   -> REVOKED    (device evidence)
 *
 * `UNAVAILABLE` IS NEVER NEGATIVE. A third party's downtime, or our own missing
 * configuration, must not quarantine a fleet — and it must never produce a
 * VERIFIED either. The one thing an outage is allowed to do is leave the device
 * at `DEGRADED`, which is what `initialDeviceTrustOnEnrollment` already decides
 * from an `INELIGIBLE` standing, without this file holding an opinion about it.
 *
 * THIS FILE NEVER THROWS TO MEAN "NO ANSWER". Every path returns a verdict.
 * A throw would leave a caller unable to tell an outage from a defect, and the
 * two have opposite trust consequences.
 *
 * NO BACKGROUND SCHEDULER (D25-08). The trust material is read at REQUEST TIME
 * through its injected seam. This class starts nothing.
 * ============================================================================
 */

/** The verifier's own internal reason vocabulary. Never returned to a caller. */
export type AndroidAttestationRefusalReason =
  | 'TRUST_MATERIAL_UNAVAILABLE'
  | 'REVOCATION_SNAPSHOT_STALE'
  | 'VERIFIER_FAULT'
  | 'CHAIN_EMPTY'
  | 'CHAIN_TOO_LONG'
  | 'CERTIFICATE_TOO_LARGE'
  | 'CERTIFICATE_UNPARSEABLE'
  | 'CHAIN_LINK_NOT_ISSUED_BY_NEXT'
  | 'CHAIN_SIGNATURE_INVALID'
  | 'CHAIN_NOT_ANCHORED_TO_PINNED_ROOT'
  | 'CERTIFICATE_NOT_YET_VALID'
  | 'CERTIFICATE_EXPIRED'
  | 'CERTIFICATE_REVOKED'
  | 'ATTESTATION_EXTENSION_MISSING'
  | 'ATTESTATION_EXTENSION_UNPARSEABLE'
  | 'ATTESTATION_CHALLENGE_MISMATCH'
  | 'LEAF_KEY_NOT_SUBMITTED_KEY'
  | 'SECURITY_LEVEL_NOT_STRONGBOX'
  | 'KEYMASTER_SECURITY_LEVEL_NOT_STRONGBOX'
  | 'KEY_ALGORITHM_NOT_P256_EC'
  | 'KEY_PURPOSE_NOT_SIGN'
  | 'KEY_ORIGIN_NOT_GENERATED'
  | 'ROOT_OF_TRUST_MISSING'
  | 'DEVICE_NOT_LOCKED'
  | 'VERIFIED_BOOT_STATE_UNACCEPTABLE'
  | 'APPLICATION_IDENTITY_MISSING'
  | 'APPLICATION_PACKAGE_UNEXPECTED'
  | 'APPLICATION_SIGNING_IDENTITY_UNEXPECTED';

/** The parsed claims, flattened to the scalars the artifact record stores. */
export interface AndroidAttestationClaims {
  readonly attestationVersion: number | null;
  readonly attestationSecurityLevel: number | null;
  readonly keymasterSecurityLevel: number | null;
  readonly keyPurposes: readonly number[];
  readonly keyAlgorithm: number | null;
  readonly keySize: number | null;
  readonly keyEcCurve: number | null;
  readonly keyOrigin: number | null;
  readonly noAuthRequired: boolean | null;
  readonly verifiedBootState: number | null;
  readonly deviceLocked: boolean | null;
  readonly attestationPackageName: string | null;
  readonly attestationSigningDigest: string | null;
}

const NO_CLAIMS: AndroidAttestationClaims = {
  attestationVersion: null,
  attestationSecurityLevel: null,
  keymasterSecurityLevel: null,
  keyPurposes: [],
  keyAlgorithm: null,
  keySize: null,
  keyEcCurve: null,
  keyOrigin: null,
  noAuthRequired: null,
  verifiedBootState: null,
  deviceLocked: null,
  attestationPackageName: null,
  attestationSigningDigest: null,
};

export interface AndroidAttestationVerificationInput {
  /** Base64 DER, LEAF FIRST. Exactly as submitted; never re-encoded before hashing. */
  readonly certificateChainBase64: readonly string[];
  /**
   * The SERVER's challenge value, as issued (canonical unpadded base64url). The
   * comparison is against these bytes and no others: D26-04A's entire point is
   * that the certificate must carry the value the server chose BEFORE the key
   * existed.
   */
  readonly expectedChallengeValue: string;
  /**
   * The DER SubjectPublicKeyInfo of the key the device SUBMITTED for
   * enrollment, built by the server from the canonical point it received.
   * Compared byte-for-byte with the leaf's SPKI: an attestation certificate for
   * somebody else's key proves nothing about the key being enrolled.
   */
  readonly submittedPublicKeySpkiDer: Buffer;
  /** The authoritative server clock. Passed in, never read here. */
  readonly now: Date;
}

export interface AndroidAttestationVerdict {
  readonly outcome: DeviceAttestationOutcome;
  readonly reason: AndroidAttestationRefusalReason | 'VERIFIED';
  readonly claims: AndroidAttestationClaims;
  /** SHA-256, lowercase hex, over the concatenated DER as submitted. */
  readonly certificateChainHash: string;
  readonly verifierVersion: string;
  readonly trustAnchorSetVersion: string;
  readonly revocationSnapshotVersion: string;
}

@Injectable()
export class AndroidKeyAttestationVerifier {
  constructor(
    @Inject(ANDROID_ATTESTATION_TRUST_MATERIAL)
    private readonly trustMaterial: AndroidAttestationTrustMaterialProvider,
  ) {}

  async verify(input: AndroidAttestationVerificationInput): Promise<AndroidAttestationVerdict> {
    // The chain hash is computed FIRST and unconditionally, so that even a
    // verdict reached before any parsing succeeded still names the exact bytes
    // it was reached about. An artifact that cannot name its evidence is not an
    // audit trail.
    const chainHash = hashChain(input.certificateChainBase64);

    let material;
    try {
      material = await this.trustMaterial.current(input.now);
    } catch {
      // The seam's contract forbids throwing, and a provider that throws anyway
      // is an OUTAGE, not a statement about a device. Never NEGATIVE.
      return unavailable('TRUST_MATERIAL_UNAVAILABLE', chainHash, 'UNKNOWN', 'UNKNOWN');
    }

    if (!material.configured) {
      return unavailable(
        'TRUST_MATERIAL_UNAVAILABLE',
        chainHash,
        material.trustAnchorSetVersion,
        material.revocationSnapshotVersion,
      );
    }

    const versions = {
      trustAnchorSetVersion: material.trustAnchorSetVersion,
      revocationSnapshotVersion: material.revocationSnapshotVersion,
    };

    // FRESHNESS BEFORE ANYTHING ELSE THAT COULD PRODUCE A POSITIVE.
    //
    // A stale snapshot cannot support "not revoked", and "not revoked" is a
    // required conjunct of VERIFIED. Checking it here rather than at the
    // revocation step means there is no ordering in which an otherwise perfect
    // chain reaches VERIFIED past a snapshot nobody could vouch for.
    if (!revocationSnapshotIsFresh(material.revocationFetchedAt, input.now)) {
      return unavailable('REVOCATION_SNAPSHOT_STALE', chainHash, versions.trustAnchorSetVersion, versions.revocationSnapshotVersion);
    }

    try {
      return this.evaluateChain(input, material, chainHash, versions);
    } catch {
      // Defence in depth. Nothing below is expected to throw — every helper
      // returns a verdict — but a fault in OUR code is not evidence about a
      // device, so it collapses to UNAVAILABLE rather than to NEGATIVE.
      return unavailable('VERIFIER_FAULT', chainHash, versions.trustAnchorSetVersion, versions.revocationSnapshotVersion);
    }
  }

  private evaluateChain(
    input: AndroidAttestationVerificationInput,
    material: Extract<Awaited<ReturnType<AndroidAttestationTrustMaterialProvider['current']>>, { configured: true }>,
    chainHash: string,
    versions: { trustAnchorSetVersion: string; revocationSnapshotVersion: string },
  ): AndroidAttestationVerdict {
    const refuse = (
      outcome: DeviceAttestationOutcome,
      reason: AndroidAttestationRefusalReason,
      claims: AndroidAttestationClaims = NO_CLAIMS,
    ): AndroidAttestationVerdict => ({
      outcome,
      reason,
      claims,
      certificateChainHash: chainHash,
      verifierVersion: ANDROID_KEY_ATTESTATION_VERIFIER_VERSION,
      ...versions,
    });

    // ---- 0. bounds ------------------------------------------------------
    if (input.certificateChainBase64.length === 0) return refuse('INVALID', 'CHAIN_EMPTY');
    if (input.certificateChainBase64.length > MAX_ATTESTATION_CHAIN_LENGTH) return refuse('INVALID', 'CHAIN_TOO_LONG');
    for (const encoded of input.certificateChainBase64) {
      if (encoded.length > MAX_ATTESTATION_CERTIFICATE_BASE64_LENGTH) return refuse('INVALID', 'CERTIFICATE_TOO_LARGE');
    }

    // ---- 1. parse -------------------------------------------------------
    const chain: X509Certificate[] = [];
    const chainDer: Buffer[] = [];
    for (const encoded of input.certificateChainBase64) {
      const der = decodeStrictBase64(encoded);
      if (der === null) return refuse('INVALID', 'CERTIFICATE_UNPARSEABLE');
      let certificate: X509Certificate;
      try {
        certificate = new X509Certificate(der);
      } catch {
        return refuse('INVALID', 'CERTIFICATE_UNPARSEABLE');
      }
      chain.push(certificate);
      chainDer.push(der);
    }

    // ---- 2. validity window --------------------------------------------
    // Checked for every certificate INCLUDING the leaf, before any signature is
    // trusted. `validTo` is exclusive here, matching the boundary doctrine every
    // other expiry in WP-23..WP-26 uses; an X.509 `notAfter` is nominally
    // inclusive, and taking the stricter reading costs one second and removes an
    // edge nobody would test.
    for (const certificate of chain) {
      const notBefore = new Date(certificate.validFrom).getTime();
      const notAfter = new Date(certificate.validTo).getTime();
      if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) return refuse('INVALID', 'CERTIFICATE_UNPARSEABLE');
      if (input.now.getTime() < notBefore) return refuse('NEGATIVE', 'CERTIFICATE_NOT_YET_VALID');
      if (input.now.getTime() >= notAfter) return refuse('NEGATIVE', 'CERTIFICATE_EXPIRED');
    }

    // ---- 3. the chain links --------------------------------------------
    // Each certificate must be issued by, and signed by, the next one along.
    // `checkIssued` compares the names and the authority key identifier;
    // `verify` is the cryptography. Both, because a name match without a
    // signature is nothing and a signature without a name match is a chain
    // assembled by whoever submitted it.
    for (let index = 0; index + 1 < chain.length; index += 1) {
      const subject = chain[index] as X509Certificate;
      const issuer = chain[index + 1] as X509Certificate;
      if (!subject.checkIssued(issuer)) return refuse('NEGATIVE', 'CHAIN_LINK_NOT_ISSUED_BY_NEXT');
      let signatureValid = false;
      try {
        signatureValid = subject.verify(issuer.publicKey);
      } catch {
        signatureValid = false;
      }
      if (!signatureValid) return refuse('NEGATIVE', 'CHAIN_SIGNATURE_INVALID');
    }

    // ---- 4. THE ANCHOR --------------------------------------------------
    // The top of the SUBMITTED chain must either BE a pinned anchor, or be
    // signed by one. Nothing else counts. A self-signed root the device brought
    // with it satisfies step 3 perfectly and dies here, which is the whole
    // reason step 3 is not the end of the story.
    const top = chain[chain.length - 1] as X509Certificate;
    const topDer = chainDer[chainDer.length - 1] as Buffer;
    const anchored = material.anchors.some((anchor) => {
      if (anchor.raw.equals(topDer)) return true;
      try {
        return top.checkIssued(anchor) && top.verify(anchor.publicKey);
      } catch {
        return false;
      }
    });
    if (!anchored) return refuse('NEGATIVE', 'CHAIN_NOT_ANCHORED_TO_PINNED_ROOT');

    // ---- 5. revocation --------------------------------------------------
    // The snapshot's freshness was established before this method was entered,
    // so an absence here genuinely means "not revoked according to something we
    // still trust" rather than "we did not look".
    for (const certificate of chain) {
      const entry = material.revocations.get(normaliseCertificateSerial(certificate.serialNumber));
      if (entry !== undefined) return refuse('REVOKED', 'CERTIFICATE_REVOKED');
    }

    // ---- 6. the attestation extension ----------------------------------
    const leaf = chain[0] as X509Certificate;
    const leafDer = chainDer[0] as Buffer;
    const extensionValue = findCertificateExtension(leafDer, ANDROID_KEY_ATTESTATION_EXTENSION_OID);
    if (extensionValue === null) return refuse('INVALID', 'ATTESTATION_EXTENSION_MISSING');
    const description = parseAndroidKeyDescription(extensionValue);
    if (description === null) return refuse('INVALID', 'ATTESTATION_EXTENSION_UNPARSEABLE');

    // From here on a refusal can carry the claims it read, so an operator can
    // see WHAT the device asserted as well as that it was refused.
    const claims = flattenClaims(description);

    // ---- 7. the challenge ----------------------------------------------
    // D26-04A. The bytes inside the certificate must be the bytes the server
    // chose before the key existed. `timingSafeEqual` is used even though this
    // value is not a secret: a length-and-content comparison written by hand is
    // how the next person introduces an early return, and there is no reason to
    // leave that shape lying about on a crypto path.
    const expected = Buffer.from(input.expectedChallengeValue, 'base64url');
    if (
      expected.length !== description.attestationChallenge.length ||
      !timingSafeEqual(expected, description.attestationChallenge)
    ) {
      return refuse('NEGATIVE', 'ATTESTATION_CHALLENGE_MISMATCH', claims);
    }

    // ---- 8. the key ------------------------------------------------------
    // The certificate must attest to THE KEY BEING ENROLLED. Comparing the full
    // SubjectPublicKeyInfo rather than the bare point means the algorithm and
    // the named curve are part of the comparison.
    let leafSpki: Buffer;
    try {
      leafSpki = Buffer.from(leaf.publicKey.export({ format: 'der', type: 'spki' }));
    } catch {
      return refuse('INVALID', 'CERTIFICATE_UNPARSEABLE', claims);
    }
    if (!leafSpki.equals(input.submittedPublicKeySpkiDer)) return refuse('NEGATIVE', 'LEAF_KEY_NOT_SUBMITTED_KEY', claims);

    // ---- 9. StrongBox, and only StrongBox -------------------------------
    // D26-03A: a certificate saying TEE is NEVER promoted into the StrongBox
    // profile. Both levels are required, and they are checked SEPARATELY so the
    // reason names which one disagreed.
    if (description.attestationSecurityLevel !== ANDROID_SECURITY_LEVEL_STRONGBOX) {
      return refuse('NEGATIVE', 'SECURITY_LEVEL_NOT_STRONGBOX', claims);
    }
    if (description.keymasterSecurityLevel !== ANDROID_SECURITY_LEVEL_STRONGBOX) {
      return refuse('NEGATIVE', 'KEYMASTER_SECURITY_LEVEL_NOT_STRONGBOX', claims);
    }

    // ---- 10. the key authorisations, from teeEnforced ONLY --------------
    // `softwareEnforced` is what the ANDROID OS asserts; `teeEnforced` is what
    // the secure hardware asserts. Only the second is evidence about hardware,
    // and reading a value out of the first because the second lacked it would be
    // accepting the operating system's word for a hardware property.
    const authorizations = description.teeEnforced;
    if (
      authorizations.algorithm !== ANDROID_KEY_ALGORITHM_EC ||
      authorizations.keySize !== ANDROID_KEY_SIZE_P256 ||
      authorizations.ecCurve !== ANDROID_EC_CURVE_P256
    ) {
      return refuse('NEGATIVE', 'KEY_ALGORITHM_NOT_P256_EC', claims);
    }
    const purposes = authorizations.purposes;
    const purposesAcceptable =
      purposes.includes(ANDROID_KEY_PURPOSE_SIGN) &&
      purposes.every((purpose) => purpose === ANDROID_KEY_PURPOSE_SIGN || purpose === ANDROID_KEY_PURPOSE_VERIFY);
    if (!purposesAcceptable) return refuse('NEGATIVE', 'KEY_PURPOSE_NOT_SIGN', claims);
    // D26-02: GENERATED, not IMPORTED. An imported key existed outside the
    // secure hardware, so the non-exportability guarantee never held for it.
    if (authorizations.origin !== ANDROID_KEY_ORIGIN_GENERATED) return refuse('NEGATIVE', 'KEY_ORIGIN_NOT_GENERATED', claims);

    // ---- 11. device state ----------------------------------------------
    const rootOfTrust = authorizations.rootOfTrust;
    if (rootOfTrust === null) return refuse('NEGATIVE', 'ROOT_OF_TRUST_MISSING', claims);
    if (!rootOfTrust.deviceLocked) return refuse('NEGATIVE', 'DEVICE_NOT_LOCKED', claims);
    if (rootOfTrust.verifiedBootState !== ANDROID_VERIFIED_BOOT_STATE_VERIFIED) {
      return refuse('NEGATIVE', 'VERIFIED_BOOT_STATE_UNACCEPTABLE', claims);
    }

    // ---- 12. the application identity -----------------------------------
    // Both halves are SERVER configuration. A package name a device could
    // choose is not a package name, and a signing identity a device could
    // choose is not a signing identity.
    const application = authorizations.attestationApplicationId;
    if (application === null) return refuse('NEGATIVE', 'APPLICATION_IDENTITY_MISSING', claims);
    if (!application.packageNames.includes(material.expectedPackageName)) {
      return refuse('NEGATIVE', 'APPLICATION_PACKAGE_UNEXPECTED', claims);
    }
    const signingMatches = application.signatureDigests.some((digest) => material.expectedSigningDigests.includes(digest));
    if (!signingMatches) return refuse('NEGATIVE', 'APPLICATION_SIGNING_IDENTITY_UNEXPECTED', claims);

    return {
      outcome: 'VERIFIED',
      reason: 'VERIFIED',
      claims,
      certificateChainHash: chainHash,
      verifierVersion: ANDROID_KEY_ATTESTATION_VERIFIER_VERSION,
      ...versions,
    };
  }
}

/**
 * SHA-256 over the DER of the chain AS SUBMITTED, in order, length-prefixed.
 *
 * The length prefix is not decoration: without it, two different chains whose
 * concatenations happen to coincide would hash the same, and a hash that cannot
 * distinguish two submissions is not a handle for either of them. The input is
 * the base64 text rather than the decoded bytes so that the hash names exactly
 * what arrived, including an encoding a stricter decoder would later reject.
 */
function hashChain(certificateChainBase64: readonly string[]): string {
  const digest = createHash('sha256');
  for (const encoded of certificateChainBase64) {
    digest.update(String(encoded.length));
    digest.update('.');
    digest.update(encoded, 'utf8');
    digest.update('|');
  }
  return digest.digest('hex');
}

/**
 * Standard base64, decoded STRICTLY.
 *
 * Node's decoder is famously permissive — it will silently skip characters it
 * does not recognise — so the decoded bytes are re-encoded and compared against
 * the input. This is the same discipline `device-signature.ts` applies to
 * base64url and for the same reason: on a security path, "what did this string
 * mean?" must have exactly one answer.
 */
function decodeStrictBase64(value: string): Buffer | null {
  if (value.length === 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0) return null;
  return decoded.toString('base64') === value ? decoded : null;
}

function flattenClaims(description: AndroidKeyDescription): AndroidAttestationClaims {
  const tee = description.teeEnforced;
  return {
    attestationVersion: description.attestationVersion,
    attestationSecurityLevel: description.attestationSecurityLevel,
    keymasterSecurityLevel: description.keymasterSecurityLevel,
    keyPurposes: tee.purposes,
    keyAlgorithm: tee.algorithm,
    keySize: tee.keySize,
    keyEcCurve: tee.ecCurve,
    keyOrigin: tee.origin,
    noAuthRequired: tee.noAuthRequired,
    verifiedBootState: tee.rootOfTrust?.verifiedBootState ?? null,
    deviceLocked: tee.rootOfTrust?.deviceLocked ?? null,
    attestationPackageName: tee.attestationApplicationId?.packageNames[0] ?? null,
    attestationSigningDigest: tee.attestationApplicationId?.signatureDigests[0] ?? null,
  };
}

function unavailable(
  reason: AndroidAttestationRefusalReason,
  certificateChainHash: string,
  trustAnchorSetVersion: string,
  revocationSnapshotVersion: string,
): AndroidAttestationVerdict {
  return {
    outcome: 'UNAVAILABLE',
    reason,
    claims: NO_CLAIMS,
    certificateChainHash,
    verifierVersion: ANDROID_KEY_ATTESTATION_VERIFIER_VERSION,
    trustAnchorSetVersion,
    revocationSnapshotVersion,
  };
}
