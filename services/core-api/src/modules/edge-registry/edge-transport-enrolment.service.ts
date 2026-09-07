import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  DeviceP256PublicKeySchema,
  TlsSpkiSha256Schema,
  canonicalDeviceJson,
  deviceCanonicalDigest,
} from '@sentinel/contracts';
import { createHash } from 'node:crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { P256KeyImporter } from '../shield/p256-key.importer';

/**
 * M3B §4 — ACTIVATING A TLS TRANSPORT IDENTITY, WITH BOTH POSSESSIONS PROVEN.
 *
 * THE PROPERTY THIS EXISTS TO ESTABLISH
 * -------------------------------------
 *     same authorised Edge
 *         application key possession PROVEN
 *       + TLS private-key possession PROVEN
 *         -> central activates the transport identity
 *
 * Either half alone is not enough, and the two must be bound to EACH OTHER.
 * An Edge that proved only its application key could register somebody else's
 * TLS public key and have every device on the site pin a certificate it does
 * not hold. An Edge that proved only TLS possession could claim to be an Edge
 * it is not.
 *
 * WHY A BARE SPKI CLAIM IS REFUSED
 * --------------------------------
 * The obvious shape is "the Edge sends its SPKI digest and central stores it".
 * That trusts the sender about the one value every Field device will then
 * enforce, and it is exactly the door pinning exists to close. So the Edge
 * signs a statement WITH THE TLS KEY over a challenge central chose, and
 * central verifies that signature against the TLS public key the Edge is
 * registering. The digest is then DERIVED by central from the verified key --
 * never copied from the request.
 *
 * THE ENDPOINT IS NOT THE EDGE'S TO ASSERT
 * ----------------------------------------
 * `https_endpoint` is supplied by the control plane, not by the enrolling box.
 * An Edge that could name its own address during enrolment could tell every
 * device on the site that it lives at `attacker.example`, and the pin would
 * then faithfully protect the connection to the wrong host. This service takes
 * the endpoint as an operator-supplied argument and has no parameter through
 * which the Edge could influence it.
 */

export type EdgeTransportEnrolmentRefusal =
  | 'EDGE_NOT_FOUND'
  | 'EDGE_NOT_ACTIVE'
  | 'EDGE_NOT_TRUSTED'
  | 'APPLICATION_KEY_NOT_CURRENT'
  | 'APPLICATION_POSSESSION_NOT_PROVEN'
  | 'TLS_KEY_MALFORMED'
  | 'TLS_POSSESSION_NOT_PROVEN'
  | 'SPKI_DIGEST_MISMATCH'
  | 'TRANSPORT_IDENTITY_ALREADY_CURRENT';

export type EdgeTransportEnrolmentOutcome =
  | { readonly outcome: 'ACTIVATED'; readonly transportIdentityId: string; readonly tlsSpkiSha256: string }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeTransportEnrolmentRefusal };

/**
 * The statement both keys sign.
 *
 * ONE STATEMENT, TWO SIGNATURES. Binding the two possessions to the same bytes
 * is what makes them one ceremony rather than two unrelated proofs that
 * happened to arrive together: a captured TLS proof cannot be replayed beside a
 * different application proof, because the application signature covers the
 * same challenge and the same TLS key.
 *
 * The TLS public key is IN the statement, so the application key is attesting
 * "this is the TLS key I am registering" rather than merely "I am here".
 */
export function canonicalEdgeTransportBindingStatement(input: {
  readonly organisationId: string;
  readonly edgeId: string;
  readonly siteId: string;
  readonly challenge: string;
  readonly tlsPublicKey: string;
  readonly transportKeyVersion: number;
}): string {
  return canonicalDeviceJson({
    domain: 'sentinel.edge.transport-identity-binding.v1',
    organisation_id: input.organisationId,
    edge_id: input.edgeId,
    site_id: input.siteId,
    challenge: input.challenge,
    tls_public_key: input.tlsPublicKey,
    transport_key_version: input.transportKeyVersion,
  });
}

/**
 * SHA-256 over the DER SubjectPublicKeyInfo, lower-case hex.
 *
 * DERIVED BY CENTRAL from the key it just verified possession of. It is never
 * read from the request: a caller-supplied digest is a caller-supplied pin,
 * and the whole point of this ceremony is that the pin is something central
 * computed from a key the Edge demonstrably holds.
 */
export function deriveTlsSpkiSha256(importer: P256KeyImporter, canonicalPublicKey: string): string | null {
  const key = importer.importPublicKey(canonicalPublicKey);
  if (key === null) return null;
  const der = key.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

@Injectable()
export class EdgeTransportEnrolmentService {
  private readonly logger = new Logger(EdgeTransportEnrolmentService.name);

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  /**
   * Activates a transport identity, or refuses.
   *
   * `httpsEndpoint` is an OPERATOR argument. There is deliberately no overload
   * that reads it from the Edge's submission.
   */
  async activate(input: {
    readonly organisationId: string;
    readonly edgeId: string;
    readonly siteId: string;
    /** Central-chosen, single-use. Never supplied by the Edge. */
    readonly challenge: string;
    /** The TLS public key being registered, canonical SEC1 base64url. */
    readonly tlsPublicKey: string;
    /** Signature over the binding statement, made with the TLS PRIVATE key. */
    readonly tlsSignature: string;
    /** Signature over the SAME statement, made with the Edge APPLICATION key. */
    readonly applicationSignature: string;
    readonly transportKeyVersion: number;
    /** CONTROL-PLANE CONFIGURED. Not the Edge's claim. */
    readonly httpsEndpoint: string;
    readonly claimedSpkiSha256?: string;
  }): Promise<EdgeTransportEnrolmentOutcome> {
    const refused = (refusal: EdgeTransportEnrolmentRefusal): EdgeTransportEnrolmentOutcome => ({
      outcome: 'REFUSED',
      refusal,
    });

    // -- THE EDGE MUST BE ONE WE STILL VOUCH FOR --------------------------
    const edge = await this.prisma.edgeNode.findFirst({
      where: { id: input.edgeId, organisationId: input.organisationId, siteId: input.siteId },
      select: { enrolmentState: true, edgeTrust: true, withdrawnAt: true },
    });
    if (edge === null) return refused('EDGE_NOT_FOUND');
    if (edge.withdrawnAt !== null || edge.enrolmentState !== 'ACTIVE') return refused('EDGE_NOT_ACTIVE');
    if (edge.edgeTrust !== 'TRUSTED') return refused('EDGE_NOT_TRUSTED');

    // -- THE APPLICATION KEY, AS THE REGISTRY CURRENTLY HOLDS IT ----------
    const registryKey = await this.prisma.edgeRegistryKey.findFirst({
      where: { organisationId: input.organisationId, edgeId: input.edgeId, status: 'CURRENT' },
      select: { publicKey: true, signatureProfile: true, revokedAt: true },
    });
    if (registryKey === null || registryKey.revokedAt !== null) return refused('APPLICATION_KEY_NOT_CURRENT');

    // The TLS key must be a real point before it is used for anything.
    if (!DeviceP256PublicKeySchema.safeParse(input.tlsPublicKey).success) return refused('TLS_KEY_MALFORMED');
    if (!this.keys.isRuntimeValidPublicKey(input.tlsPublicKey)) return refused('TLS_KEY_MALFORMED');

    const statement = canonicalEdgeTransportBindingStatement({
      organisationId: input.organisationId,
      edgeId: input.edgeId,
      siteId: input.siteId,
      challenge: input.challenge,
      tlsPublicKey: input.tlsPublicKey,
      transportKeyVersion: input.transportKeyVersion,
    });

    // -- POSSESSION ONE: THE APPLICATION KEY ------------------------------
    // Proves the caller is the Edge the registry knows, AND that this Edge is
    // the one asserting this TLS key -- because the key is inside the bytes it
    // signed.
    const applicationProven = this.keys.verifySignature({
      registeredPublicKey: registryKey.publicKey,
      message: statement,
      signature: input.applicationSignature,
      serverResolvedProfile: registryKey.signatureProfile,
      claimedProfile: registryKey.signatureProfile,
    });
    if (!applicationProven) return refused('APPLICATION_POSSESSION_NOT_PROVEN');

    // -- POSSESSION TWO: THE TLS KEY --------------------------------------
    // Verified against the key being REGISTERED, which is what makes a bare
    // SPKI claim insufficient: an Edge cannot register a key it does not hold.
    const tlsProven = this.keys.verifySignature({
      registeredPublicKey: input.tlsPublicKey,
      message: statement,
      signature: input.tlsSignature,
      serverResolvedProfile: registryKey.signatureProfile,
      claimedProfile: registryKey.signatureProfile,
    });
    if (!tlsProven) return refused('TLS_POSSESSION_NOT_PROVEN');

    // -- THE PIN, DERIVED RATHER THAN ACCEPTED ----------------------------
    const derived = deriveTlsSpkiSha256(this.keys, input.tlsPublicKey);
    if (derived === null) return refused('TLS_KEY_MALFORMED');
    if (!TlsSpkiSha256Schema.safeParse(derived).success) return refused('TLS_KEY_MALFORMED');
    // A claim, when present, is equality-BOUND and never consulted. It exists
    // so a client that computed the digest differently learns it disagrees,
    // rather than silently registering a pin its own code will not reproduce.
    if (input.claimedSpkiSha256 !== undefined && input.claimedSpkiSha256 !== derived) {
      return refused('SPKI_DIGEST_MISMATCH');
    }

    // -- ONE CURRENT IDENTITY PER SITE ------------------------------------
    // Checked here for a clear refusal; the partial unique index enforces it
    // regardless, so a race that slipped past this becomes a constraint
    // violation rather than a second pinned key.
    const existing = await this.prisma.edgeTransportIdentity.findFirst({
      where: { organisationId: input.organisationId, siteId: input.siteId, status: 'CURRENT' },
      select: { id: true },
    });
    if (existing !== null) return refused('TRANSPORT_IDENTITY_ALREADY_CURRENT');

    const now = new Date();
    const created = await this.prisma.edgeTransportIdentity.create({
      data: {
        organisationId: input.organisationId,
        siteId: input.siteId,
        edgeId: input.edgeId,
        transportKeyVersion: input.transportKeyVersion,
        transportPublicKey: input.tlsPublicKey,
        tlsSpkiSha256: derived,
        // OPERATOR-SUPPLIED. The Edge has no way to influence this value.
        httpsEndpoint: input.httpsEndpoint,
        status: 'CURRENT',
        registeredAt: now,
        activatedAt: now,
      },
      select: { id: true },
    });

    this.logger.log(
      `edge transport identity activated: organisation_id=${input.organisationId} edge_id=${input.edgeId} ` +
        `site_id=${input.siteId} version=${input.transportKeyVersion}`,
    );

    return { outcome: 'ACTIVATED', transportIdentityId: created.id, tlsSpkiSha256: derived };
  }
}

/** Exported for the spec: the digest of the canonical binding statement. */
export function edgeTransportBindingFingerprint(statement: string): string {
  return deviceCanonicalDigest(statement);
}
