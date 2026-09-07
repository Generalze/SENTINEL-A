import { Injectable, Logger } from '@nestjs/common';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DeviceEdgeTransportDescriptorSchema,
  type AuthenticatedDeviceContext,
  type DeviceEdgeTransportRefusal,
  type DeviceEdgeTransportResponse,
} from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * M3B §2 — TELLING A DEVICE WHICH EDGE TO TRUST, AND NOTHING ELSE.
 *
 * WHY THIS IS A SEPARATE SERVICE AND NOT A FIELD ON THE CONTEXT RESPONSE
 * ---------------------------------------------------------------------
 * The device-context response is frozen, and widening it would make every
 * caller of a hot general-purpose endpoint pay for a lookup only a device about
 * to open an Edge connection needs. It would also put transport routing inside
 * a response whose meaning is "who you are and what you may do" -- a different
 * question with a different lifetime.
 *
 * THE DESCRIPTOR GRANTS NOTHING
 * -----------------------------
 * It carries no key, no token and no session material. It says who to believe,
 * and the device still authenticates every subsequent request. Which is why
 * intercepting one is not a compromise: knowing which SPKI is legitimate is
 * precisely the knowledge that stops an attacker substituting their own.
 *
 * HOW THE SITE IS RESOLVED, AND WHY IT IS NOT SIMPLY READ OFF THE CONTEXT
 * ----------------------------------------------------------------------
 * A device context authorises a LIST of sites (`authorised_site_ids`), so
 * there is no single "the device's site" to read. The caller may name one, and
 * central checks MEMBERSHIP of the authenticated context's own list -- exactly
 * the rule `DevicePolicyLeaseService` already applies. When the context
 * authorises precisely one site, naming it is unnecessary and central uses it.
 *
 * That is not an enumeration oracle, because membership is already known to
 * whoever holds the context. What preserves D25-13 is that "no such site" and
 * "a site you have no authority over" produce the SAME coarse refusal, so a
 * caller learns nothing it did not already hold.
 */
@Injectable()
export class DeviceEdgeTransportService {
  private readonly logger = new Logger(DeviceEdgeTransportService.name);

  constructor(private readonly prisma: PrismaService) {}

  async issue(
    context: AuthenticatedDeviceContext,
    requestedSiteId: string | null,
    now: Date = new Date(),
  ): Promise<DeviceEdgeTransportResponse> {
    const refused = (refusal: DeviceEdgeTransportRefusal): DeviceEdgeTransportResponse => ({
      outcome: 'REFUSED',
      refusal,
    });

    const siteId = this.resolveSite(context, requestedSiteId);
    if (siteId === null) return refused('SITE_NOT_RESOLVED');

    // TENANT FROM THE PRINCIPAL, SITE FROM THE PRINCIPAL'S OWN LIST. The
    // organisation is never readable from the request at all; the site, when
    // named, has already been checked for membership above, so by this line
    // both values are ones the authenticated context vouched for.
    //
    // `findMany` with a small take rather than `findFirst`, deliberately. The
    // database's partial unique index already makes two CURRENT rows per site
    // impossible, but this service must not DEPEND on that index being present
    // to behave safely -- a schema drift, a restored backup or a hand-applied
    // migration could remove it. Asking for two and refusing when two arrive is
    // the difference between an invariant that is enforced twice and one that
    // is enforced in a place this code cannot see.
    const candidates = await this.prisma.edgeTransportIdentity.findMany({
      where: {
        organisationId: context.organisation_id,
        siteId,
        status: 'CURRENT',
      },
      take: 2,
    });

    if (candidates.length === 0) return refused('NO_TRUSTED_EDGE_FOR_SITE');
    if (candidates.length > 1) {
      // REFUSE, NEVER PICK. Choosing the newest or the first row would mean the
      // fleet's trust anchor is decided by result ordering, and half a site
      // could end up pinned to a different key than the other half with nothing
      // in the system recording that it happened.
      this.logger.error(
        `ambiguous edge transport identity: organisation_id=${context.organisation_id} site_id=${siteId} ` +
          `candidates=${candidates.length}`,
      );
      return refused('AMBIGUOUS_TRANSPORT_IDENTITY');
    }

    const identity = candidates[0];
    if (identity === undefined) return refused('NO_TRUSTED_EDGE_FOR_SITE');

    // `status = 'CURRENT'` and the two instants do not move atomically, so they
    // are asked INDEPENDENTLY -- the C15-R4-final rule, applied to transport.
    // A row still marked CURRENT whose `revoked_at` has been set is revoked.
    if (identity.revokedAt !== null || identity.rotatedAt !== null) return refused('TRANSPORT_IDENTITY_NOT_ACTIVE');
    if (identity.activatedAt === null) return refused('TRANSPORT_IDENTITY_NOT_ACTIVE');

    // The Edge itself must still be one devices are allowed to talk to. A
    // transport identity outliving its Edge's trust would keep a pin alive for
    // a box the estate has already disowned.
    const edge = await this.prisma.edgeNode.findFirst({
      where: { id: identity.edgeId, organisationId: context.organisation_id },
      select: { edgeTrust: true, enrolmentState: true, withdrawnAt: true },
    });
    if (edge === null) return refused('EDGE_NOT_AVAILABLE');
    if (edge.withdrawnAt !== null) return refused('EDGE_NOT_AVAILABLE');
    if (edge.enrolmentState !== 'ACTIVE') return refused('EDGE_NOT_AVAILABLE');
    if (edge.edgeTrust !== 'TRUSTED') return refused('EDGE_NOT_AVAILABLE');

    // THE DESCRIPTOR MUST NOT OUTLIVE THE AUTHORITY THAT JUSTIFIED IT.
    //
    // The window is the SHORTER of the offline ceiling and whatever remains of
    // the authenticated context. A descriptor that outlived its context would
    // let a device keep opening trusted Edge connections on authority that has
    // already lapsed -- which is exactly the stale-authority failure the
    // offline design exists to prevent, arriving through the transport layer
    // instead of the operation layer.
    const contextExpiry = this.contextExpiryOf(context);
    const ceiling = new Date(now.getTime() + DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
    const expiresAt = contextExpiry !== null && contextExpiry < ceiling ? contextExpiry : ceiling;
    if (expiresAt <= now) return refused('DESCRIPTOR_WINDOW_UNAVAILABLE');

    const candidate = {
      schema_version: 1 as const,
      edge_id: identity.edgeId,
      site_id: identity.siteId,
      transport_identity_id: identity.id,
      transport_key_version: identity.transportKeyVersion,
      https_endpoint: identity.httpsEndpoint,
      tls_spki_sha256: identity.tlsSpkiSha256,
      issued_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    // PARSED ON THE WAY OUT, NOT ONLY ON THE WAY IN.
    //
    // Everything above came from central's own database, so this looks
    // redundant. It is not: the descriptor's schema forbids plaintext
    // endpoints, credentials in URLs and malformed pins, and those rules must
    // hold against a BAD ROW as well as a bad request. A misconfigured or
    // tampered `https_endpoint` column would otherwise be distributed to every
    // device on the site with central's authority behind it.
    const parsed = DeviceEdgeTransportDescriptorSchema.safeParse(candidate);
    if (!parsed.success) {
      this.logger.error(
        `stored edge transport identity is not a valid descriptor: transport_identity_id=${identity.id}`,
      );
      return refused('TRANSPORT_IDENTITY_NOT_ACTIVE');
    }

    return { outcome: 'ISSUED', descriptor: parsed.data };
  }

  /**
   * Resolves the one site this call is about, or `null`.
   *
   * `null` is returned for BOTH "you named a site you have no authority over"
   * and "you named nothing and authorise several". One answer for both is the
   * D25-13 property: the caller cannot use this endpoint to learn whether a
   * site it cannot reach exists.
   */
  private resolveSite(context: AuthenticatedDeviceContext, requested: string | null): string | null {
    const authorised = context.authorised_site_ids;
    if (requested !== null) return authorised.includes(requested) ? requested : null;
    return authorised.length === 1 ? (authorised[0] ?? null) : null;
  }

  /**
   * When the authenticated context stops being authority.
   *
   * `expires_at` is a required field on the frozen context, so this reads it
   * directly. An unparseable value yields `null`, which means "clamp to the
   * ceiling only" -- the shorter answer, never a longer one, because a
   * descriptor that failed OPEN on a malformed instant would outlive the
   * authority that justified it.
   */
  private contextExpiryOf(context: AuthenticatedDeviceContext): Date | null {
    const parsed = Date.parse(context.expires_at);
    return Number.isNaN(parsed) ? null : new Date(parsed);
  }
}
