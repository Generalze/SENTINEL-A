import { z } from 'zod';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DeviceKeyVersionSchema,
  refineDeviceInstantWindow,
} from './device-identity.js';

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

/**
 * M3B §2 — HOW A FIELD DEVICE LEARNS WHICH EDGE TO TRUST.
 *
 * THE PROBLEM THIS SOLVES, AND THE FOUR ANSWERS THAT WERE REJECTED
 * ---------------------------------------------------------------
 * An Android handset on a site LAN needs to talk to that site's Edge over TLS.
 * Something has to tell it which endpoint is legitimate and which certificate
 * to accept. Four ways of answering that were considered and all four are
 * refused by this design:
 *
 *   TOFU                        trusts whatever answers first, which on a
 *                               hostile LAN is the attacker.
 *   public-Web PKI              proves a name was registered, not that this is
 *                               the Edge central authorised for this site.
 *   permissive TrustManager     is not trust, it is the absence of it.
 *   the Edge APPLICATION key    conflates "may sign statements" with "may
 *                               terminate TLS", so one compromise becomes two.
 *
 * The answer is that CENTRAL already knows which Edge serves which site, and
 * the device already holds an authenticated channel to central. So central
 * distributes the endpoint and an exact key pin down that existing channel,
 * and the device trusts nothing it was told by the LAN.
 *
 * WHY A SEPARATE SURFACE AND NOT A FIELD ON THE DEVICE CONTEXT RESPONSE
 * --------------------------------------------------------------------
 * The device-context response is frozen. Widening it would also make every
 * caller of a hot, general-purpose endpoint pay for a lookup that only a
 * device about to open an Edge connection needs, and would put transport
 * routing inside a response whose meaning is "who you are and what you may
 * do". Those are different questions with different lifetimes.
 *
 * WHAT IS DELIBERATELY ABSENT
 * ---------------------------
 *   no private material of any kind
 *   no Edge signing key                (purpose separation is the point)
 *   no bearer credential or token      (this descriptor grants NOTHING; it
 *                                       only says who to believe. The device
 *                                       still authenticates on every request)
 *   no CA bundle or certificate chain  (a pin is smaller, exact, and cannot be
 *                                       widened by adding an issuer)
 *
 * A descriptor is therefore not a secret. Intercepting one tells an attacker
 * which endpoint and key are legitimate -- which is precisely the information
 * that stops them substituting their own.
 */
export const DEVICE_EDGE_TRANSPORT_DESCRIPTOR_DOMAIN = 'sentinel.device.edge-transport-descriptor.v1';

/**
 * A SHA-256 digest of the DER SubjectPublicKeyInfo of the Edge's TLS leaf.
 *
 * SPKI rather than a whole-certificate fingerprint on purpose: it survives
 * certificate renewal on the same keypair, so routine expiry does not force a
 * fleet-wide re-pin, while still changing the instant the KEY changes -- which
 * is the event anyone actually cares about.
 *
 * Lower-case hex, fixed length. Not base64url like the signature primitives,
 * because this value is compared against what platform TLS stacks hand back
 * and is read by humans in incident notes; a fixed-width hex string has no
 * padding or alphabet ambiguity to get wrong at a security boundary.
 */
export const TLS_SPKI_SHA256_PATTERN = /^[0-9a-f]{64}$/;
export const TlsSpkiSha256Schema = z.string().regex(TLS_SPKI_SHA256_PATTERN, 'must be 64 lower-case hex characters');

/**
 * The endpoint the device may open.
 *
 * HTTPS ONLY, and asserted here rather than in the client, so a plaintext
 * endpoint cannot be distributed even by a central that has been talked into
 * emitting one. There is no `http_endpoint` field and no scheme parameter:
 * the absence of an alternative is the guarantee.
 *
 * No credentials in the URL, no query string, no fragment. A transport
 * endpoint that carries a secret in its address leaks it into every log that
 * ever records a connection.
 */
export const EdgeHttpsEndpointSchema = z
  .string()
  .min(1)
  .max(512)
  .superRefine((value, context) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'must be an absolute URL' });
      return;
    }
    if (url.protocol !== 'https:') {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'must be https' });
    }
    if (url.username !== '' || url.password !== '') {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'must not carry credentials' });
    }
    if (url.search !== '' || url.hash !== '') {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'must not carry a query or fragment' });
    }
  });

export const DeviceEdgeTransportDescriptorSchema = z
  .object({
    schema_version: z.literal(1),
    /** Which Edge this is. Audit identity, and what a receipt's `edge_id` is checked against. */
    edge_id: scopedId,
    /**
     * The site this descriptor is FOR.
     *
     * A device context authorises a LIST of sites (`authorised_site_ids`), so
     * "the device's site" is not a single value and central cannot always infer
     * one. The caller may therefore name a site, and central checks MEMBERSHIP
     * of the authenticated context's own list -- the same rule
     * `DevicePolicyLeaseService` already applies.
     *
     * That is not an enumeration oracle: membership is already known to
     * whoever holds the context. What preserves D25-13 is that "no such site"
     * and "a site you have no authority over" return the SAME coarse refusal,
     * so the answer discloses nothing the caller did not already have.
     */
    site_id: scopedId,
    /** The transport identity being pinned -- distinct from any signing key identity. */
    transport_identity_id: scopedId,
    /** Rotation position, so a device can tell a re-pin from a replayed old descriptor. */
    transport_key_version: DeviceKeyVersionSchema,

    /** Where to connect. HTTPS, no credentials, no query. */
    https_endpoint: EdgeHttpsEndpointSchema,
    /** What to require. Exact match, no fallback, no issuer widening. */
    tls_spki_sha256: TlsSpkiSha256Schema,

    issued_at: timestamp,
    /**
     * When the device must stop treating this as current.
     *
     * Bounded by the same ceiling as an offline policy lease, and in practice
     * clamped by central to the authenticated context or lease that produced
     * it -- a descriptor must never outlive the authority that justified
     * issuing it. An expired descriptor does not degrade to "probably still
     * fine": the client refuses to open a NEW trusted connection on it.
     */
    expires_at: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    refineDeviceInstantWindow(
      { issued_at: value.issued_at, expires_at: value.expires_at },
      {
        ...context,
        addIssue: (issue) => context.addIssue({ ...issue, path: ['expires_at'] }),
      },
      DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
      'edge transport descriptor',
    );
  });
export type DeviceEdgeTransportDescriptor = z.infer<typeof DeviceEdgeTransportDescriptorSchema>;

/**
 * Shapes a descriptor must never be able to carry.
 *
 * The first four are private or bearer material: a descriptor that could carry
 * them would turn a routing lookup into a credential-distribution endpoint,
 * and every device that ever cached one would be holding a secret it has no
 * way to protect or revoke.
 *
 * The rest are instructions to relax the check. `allow_insecure`,
 * `pin_optional` and friends are how pinning dies in practice -- not by being
 * removed, but by acquiring an escape hatch that is set once during an
 * incident and never unset. `.strict()` rejects unknown keys already; this
 * list exists so the intent is asserted by a test rather than remembered.
 */
export const DEVICE_EDGE_TRANSPORT_DESCRIPTOR_FORBIDDEN_FIELDS = [
  'tls_private_key',
  'edge_signing_key',
  'bearer_token',
  'session_token',
  'ca_bundle',
  'allow_insecure',
  'pin_optional',
  'skip_pin_check',
  'http_endpoint',
  'trust_all_certificates',
] as const;

/**
 * Why central declined to issue one.
 *
 * A REFUSAL IS NOT AN ERROR AND IT MUST NOT BE AN ORACLE. Every reason here is
 * deliberately coarse. "This device's site has no usable Field-ingress Edge
 * right now" is all a caller learns; it cannot distinguish "no Edge exists"
 * from "an Edge exists and is suspended", because a device that could tell
 * those apart could map the estate's deployment and enrolment state by asking
 * repeatedly (D25-13).
 *
 * `AMBIGUOUS_TRANSPORT_IDENTITY` is the one that matters most. If a site
 * somehow presents more than one CURRENT Field-ingress transport identity,
 * central refuses. It does not pick the newest, the lowest-id, or the first
 * row returned. Picking one would mean the device's trust anchor is decided by
 * row ordering, and half the fleet could end up pinned to a different key than
 * the other half with nothing in the system recording that it happened.
 */
export const DeviceEdgeTransportRefusalSchema = z.enum([
  /**
   * The request did not resolve to exactly one site this context authorises --
   * either it named none and the context authorises several, or it named one
   * the context does not authorise. DELIBERATELY ONE CODE FOR BOTH: splitting
   * them would let a caller distinguish "that site does not exist" from "that
   * site exists and is not yours", which is the enumeration D25-13 forbids.
   */
  'SITE_NOT_RESOLVED',
  'NO_TRUSTED_EDGE_FOR_SITE',
  'EDGE_NOT_AVAILABLE',
  'TRANSPORT_IDENTITY_NOT_ACTIVE',
  'AMBIGUOUS_TRANSPORT_IDENTITY',
  'DESCRIPTOR_WINDOW_UNAVAILABLE',
]);
export type DeviceEdgeTransportRefusal = z.infer<typeof DeviceEdgeTransportRefusalSchema>;

/**
 * The response envelope.
 *
 * A discriminated union rather than a nullable descriptor, so a caller cannot
 * read `response.descriptor` without having first handled the refused case.
 * The type system enforces the fail-closed branch that a `descriptor: null`
 * shape would leave to reviewer diligence.
 */
export const DeviceEdgeTransportResponseSchema = z.discriminatedUnion('outcome', [
  z.object({ outcome: z.literal('ISSUED'), descriptor: DeviceEdgeTransportDescriptorSchema }).strict(),
  z.object({ outcome: z.literal('REFUSED'), refusal: DeviceEdgeTransportRefusalSchema }).strict(),
]);
export type DeviceEdgeTransportResponse = z.infer<typeof DeviceEdgeTransportResponseSchema>;
