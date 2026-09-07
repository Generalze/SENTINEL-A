import { Inject, Injectable } from '@nestjs/common';
import { EdgeRegistryKeyRecordSchema, type EdgeRegistryKeyRecord } from '@sentinel/contracts';
import { EdgeRegistryRepository, type EdgeTx } from './edge-registry.repository';

/**
 * WP-29B — THE READ SIDE, AND THE ONE FUNCTION THE OFFLINE EVALUATOR NEEDS.
 *
 * `evaluateOfflineOperationAdmissibility` takes a `registeredEdgeKey` and
 * refuses EDGE_KEY_NOT_USABLE, EDGE_CREDENTIAL_REVOKED, EDGE_NOT_TRUSTED,
 * EDGE_ORGANISATION_MISMATCH and EDGE_SITE_NOT_AUTHORISED against it. This
 * service is where that record comes from, and it creates nothing: activation
 * belongs to `EdgeEnrolmentService`, and keeping the read side unable to write
 * is the `DeviceRegistryService` split for the same reason.
 *
 * THE RECORD IS BUILT, NOT STORED. `EdgeRegistryKeyRecordSchema` is the frozen
 * shape; this assembles it from the key row and its owning Edge and PARSES it
 * before handing it out. Parsing is not ceremony — it is what guarantees the
 * evaluator never receives a record the contract would have refused: a
 * thumbprint that does not match its key, a REVOKED status with no withdrawal
 * instant, an empty site list.
 */
@Injectable()
export class EdgeRegistryService {
  constructor(@Inject(EdgeRegistryRepository) private readonly repository: EdgeRegistryRepository) {}

  /**
   * Resolves the record a receipt's `edge_key_id` names, or `null`.
   *
   * `null` covers every failure identically — no such key, another tenant's
   * key, a key whose Edge has vanished — because a caller able to tell them
   * apart holds an oracle over the estate, and the safe action for all three is
   * the same refusal. The frozen evaluator then answers
   * NO_TRUSTWORTHY_TIME_WITNESS, which is the correct outcome.
   */
  async resolveEdgeRegistryKeyRecord(organisationId: string, edgeKeyId: string, tx?: EdgeTx): Promise<EdgeRegistryKeyRecord | null> {
    const key = await this.repository.findRegistryKeyByKeyId(organisationId, edgeKeyId, tx);
    if (key === null || key.organisationId !== organisationId) return null;
    const edge = await this.repository.findEdge(organisationId, key.edgeId, tx);
    if (edge === null) return null;

    const parsed = EdgeRegistryKeyRecordSchema.safeParse({
      schema_version: 1,
      organisation_id: key.organisationId,
      edge_id: key.edgeId,
      edge_key_id: key.edgeKeyId,
      edge_key_version: key.edgeKeyVersion,
      public_key: key.publicKey,
      public_key_thumbprint: key.publicKeyThumbprint,
      signature_profile: key.signatureProfile,
      status: key.status,
      // THE PRINCIPAL'S TRUST, read from the Edge and not from the key. C15-02
      // keeps them apart: a perfectly valid key belonging to a suspended Edge
      // must not witness anything.
      edge_trust: edge.edgeTrust,
      // The one site this Edge is deployed at, as a one-element array. See the
      // narrowing note in the header of `prisma/schema/edge.prisma`: it is
      // strictly narrower than the contract permits and can only cause more
      // refusals, never fewer.
      authorised_site_ids: [edge.siteId],
      registered_at: key.registeredAt.toISOString(),
      revoked_at: key.revokedAt?.toISOString() ?? null,
    });
    // A record the contract would refuse is not weak evidence, it is no
    // evidence — so it is reported as absent rather than passed along.
    return parsed.success ? parsed.data : null;
  }

  /** The current key of an Edge, or `null`. Relies on the partial unique index. */
  async currentRegistryKeyId(organisationId: string, edgeId: string, tx?: EdgeTx): Promise<string | null> {
    const key = await this.repository.findCurrentRegistryKey(organisationId, edgeId, tx);
    return key?.edgeKeyId ?? null;
  }
}
