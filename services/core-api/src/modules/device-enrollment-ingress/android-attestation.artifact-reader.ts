import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * WP-26/D26-04B — THE ONE READER OF AN ATTESTATION ARTIFACT, AND IT IS NARROW
 * ON PURPOSE.
 *
 * IT IS A SEPARATE CLASS FROM THE INGRESS REPOSITORY, AND THAT IS WIRING, NOT
 * TASTE.
 *
 * `AndroidKeyAttestationEvaluator` is constructed inside `ShieldModule`'s
 * injector — Nest resolves `DEVICE_ATTESTATION_EVALUATOR` where the CONSUMER
 * lives, and `DeviceEnrollmentService` lives in Shield. So the evaluator's
 * collaborator has to be reachable from there. Giving Shield the ingress's whole
 * repository would hand the registry a writer for the attestation challenge
 * table it has no business touching; giving it a second INSTANCE of that
 * repository would put two objects behind one name. This class is the third
 * answer: the read the evaluator needs, and nothing else.
 *
 * IT CANNOT LOAD THE RAW CHAIN.
 *
 * The `select` below omits `certificate_chain_der`, permanently. The evaluator
 * hands its answer to Shield, and Shield's frozen evidence structure has nowhere
 * to put a blob; a read that fetched the chain anyway would leave the raw
 * evidence one careless log line away from an audit row. What cannot be loaded
 * cannot be leaked, which is a stronger guarantee than remembering not to log
 * it.
 *
 * IT ANSWERS NO AUTHORISATION QUESTION. It returns a row or `null`. The
 * re-binding — this tenant, this exact key — is the evaluator's, where the
 * inputs being compared are the ones the ceremony actually supplied.
 */
@Injectable()
export class AndroidAttestationArtifactReader {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * The verdict behind a server-owned artifact reference, scoped to a tenant.
   *
   * `organisationId` is always the organisation the caller is ACTING IN, never
   * one a request named (C17-02). An artifact in another tenant and an id that
   * never existed are the same answer, which is the isolation rule every read in
   * Shield follows.
   */
  async readVerdict(
    organisationId: string,
    artifactId: string,
  ): Promise<{ id: string; publicKeyThumbprint: string; outcome: string; evaluatedAt: Date } | null> {
    return this.prisma.androidKeyAttestationArtifact.findFirst({
      where: { id: artifactId, organisationId },
      select: { id: true, publicKeyThumbprint: true, outcome: true, evaluatedAt: true },
    });
  }
}
